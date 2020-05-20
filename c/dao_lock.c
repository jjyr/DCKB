/* Deposit lock
 *
 * This lock is designed to only works with NervosDAO cells,
 * other usage will causes the cell be locked forever.
 *
 * Motivation:
 * This lock is designed to enforce users to destroy DCKB to get their native
 * CKB back, in withdraw phase1 a user must destroy X DCKB, which correspond to
 * the `original deposited capacity - occupied capacity`. In withdraw phase2 a
 * user must destroy Y DCKB which correspond to the NervosDAO compensation. we
 * also set a timeout after the withdraw phase1, after W blocks, if the user do
 * not perform phase2, anyone can destroy Y DCKB to get unlock the NervosDAO
 * cell.
 *
 * Unlock conditions:
 *
 * phase1:
 * 1. check `inputs DCKB - outputs DCKB = X`.
 * 2. has one output custodian cell which type is DCKB and lock is
 * custodian_lock, and cell's dckb amount equals to X.
 *
 * phase2:
 * 1. check `inputs DCKB - outputs DCKB = Y`.
 * 2. has the custodian cell in phase1 as input.
 *
 * HINT: we use the custodian cell to handle withdraw unlock and timeout, check
 * custodian_lock for details.
 *
 * Script args:
 * This script accept 64 bytes args: <dckb type hash> | <refund lock hash>
 * <dckb type hash>: blake2b(Script(hash_type: Type, code_hash: <dckb type id>))
 * <refund lock hash>: lock hash that receives the refund CKB
 *
 * Witness args:
 * This script expect a WitnessArgs and its lock:
 * <custodian index>: a uint8_t index refer to custodian cell.
 */

#include "ckb_utils.h"
#include "common.h"
#include "custodian_lock.h"

/* load dckb type hash from script.args */
int load_dckb_type_hash(uint8_t dckb_type_hash[HASH_SIZE],
                        uint8_t refund_lock_hash[HASH_SIZE]) {
  int ret;
  uint64_t len = 0;
  uint8_t script[MAX_SCRIPT_SIZE];

  len = MAX_SCRIPT_SIZE;
  ret = ckb_checked_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len > MAX_SCRIPT_SIZE) {
    return ERROR_ENCODING;
  }

  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;

  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }
  /* Load type args */
  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);

  mol_seg_t raw_args_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (raw_args_seg.size != HASH_SIZE * 2) {
    return ERROR_ENCODING;
  }

  memcpy(dckb_type_hash, raw_args_seg.ptr, HASH_SIZE);
  memcpy(refund_lock_hash, raw_args_seg.ptr + HASH_SIZE, HASH_SIZE);
  return CKB_SUCCESS;
}

/* load custodian cell index from witness_args.lock */
int load_custodian_cell_index(uint8_t *index) {
  int ret = load_witness_lock_args(0, CKB_SOURCE_GROUP_INPUT, index, 1);
  if (ret == CKB_ITEM_MISSING) {
    return ERROR_DL_NO_CUSTODIAN_CELL_INDEX;
  }
  if (ret != CKB_SUCCESS) {
    return ERROR_DL_NO_CUSTODIAN_CELL_INDEX;
  }
  return CKB_SUCCESS;
}

/* check validity of custodian cell
 */
int check_custodian_cell(uint8_t dckb_type_hash[HASH_SIZE], uint64_t i,
                         uint64_t source) {
  uint8_t type_hash[HASH_SIZE];
  uint64_t len = HASH_SIZE;
  /* check cell type must be DCKB */
  int ret = ckb_checked_load_cell_by_field(type_hash, &len, 0, i, source,
                                           CKB_CELL_FIELD_TYPE_HASH);
  printf("check load custodian type hash ret %i", ret);
  if (ret == CKB_ITEM_MISSING) {
    return ERROR_DL_INVALID_CUSTODIAN_CELL;
  }
  if (ret != CKB_SUCCESS || len != HASH_SIZE) {
    return ERROR_ENCODING;
  }
  ret = memcmp(type_hash, dckb_type_hash, HASH_SIZE);
  printf("check custodian type ret %i", ret);
  if (ret != 0) {
    return ERROR_DL_INVALID_CUSTODIAN_CELL;
  }
  /* check cell lock must be custodian_lock */
  uint8_t lock_buf[MAX_SCRIPT_SIZE];
  len = MAX_SCRIPT_SIZE;
  ret = ckb_checked_load_cell_by_field(lock_buf, &len, 0, i, source,
                                       CKB_CELL_FIELD_LOCK);

  if (ret != CKB_SUCCESS || len > MAX_SCRIPT_SIZE) {
    return ERROR_ENCODING;
  }
  mol_seg_t script_seg;
  script_seg.ptr = lock_buf;
  script_seg.size = len;
  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }
  /* Load code hash */
  mol_seg_t code_hash_seg = MolReader_Script_get_code_hash(&script_seg);
  if (code_hash_seg.size != HASH_SIZE) {
    return ERROR_ENCODING;
  }
  mol_seg_t hash_type_seg = MolReader_Script_get_hash_type(&script_seg);
  if (hash_type_seg.size != 1) {
    return ERROR_ENCODING;
  }

  if (*(hash_type_seg.ptr) != HASH_TYPE_DATA) {
    printf("custodian lock hash type error");
    return ERROR_DL_INVALID_CUSTODIAN_CELL;
  }
  ret = memcmp(code_hash_seg.ptr, CUSTODIAN_LOCK_CODE_HASH, HASH_SIZE);
  if (ret != 0) {
    printf("custodian lock code hash error");
    return ERROR_DL_INVALID_CUSTODIAN_CELL;
  }
  return CKB_SUCCESS;
}

/* check withdraw unlock condition
 * phase1: expected custodian original deposited capacity
 * phase2: expected destroy total withdraw capacity
 */
int check_withdraw_unlock_condition(int *is_phase1,
                                    uint64_t *expected_custodian_amount) {
  int ret;
  uint64_t len;
  int i = 0;
  /*
   * We assume inputs cells are NervosDAO cells,
   * input cells withdraw phase must be same.
   */
  uint8_t cell_data[BLOCK_NUM_LEN];
  uint8_t nervos_dao_type_hash[HASH_SIZE];
  uint8_t type_hash[HASH_SIZE];
  *expected_custodian_amount = 0;
  while (1) {
    len = BLOCK_NUM_LEN;
    ret = ckb_load_cell_data(cell_data, &len, 0, i, CKB_SOURCE_GROUP_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS || len != BLOCK_NUM_LEN) {
      return ERROR_ENCODING;
    }
    /* check withdraw phase */
    if (i == 0) {
      /* first cell, initialize is_phase1 */
      *is_phase1 = is_dao_withdraw1_cell(cell_data, len);
    }
    int is_input_cell_phase1 = is_dao_withdraw1_cell(cell_data, len);
    printf("i=%d withdraw phase: %d is_input_cell_phase1=%d", i, *is_phase1,
           is_input_cell_phase1);
    /* inputs must be same withdraw phase */
    if (*is_phase1 != is_input_cell_phase1) {
      return ERROR_DL_CONFLICT_WITHDRAW_PHASE;
    }
    /* check type hash */
    len = HASH_SIZE;
    ret = ckb_checked_load_cell_by_field(type_hash, &len, 0, i,
                                         CKB_SOURCE_GROUP_INPUT,
                                         CKB_CELL_FIELD_TYPE_HASH);
    if (ret != CKB_SUCCESS || len != HASH_SIZE) {
      return ERROR_ENCODING;
    }
    if (i == 0) {
      /* first cell, initialize nervos_dao_type_hash */
      memcpy(nervos_dao_type_hash, type_hash, HASH_SIZE);
    } else {
      /* inputs must have same type hash */
      ret = memcmp(nervos_dao_type_hash, type_hash, HASH_SIZE);
      if (ret != 0) {
        return ERROR_DL_CONFLICT_DAO_TYPE_HASH;
      }
    }
    /* calculate expected amount */
    uint64_t original_capacity;
    len = CKB_LEN;
    ret = ckb_checked_load_cell_by_field((uint8_t *)&original_capacity, &len, 0,
                                         i, CKB_SOURCE_GROUP_INPUT,
                                         CKB_CELL_FIELD_CAPACITY);
    if (ret != CKB_SUCCESS || len != CKB_LEN) {
      return ERROR_LOAD_CAPACITY;
    }
    if (!is_input_cell_phase1) {
      /* current tx is phase1 withdraw */
      uint64_t efficient_capacity;
      if (__builtin_usubl_overflow(original_capacity, DAO_OCCUPIED_CAPACITY,
                                   &efficient_capacity)) {
        return ERROR_OVERFLOW;
      }
      if (__builtin_uaddl_overflow(*expected_custodian_amount,
                                   efficient_capacity,
                                   expected_custodian_amount)) {
        return ERROR_OVERFLOW;
      }
    } else {
      /* current tx is phase2 withdraw */
      /* load DAO deposit header */
      size_t header_index;
      ret = extract_deposit_header_index(i, &header_index);
      if (ret != CKB_SUCCESS) {
        return ERROR_LOAD_HEADER_INDEX;
      }
      dao_header_data_t deposit_data;
      ret = load_dao_header_data(header_index, CKB_SOURCE_HEADER_DEP,
                                 &deposit_data);
      if (ret != CKB_SUCCESS) {
        return ERROR_LOAD_HEADER;
      }
      /* load DAO withdraw header */
      dao_header_data_t target_data;
      ret = load_dao_header_data(i, CKB_SOURCE_GROUP_INPUT, &target_data);
      if (ret != CKB_SUCCESS) {
        return ERROR_LOAD_HEADER;
      }
      /* calculate withdraw amount */
      uint64_t deposited_block_number = *(uint64_t *)cell_data;
      uint64_t calculated_capacity;
      ret = calculate_dao_input_capacity(
          DAO_OCCUPIED_CAPACITY, deposit_data, target_data,
          deposited_block_number, original_capacity, &calculated_capacity);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
      /* accumulate compensation */
      *expected_custodian_amount = calculated_capacity;
    }
    i++;
  }
  return CKB_SUCCESS;
}

int load_out_point_seg(uint64_t i, uint64_t source, uint8_t buf[OUT_POINT_SIZE],
                       mol_seg_t *out_point_seg) {
  uint64_t len = OUT_POINT_SIZE;
  int ret = ckb_load_input_by_field(buf, &len, 0, i, source,
                                    CKB_INPUT_FIELD_OUT_POINT);
  printf("load input out point %ld, ret %d", i, ret);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != OUT_POINT_SIZE) {
    return ERROR_ENCODING;
  }

  out_point_seg->ptr = (uint8_t *)buf;
  out_point_seg->size = len;

  if (MolReader_OutPoint_verify(out_point_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  return CKB_SUCCESS;
}

/* phase1 should output one custodian cell
 * 1. custodian cell should be validity
 * 2. DCKB amount should satisfied expected custodian amount
 */
int check_phase1_custodian_cell(uint8_t dckb_type_hash[HASH_SIZE],
                                uint64_t custodian_cell_i,
                                uint64_t expected_custodian_amount) {
  /* check custodian cell */
  int ret =
      check_custodian_cell(dckb_type_hash, custodian_cell_i, CKB_SOURCE_OUTPUT);
  printf("phase1 check custodian cell ret %d", ret);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  /* check custodian DCKB */
  uint8_t buf[BLOCK_NUM_LEN + UDT_LEN];
  uint64_t len = BLOCK_NUM_LEN + UDT_LEN;
  ret = ckb_load_cell_data(buf, &len, 0, custodian_cell_i, CKB_SOURCE_OUTPUT);
  if (ret != CKB_SUCCESS || len != UDT_LEN + BLOCK_NUM_LEN) {
    return ERROR_DL_INVALID_CUSTODIAN_CELL;
  }
  uint128_t amount;
  uint64_t block_number;
  ret = parse_dckb_data(&amount, &block_number, buf, len);
  if (ret != CKB_SUCCESS) {
    return ERROR_DL_INVALID_CUSTODIAN_CELL;
  }
  if (amount != expected_custodian_amount) {
    return ERROR_DL_INCORRECT_DESTROY_AMOUNT;
  }
  return CKB_SUCCESS;
}

/* phase2 custodian cell
 * 1. custodian cell should be validity
 * 2. all inputs and custodian cell are from the same tx
 */
int check_phase2_custodian_cell(uint8_t dckb_type_hash[HASH_SIZE],
                                uint64_t custodian_cell_i) {
  /* check custodian cell */
  int ret =
      check_custodian_cell(dckb_type_hash, custodian_cell_i, CKB_SOURCE_INPUT);
  printf("phase2 check custodian cell i %ld ret %d", custodian_cell_i, ret);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  /* load custodian cell outpoint */
  uint8_t custodian_cell_tx_hash[HASH_SIZE];
  uint8_t buf[OUT_POINT_SIZE];
  mol_seg_t out_point_seg;
  ret = load_out_point_seg(custodian_cell_i, CKB_SOURCE_INPUT, buf,
                           &out_point_seg);
  printf("load out point ret %d", ret);
  if (ret != CKB_SUCCESS) {
    return ERROR_LOAD_OUT_POINT;
  }
  mol_seg_t tx_hash_seg = MolReader_OutPoint_get_tx_hash(&out_point_seg);
  if (tx_hash_seg.size != HASH_SIZE) {
    return ERROR_ENCODING;
  }
  memcpy(custodian_cell_tx_hash, tx_hash_seg.ptr, HASH_SIZE);

  /* check inputs outpoints */
  int i = 0;
  while (1) {
    ret = load_out_point_seg(i, CKB_SOURCE_GROUP_INPUT, buf, &out_point_seg);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_LOAD_OUT_POINT;
    }

    /* Load tx hash */
    tx_hash_seg = MolReader_OutPoint_get_tx_hash(&out_point_seg);
    if (tx_hash_seg.size != HASH_SIZE) {
      return ERROR_ENCODING;
    }
    ret = memcmp(custodian_cell_tx_hash, tx_hash_seg.ptr, HASH_SIZE);
    if (ret != 0) {
      return ERROR_DL_MISMATCH_CUSTODIAN_CELL_TX_HASH;
    }

    i++;
  }
  return CKB_SUCCESS;
}

/* assert input group cell's capacity equals to outputs(where
 * lock=refund_lock_hash) cell's capacity  */
int check_refund_ckb_cell(uint8_t refund_lock_hash[HASH_SIZE]) {
  int i = 0;
  uint64_t input_cells_capacity = 0;
  while (1) {
    uint64_t capacity = 0;
    uint64_t len = CKB_LEN;
    int ret = ckb_checked_load_cell_by_field((uint8_t *)&capacity, &len, 0, i,
                                             CKB_SOURCE_GROUP_INPUT,
                                             CKB_CELL_FIELD_CAPACITY);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS || len != CKB_LEN) {
      return ERROR_ENCODING;
    }
    if (__builtin_uaddl_overflow(input_cells_capacity, capacity,
                                 &input_cells_capacity)) {
      return ERROR_OVERFLOW;
    }
    i++;
  }
  uint64_t refund_capacity = 0;
  i = 0;
  while (1) {
    uint8_t lock_hash[HASH_SIZE];
    uint64_t len = HASH_SIZE;
    int ret = ckb_checked_load_cell_by_field(
        lock_hash, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_LOCK_HASH);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS || len != HASH_SIZE) {
      return ERROR_ENCODING;
    }
    ret = memcmp(lock_hash, refund_lock_hash, HASH_SIZE);
    if (ret != 0) {
      goto next;
    }
    uint64_t capacity = 0;
    len = CKB_LEN;
    ret = ckb_checked_load_cell_by_field((uint8_t *)&capacity, &len, 0, i,
                                         CKB_SOURCE_OUTPUT,
                                         CKB_CELL_FIELD_CAPACITY);
    if (ret != CKB_SUCCESS || len != CKB_LEN) {
      return ERROR_ENCODING;
    }
    if (__builtin_uaddl_overflow(refund_capacity, capacity, &refund_capacity)) {
      return ERROR_OVERFLOW;
    }
  next:
    i++;
  }
  if (refund_capacity < input_cells_capacity) {
    return ERROR_DL_REFUND_CKB_NOT_ENOUGH;
  }
  return CKB_SUCCESS;
}

int check_destroy_dckb_amount(uint8_t dckb_type_hash[HASH_SIZE],
                              uint64_t expected_destroy_amount) {
  /* fetch inputs */
  int input_dckb_cells_cnt;
  TokenInfo input_dckb_cells[MAX_SWAP_CELLS];
  int ret = fetch_inputs(dckb_type_hash, NULL, NULL, NULL, NULL, NULL,
                         &input_dckb_cells_cnt, input_dckb_cells);
  printf("fetch inputs ret %d", ret);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  /* fetch outputs */
  int output_dckb_cells_cnt;
  TokenInfo output_dckb_cells[MAX_SWAP_CELLS];
  ret = fetch_outputs(dckb_type_hash, NULL, NULL, NULL, NULL, NULL,
                      &output_dckb_cells_cnt, output_dckb_cells);
  printf("fetch outputs ret %d", ret);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  if (input_dckb_cells_cnt == 0) {
    printf("input_dckb_cells_cnt %d", input_dckb_cells_cnt);
    return ERROR_DL_INCORRECT_DESTROY_AMOUNT;
  }
  /* calculate input dckb */
  dao_header_data_t align_target_data;
  ret = load_align_target_dao_header_data(input_dckb_cells[0].cell_index,
                                          CKB_SOURCE_INPUT, &align_target_data);
  printf("load aligned target ret %d", ret);
  if (ret != CKB_SUCCESS) {
    return ERROR_LOAD_DAO_HEADER_DATA;
  }
  uint64_t calculated_capacity;
  uint64_t total_input_dckb = 0;
  for (int i = 0; i < input_dckb_cells_cnt; i++) {
    printf("input amount %ld, block_number %ld",
           (uint64_t)input_dckb_cells[i].amount,
           input_dckb_cells[i].block_number);
    ret = align_dckb_cell(input_dckb_cells[i].cell_index, CKB_SOURCE_INPUT,
                          align_target_data, input_dckb_cells[i].block_number,
                          input_dckb_cells[i].amount, &calculated_capacity);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    printf("after align input amount %ld, block_number %ld",
           (uint64_t)calculated_capacity, align_target_data.block_number);
    if (__builtin_uaddl_overflow(total_input_dckb, calculated_capacity,
                                 &total_input_dckb)) {
      return ERROR_OVERFLOW;
    }
  }

  uint64_t total_output_dckb = 0;
  for (int i = 0; i < output_dckb_cells_cnt; i++) {
    if (__builtin_uaddl_overflow(total_output_dckb, output_dckb_cells[i].amount,
                                 &total_output_dckb)) {
      return ERROR_OVERFLOW;
    }
  }

  printf("total input dckb %ld total output dckb %ld", total_input_dckb,
         total_output_dckb);

  uint64_t destroy_amount;
  if (__builtin_usubl_overflow(total_input_dckb, total_output_dckb,
                               &destroy_amount)) {
    return ERROR_OVERFLOW;
  }
  printf("destroy amount %ld, expect %ld", destroy_amount,
         expected_destroy_amount);
  /* check destroy dckb */
  if (destroy_amount != expected_destroy_amount) {
    return ERROR_DL_INCORRECT_DESTROY_AMOUNT;
  }

  return CKB_SUCCESS;
}

int main() {
  uint8_t dckb_type_hash[HASH_SIZE];
  uint8_t refund_lock_hash[HASH_SIZE];
  int ret = load_dckb_type_hash(dckb_type_hash, refund_lock_hash);
  printf("load dckb type hash %d", ret);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  int is_input_cell_phase1;
  uint64_t expected_custodian_amount;
  ret = check_withdraw_unlock_condition(&is_input_cell_phase1,
                                        &expected_custodian_amount);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  /* check unlock condition */
  if (!is_input_cell_phase1) {
    /* we are performing DAO withdraw phase1.
     * 1. anyone custodian enough DCKB can unlock DAO cells.
     * 2. outputs must include a valid custodian cell.
     */
    uint8_t custodian_cell_i = 0;
    ret = load_custodian_cell_index(&custodian_cell_i);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    ret = check_phase1_custodian_cell(dckb_type_hash, custodian_cell_i,
                                      expected_custodian_amount);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
  } else {
    /* input is a phase1 withdraw cell, implies we are performing DAO
     * withdraw phase2.
     * 1. inputs must include the custodian cell used in phase1 unlock.
     * 2. must destroy expected_custodian_amount DCKB.
     */
    uint8_t custodian_cell_i = 0;
    ret = load_custodian_cell_index(&custodian_cell_i);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    /* unlock via custodian cell */
    ret = check_phase2_custodian_cell(dckb_type_hash, custodian_cell_i);
    if (ret != CKB_SUCCESS) {
      return ret;
    }

    ret = check_refund_ckb_cell(refund_lock_hash);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    ret = check_destroy_dckb_amount(dckb_type_hash, expected_custodian_amount);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
  }

  printf("DAO unlock success");
  return CKB_SUCCESS;
}
