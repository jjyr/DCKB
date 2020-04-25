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
 * 2. has one output cell that data set to first 8 bytes of the current
 * `script_hash` and has no type field, as the proxy lock cell.
 *
 * phase2:
 * 1. check `inputs DCKB - outputs DCKB = Y`.
 * 2. has one input cell that has no type field, and created from the same
 * transaction of withdraw cell. or:
 * 2. the since field of inputs are set to a value which large or equals to
 * relatively `W` epochs.
 *
 * HINT: we use a proxy lock cell as ownership proof to break the restriction of
 * NervosDAO.
 *
 * Script args:
 * This script accept 64 bytes args: <dckb type hash> | <lock hash>
 * <dckb type hash>: blake2b(Script(hash_type: Type, code_hash: <dckb type id>))
 * <lock hash>: lock hash that receives the refund CKB
 *
 * Witness args:
 * This script expect a WitnessArgs and its lock:
 * <lock index>: a uint8 value to indicates proxy lock cell in phase1 and
 * phase2.
 */

#include "ckb_utils.h"
#include "common.h"
#include "const.h"

/* since relative time 18 epochs(~ 72 hours) */
#define PHASE2_TIMEOUT_SINCE 0xa000010000000012

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

/* load proxy lock cell index from witness_args.lock */
int load_proxy_lock_cell_index(uint8_t *index) {
  int ret;
  uint64_t len = 0;
  uint8_t witness[MAX_WITNESS_SIZE];

  len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(witness, &len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret == CKB_ITEM_MISSING) {
    return ERROR_DL_NO_PROXY_CELL_INDEX;
  }
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len > MAX_WITNESS_SIZE) {
    return ERROR_WITNESS_TOO_LONG;
  }

  mol_seg_t witness_seg;
  witness_seg.ptr = (uint8_t *)witness;
  witness_seg.size = len;

  if (MolReader_WitnessArgs_verify(&witness_seg, false) != MOL_OK) {
    return ERROR_LOAD_WITNESS_ARGS;
  }
  /* Load type args */
  mol_seg_t lock_seg = MolReader_WitnessArgs_get_lock(&witness_seg);

  if (MolReader_BytesOpt_is_none(&lock_seg)) {
    return ERROR_DL_NO_PROXY_CELL_INDEX;
  }

  mol_seg_t lock_bytes_seg = MolReader_Bytes_raw_bytes(&lock_seg);
  if (lock_bytes_seg.size != 1) {
    return ERROR_DL_NO_PROXY_CELL_INDEX;
  }

  *index = *(uint8_t *)lock_bytes_seg.ptr;
  return CKB_SUCCESS;
}

/* check validity of proxy lock cell
 */
int check_proxy_lock_cell(uint8_t script_hash[HASH_SIZE], uint64_t i,
                          uint64_t source) {
  uint64_t len = 0;
  /* proxy lock cell must has no type field */
  int ret = ckb_checked_load_cell_by_field(NULL, &len, 0, i, source,
                                           CKB_CELL_FIELD_TYPE_HASH);
  printf("check proxy lock cell i %ld source %ld ret %d", i, source, ret);
  if (ret == CKB_INDEX_OUT_OF_BOUND) {
    return ret;
  }
  if (ret != CKB_ITEM_MISSING) {
    return ERROR_DL_INVALID_PROXY_LOCK;
  }
  /* proxy data must equals to script hash */
  uint8_t buf[PROXY_LOCK_CELL_DATA_LEN];
  len = PROXY_LOCK_CELL_DATA_LEN;
  ret = ckb_load_cell_data(buf, &len, 0, i, source);
  if (ret != CKB_SUCCESS && len != PROXY_LOCK_CELL_DATA_LEN) {
    return ERROR_ENCODING;
  }
  ret = memcmp(buf, script_hash, PROXY_LOCK_CELL_DATA_LEN);
  if (ret == 0) {
    return CKB_SUCCESS;
  } else {
    return ERROR_DL_INVALID_PROXY_LOCK;
  }
}

/* check group inputs
 * calculate the withdraw phase and expected dckb destroy amount
 */
int check_unlock_cells(int *is_phase1, uint64_t *expected_destroy_amount) {
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
  *expected_destroy_amount = 0;
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
    int cell_is_phase1 = is_dao_withdraw1_cell(cell_data, len);
    printf("i=%d withdraw phase: %d cell_is_phase1=%d", i, *is_phase1,
           cell_is_phase1);
    /* inputs must be same withdraw phase */
    if (*is_phase1 != cell_is_phase1) {
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
    if (!cell_is_phase1) {
      /* the input cell is in phase1 withdraw */
      uint64_t efficient_capacity;
      if (__builtin_usubl_overflow(original_capacity, DAO_OCCUPIED_CAPACITY,
                                   &efficient_capacity)) {
        return ERROR_OVERFLOW;
      }
      if (__builtin_uaddl_overflow(*expected_destroy_amount, efficient_capacity,
                                   expected_destroy_amount)) {
        return ERROR_OVERFLOW;
      }
    } else {
      /* the input cell is in phase2 withdraw */
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
      uint64_t compensation_capacity = 0;
      if (__builtin_usubl_overflow(calculated_capacity, original_capacity,
                                   &compensation_capacity)) {
        return ERROR_OVERFLOW;
      }
      if (__builtin_uaddl_overflow(*expected_destroy_amount,
                                   compensation_capacity,
                                   expected_destroy_amount)) {
        return ERROR_OVERFLOW;
      }
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

/* phase1 should output one proxy cell
 * 1. proxy cell should be validity
 * 2. all other cells should not be a valid proxy cell
 */
int check_phase1_only_one_proxy_lock_cell(uint64_t proxy_lock_cell_i) {
  uint8_t script_hash[HASH_SIZE];
  uint64_t len = HASH_SIZE;
  int ret = ckb_load_script_hash(script_hash, &len, 0);
  if (ret != CKB_SUCCESS || len != HASH_SIZE) {
    return ERROR_ENCODING;
  }
  /* check proxy lock cell */
  ret =
      check_proxy_lock_cell(script_hash, proxy_lock_cell_i, CKB_SOURCE_OUTPUT);
  printf("check proxy lock cell ret %d", ret);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  /* check other outputs */
  int i = 0;
  while (1) {
    if (i == proxy_lock_cell_i) {
      goto next;
    }
    int ret = check_proxy_lock_cell(script_hash, i, CKB_SOURCE_OUTPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS && ret != ERROR_DL_INVALID_PROXY_LOCK) {
      return ret;
    }
    /* only one proxy lock should exists */
    if (ret == CKB_SUCCESS) {
      return ERROR_DL_MULTIPLE_PROXY_LOCK;
    }
  next:
    i++;
  }
  return CKB_SUCCESS;
}

/* unlock via proxy cell
 * 1. proxy cell should be validity
 * 2. all inputs is from the same tx as the proxy cell froms
 */
int check_phase2_unlock_via_proxy_cell(uint64_t proxy_lock_cell_i) {
  uint8_t script_hash[HASH_SIZE];
  uint64_t len = HASH_SIZE;
  int ret = ckb_load_script_hash(script_hash, &len, 0);
  if (ret != CKB_SUCCESS || len != HASH_SIZE) {
    return ERROR_ENCODING;
  }
  /* check proxy lock cell */
  ret = check_proxy_lock_cell(script_hash, proxy_lock_cell_i, CKB_SOURCE_INPUT);
  printf("check proxy lock cell ret %d", ret);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  /* load proxy lock cell outpoint */
  uint8_t proxy_lock_cell_tx_hash[HASH_SIZE];
  uint8_t buf[OUT_POINT_SIZE];
  mol_seg_t out_point_seg;
  ret = load_out_point_seg(proxy_lock_cell_i, CKB_SOURCE_INPUT, buf,
                           &out_point_seg);
  printf("load out point ret %d", ret);
  if (ret != CKB_SUCCESS) {
    return ERROR_LOAD_OUT_POINT;
  }
  mol_seg_t tx_hash_seg = MolReader_OutPoint_get_tx_hash(&out_point_seg);
  if (tx_hash_seg.size != HASH_SIZE) {
    return ERROR_ENCODING;
  }
  memcpy(proxy_lock_cell_tx_hash, tx_hash_seg.ptr, HASH_SIZE);

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
    ret = memcmp(proxy_lock_cell_tx_hash, tx_hash_seg.ptr, HASH_SIZE);
    if (ret != 0) {
      return ERROR_DL_INVALID_PROXY_LOCK_TX_HASH;
    }

    i++;
  }
  return CKB_SUCCESS;
}

/* to unlock via timeout, all inputs' since value should greater than or equals
 * to PHASE2_TIMEOUT_SINCE
 */
int check_phase2_unlock_via_timeout() {
  int ret;
  uint64_t len;
  int i = 0;
  while (1) {
    uint64_t since;
    len = SINCE_LEN;
    ret =
        ckb_load_input_by_field((uint8_t *)&since, &len, 0, i,
                                CKB_SOURCE_GROUP_INPUT, CKB_INPUT_FIELD_SINCE);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS || len != SINCE_LEN) {
      return ERROR_ENCODING;
    }
    int comparable = 0;
    ret = ckb_since_cmp(since, PHASE2_TIMEOUT_SINCE, &comparable);
    if (!comparable || ret < 0) {
      return ERROR_DL_INVALID_SINCE;
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

int main() {
  uint8_t dckb_type_hash[HASH_SIZE];
  uint8_t refund_lock_hash[HASH_SIZE];
  int ret = load_dckb_type_hash(dckb_type_hash, refund_lock_hash);
  printf("load dckb type hash %d", ret);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  int is_phase1_cell;
  uint64_t expected_destroy_amount;
  ret = check_unlock_cells(&is_phase1_cell, &expected_destroy_amount);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  /* check unlock condition */
  if (!is_phase1_cell) {
    /* we are performing DAO withdraw phase1.
     * anyone destroy enough DCKB can unlock cells,
     * outputs should include a lock proxy cell to prove the ownership in DAO
     * withdraw phase2.
     */
    uint8_t proxy_lock_cell_i = 0;
    ret = load_proxy_lock_cell_index(&proxy_lock_cell_i);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    ret = check_phase1_only_one_proxy_lock_cell(proxy_lock_cell_i);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
  } else {
    /* input cell is phase1 withdraw cell, implies we are performing DAO
     * withdraw phase2.
     * 1. inputs should include a lock proxy cell, which generated from same
     * transaction of DAO cells. or
     * 2. inputs have `since` field.
     *   a. the `since` flags is set to relative epochs
     *   b. the `since` value is greater than or equals to PHASE2_TIMEOUT_SINCE
     */
    uint8_t proxy_lock_cell_i = 0;
    ret = load_proxy_lock_cell_index(&proxy_lock_cell_i);
    if (ret != CKB_SUCCESS && ret != ERROR_DL_NO_PROXY_CELL_INDEX) {
      return ret;
    }
    if (ret == CKB_SUCCESS) {
      /* unlock via lock proxy */
      ret = check_phase2_unlock_via_proxy_cell(proxy_lock_cell_i);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
    } else {
      /* unlock via phase2 withdraw timeout */
      ret = check_phase2_unlock_via_timeout();
      if (ret != CKB_SUCCESS) {
        return ret;
      }
    }

    ret = check_refund_ckb_cell(refund_lock_hash);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
  }

  /* fetch inputs */
  int input_dckb_cells_cnt;
  TokenInfo input_dckb_cells[MAX_SWAP_CELLS];
  ret = fetch_inputs(dckb_type_hash, NULL, NULL, NULL, NULL,
                     &input_dckb_cells_cnt, input_dckb_cells);
  printf("fetch inputs ret %d", ret);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  /* fetch outputs */
  int output_dckb_cells_cnt;
  TokenInfo output_dckb_cells[MAX_SWAP_CELLS];
  ret = fetch_outputs(dckb_type_hash, NULL, NULL, NULL, NULL,
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
  ret = load_dao_header_data_by_cell(input_dckb_cells[0].cell_index,
                                     CKB_SOURCE_INPUT, 1, &align_target_data);
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
    ret = align_dao_compensation(
        input_dckb_cells[i].cell_index, CKB_SOURCE_INPUT, align_target_data,
        input_dckb_cells[i].block_number, input_dckb_cells[i].amount,
        &calculated_capacity);
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

  printf("deposit lock success");
  return CKB_SUCCESS;
}
