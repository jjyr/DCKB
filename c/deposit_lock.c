/* Deposit lock
 *
 * This lock is designed to only works with NervosDAO cells,
 * other usage will causes the cell be locked forever.
 *
 * Motivation:
 * This lock is designed to enforce users to destroy WCKB to get their native
 * CKB back, in withdraw phase1 a user must destroy X WCKB, which correspond to
 * the original deposited CKB. in withdraw phase2 a user must destroy Y WCKB
 * which correspond to the NervosDAO compensation. we also set a timeout after
 * the withdraw phase1, after W blocks, if the user do not perform phase2,
 * anyone can destroy Y WCKB to get unlock the NervosDAO cell.
 *
 * Unlock conditions:
 *
 * phase1:
 * 1. check `inputs WCKB - outputs WCKB = X`.
 * 2. has one output cell that has no type field as proxy lock cell.
 *
 * phase2:
 * 1. check `inputs WCKB - outputs WCKB = Y`.
 * 2. has one input cell that has no type field, and created from the same
 * transaction of withdraw cell. or:
 * 2. the since field of inputs are set to a value which large or equals to
 * relatively `W` blocks.
 *
 * HINT: we use a proxy lock cell as ownership proof to break the restriction of
 * NervosDAO.
 *
 * Script args:
 * This script accept 32 bytes args: <wckb type hash>
 * <wckb type hash>: blake2b(Script(hash_type: Type, code_hash: <wckb type id>))
 *
 * Witness args:
 * This script expect a WitnessArgs and its lock:
 * <lock index>: a uint8 value to indicates proxy lock cell in phase1 and
 * phase2.
 */

/* load wckb type hash from script.args */
int load_wckb_type_hash(uint8_t wckb_type_hash[HASH_SIZE]) {
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
  if (raw_args_seg.size != HASH_SIZE) {
    return ERROR_ENCODING;
  }

  memcpy(wckb_type_hash, raw_args_seg.ptr, HASH_SIZE);
  return CKB_SUCCESS;
}

/* load proxy lock cell index from witness_args.lock */
int load_proxy_lock_cell_index(uint8_t *index) {
  int ret;
  uint64_t len = 0;
  uint8_t witness[MAX_WITNESS_SIZE];

  len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(witness, &len, 0, 0, CKB_SOURCE_GROUP_INPUT);
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
    return ERROR_ENCODING;
  }

  mol_seg_t lock_bytes_seg = MolReader_Bytes_raw_bytes(&lock_seg);
  if (lock_bytes_seg.size != 1) {
    return ERROR_ENCODING;
  }

  *index = *(uint8_t *)lock_bytes_seg.ptr;
  return CKB_SUCCESS;
}

/* check group inputs
 * calculate the withdraw phase and expected wckb destroy amount
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
    if (is_phase1 == NULL) {
      /* first cell, initialize is_phase1 */
      *is_phase1 = is_dao_withdraw1_cell(cell_data, len);
    }
    int cell_is_phase1 = is_dao_withdraw1_cell(cell_data, len);
    /* inputs must be same withdraw phase */
    if (*is_phase1 != cell_is_phase1) {
      return ERROR_ENCODING;
    }
    /* check type hash */
    uint64_t original_capacity;
    len = HASH_SIZE;
    ret = ckb_checked_load_cell_by_field(type_hash, &len, 0, i,
                                         CKB_SOURCE_GROUP_INPUT,
                                         CKB_CELL_FIELD_TYPE_HASH);
    if (ret != CKB_SUCCESS || len != BLOCK_NUM_LEN) {
      return ERROR_ENCODING;
    }
    if (i == 0) {
      /* first cell, initialize nervos_dao_type_hash */
      memcpy(nervos_dao_type_hash, type_hash, HASH_SIZE);
    } else {
      /* inputs must have same type hash */
      ret = memcmp(nervos_dao_type_hash, type_hash, HASH_SIZE);
      if (ret != 0) {
        return ERROR_ENCODING;
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
    if (cell_is_phase1) {
      if (__builtin_uaddl_overflow(*expected_destroy_amount, original_capacity,
                                   expected_destroy_amount)) {
        return ERROR_OVERFLOW;
      }
    } else {
      /* load DAO deposit header */
      size_t header_index;
      ret = extract_deposit_header_index(i, &header_index);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
      dao_header_data_t deposit_data;
      ret = load_dao_header_data(header_index, CKB_SOURCE_DEP_HEADER,
                                 &deposit_data);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
      /* load DAO withdraw header */
      dao_header_data_t target_data;
      ret = load_dao_header_data(i, CKB_SOURCE_GROUP_INPUT, &target_data);
      if (ret != CKB_SUCCESS) {
        return ret;
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

int main() {
  uint8_t proxy_lock_cell_i = 0;
  uint8_t wckb_type_hash[HASH_SIZE];
  /* TODO unlock via timeout */
  int ret = load_proxy_lock_cell_index(&proxy_lock_cell_i);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  ret = load_wckb_type_hash(wckb_type_hash);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  int is_phase1;
  uint64_t expected_destroy_amount;
  ret = check_unlock_cells(&is_phase1, &expected_destroy_amount);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  /* fetch inputs */
  int input_wckb_cells_cnt;
  TokenInfo input_wckb_cells[MAX_SWAP_CELLS];
  ret = fetch_inputs(wckb_type_hash, NULL, NULL, NULL, NULL,
                     &input_wckb_cells_cnt, input_wckb_cells);
  printf("fetch inputs ret %d", ret);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  /* fetch outputs */
  int output_wckb_cells_cnt;
  TokenInfo output_wckb_cells[MAX_SWAP_CELLS];
  ret = fetch_outputs(wckb_type_hash, NULL, NULL, NULL, NULL,
                      &output_wckb_cells_cnt, output_wckb_cells);
  printf("fetch outputs ret %d", ret);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  uint64_t total_input_wckb = 0;
  for (int i = 0; i < input_wckb_cells_cnt; i++) {
    if (__builtin_uaddl_overflow(total_input_wckb, input_wckb_cells[i].amount,
                                 &total_input_wckb)) {
      return ERROR_OVERFLOW;
    }
  }

  uint64_t total_output_wckb = 0;
  for (int i = 0; i < output_wckb_cells_cnt; i++) {
    if (__builtin_uaddl_overflow(total_output_wckb, output_wckb_cells[i].amount,
                                 &total_output_wckb)) {
      return ERROR_OVERFLOW;
    }
  }

  uint64_t destroy_amount;
  if (__builtin_usubl_overflow(total_input_wckb, total_output_wckb,
                               &destroy_amount)) {
    return ERROR_OVERFLOW;
  }
  if (destroy_amount != expected_destroy_amount) {
    return ERROR_ENCODING;
  }

  return CKB_SUCCESS;
}
