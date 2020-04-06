/* Deposit lock
 * 
 * This lock is designed to only works with NervosDAO cells,
 * other usage will causes the cell be locked forever.
 *
 * Motivation:
 * This lock is designed to enforce users to destroy WCKB to get their native CKB back,
 * in withdraw phase1 a user must destroy X WCKB, which correspond to the original deposited CKB.
 * in withdraw phase2 a user must destroy Y WCKB which correspond to the NervosDAO compensation.
 * we also set a timeout after the withdraw phase1, after W blocks, if the user do not perform phase2, 
 * anyone can destroy Y WCKB to get unlock the NervosDAO cell.
 *
 * Unlock conditions:
 *
 * phase1:
 * 1. check `inputs WCKB - outputs WCKB = X`.
 * 2. has exactly one output cell that do not has the type field.
 *
 * phase2:
 * 1. check `inputs WCKB - outputs WCKB = Y`.
 * 2. at least one input cell that do not has the type field is from the same transaction.
 * or:
 * 2. the since field of inputs is set to relatively `W` blocks.
 *
 * HINT: we use a cell as unlock proof to break the restriction of NervosDAO.
 *
 * Args:
 * This script accept 32 bytes args: <wckb type hash>
 * <wckb type hash>: blake2b(Script(hash_type: Type, code_hash: <wckb type id>))
 */


/* check inputs, return input WCKB */
int fetch_inputs(unsigned char *wckb_type_hash,
                 TokenInfo withdraw_dao_infos[MAX_SWAPS], int *input_wckb_cnt,
                 TokenInfo input_wckb_infos[MAX_SWAPS]) {

  *withdraw_dao_cnt = 0;
  *input_wckb_cnt = 0;
  int i = 0;
  int ret;
  uint64_t len;
  while (1) {
    unsigned char input_type_hash[HASH_SIZE];
    len = HASH_SIZE;
    ret = ckb_checked_load_cell_by_field(input_type_hash, &len, 0, i,
                                         CKB_SOURCE_INPUT,
                                         CKB_CELL_FIELD_TYPE_HASH);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret == CKB_ITEM_MISSING) {
      i++;
      continue;
    }
    sprintf(dbuf, "load cell type ret %d len %ld", ret, len);
    ckb_debug(dbuf);
    if (ret != CKB_SUCCESS || len != HASH_SIZE) {
      return ERROR_LOAD_TYPE_HASH;
    }
    uint8_t buf[UDT_LEN + BLOCK_NUM_LEN];
    len = UDT_LEN + BLOCK_NUM_LEN;
    ret = ckb_load_cell_data(buf, &len, 0, i, CKB_SOURCE_INPUT);
    if (ret == CKB_ITEM_MISSING) {
      i++;
      continue;
    }
    sprintf(dbuf, "load input cell data ret %d len %ld", ret, len);
    ckb_debug(dbuf);
    if (ret != CKB_SUCCESS || len > UDT_LEN + BLOCK_NUM_LEN) {
      return ERROR_LOAD_TYPE_HASH;
    }
    int is_dao = is_dao_withdraw1_cell(input_type_hash, buf, len);
    if (is_dao) {
      ckb_debug("check a new withdraw cell");
      /* withdraw NervosDAO */
      uint64_t deposited_block_number = *(uint64_t *)buf;
      size_t deposit_index;
      ret = extract_deposit_header_index(i, &deposit_index);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
      /* calculate withdraw amount */
      dao_header_data_t deposit_data;
      load_dao_header_data(deposit_index, CKB_SOURCE_HEADER_DEP, &deposit_data);
      dao_header_data_t withdraw_data;
      load_dao_header_data(i, CKB_SOURCE_INPUT, &withdraw_data);
      uint64_t occupied_capacity;
      len = CKB_LEN;
      ret = ckb_checked_load_cell_by_field((uint8_t *)&occupied_capacity, &len,
                                           0, i, CKB_SOURCE_INPUT,
                                           CKB_CELL_FIELD_OCCUPIED_CAPACITY);
      if (ret != CKB_SUCCESS || len != CKB_LEN) {
        return ERROR_LOAD_OCCUPIED_CAPACITY;
      }
      if (occupied_capacity != DAO_OCCUPIED_CAPACITY) {
        sprintf(dbuf, "input DAO occupied capacity %ld, expected %ld",
                occupied_capacity, DAO_OCCUPIED_CAPACITY);
        ckb_debug(dbuf);
        i += 1;
        continue;
      }
      len = CKB_LEN;
      uint64_t original_capacity;
      ret = ckb_checked_load_cell_by_field((uint8_t *)&original_capacity, &len,
                                           0, i, CKB_SOURCE_INPUT,
                                           CKB_CELL_FIELD_CAPACITY);
      if (ret != CKB_SUCCESS || len != CKB_LEN) {
        return ERROR_LOAD_CAPACITY;
      }
      uint64_t calculated_capacity = 0;
      calculate_dao_input_capacity(occupied_capacity, deposit_data,
                                   withdraw_data, deposited_block_number,
                                   original_capacity, &calculated_capacity);
      /* record withdraw amount */
      int j = *withdraw_dao_cnt;
      *withdraw_dao_cnt += 1;
      withdraw_dao_infos[j].amount = calculated_capacity;
      withdraw_dao_infos[j].block_number = withdraw_data.block_number;
    } else if (memcmp(input_type_hash, type_hash, HASH_SIZE) == 0) {
      /* WCKB */
      uint128_t amount;
      uint64_t block_number;
      if (len != UDT_LEN + BLOCK_NUM_LEN) {
        return ERROR_LOAD_WCKB_DATA;
      }
      amount = *(uint128_t *)buf;
      block_number = *(uint64_t *)(buf + UDT_LEN);
      /* record input amount */
      int j = *input_wckb_cnt;
      *input_wckb_cnt += 1;
      input_wckb_infos[j].amount = amount;
      input_wckb_infos[j].block_number = block_number;
    }
    i++;
  }
  return CKB_SUCCESS;
}

int main() { return 0; }
