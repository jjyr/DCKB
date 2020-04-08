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

int main() {
  uint8_t proxy_lock_cell_i = 0;
  uint8_t wckb_type_hash[HASH_SIZE];
  int ret = load_proxy_lock_cell_index(&proxy_lock_cell_i);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  ret = load_wckb_type_hash(wckb_type_hash);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  return CKB_SUCCESS;
}
