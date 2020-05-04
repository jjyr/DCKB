/* Custodian lock
 * used for custodian DCKB cell when withdraw from NervosDAO
 *
 * Script args:
 * This script accept 32 bytes args: <lock hash>
 *
 * Witness args:
 * lock: <unlock cell index>
 * accept one byte arg <unlock cell index>,
 * which denote an index of input that has the lock equals to <lock hash>,
 * script will assume the unlock is via timeout if not provide the arg.
 *
 * Custodian cell has two unlock path:
 * 1. Provide an input in the tx which lock equals to <lock hash>. or
 * 2. All inputs have `since` field:
 *   a. the `since` flags is set to relative epochs
 *   b. the `since` value is greater than or equals to PHASE2_TIMEOUT_SINCE
 */

#include "ckb_utils.h"
#include "common.h"

/* since relative time 42 epochs(~ 7 days) */
#define PHASE2_TIMEOUT_SINCE 0xa00001000000002a

int check_unlock_via_input(uint8_t unlock_input_cell_index) {
  uint8_t script[MAX_SCRIPT_SIZE];
  uint64_t len = MAX_SCRIPT_SIZE;
  int ret = ckb_checked_load_script(script, &len, 0);
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
  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t raw_args_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (raw_args_seg.size != HASH_SIZE) {
    return ERROR_ENCODING;
  }
  /* read unlock input cell lock_hash */
  uint8_t lock_hash[HASH_SIZE];
  len = HASH_SIZE;
  ret = ckb_checked_load_cell_by_field(
      lock_hash, &len, 0, unlock_input_cell_index, CKB_SOURCE_INPUT,
      CKB_CELL_FIELD_LOCK_HASH);
  if (ret != CKB_SUCCESS || len != HASH_SIZE) {
    return ERROR_ENCODING;
  }
  ret = memcmp(lock_hash, raw_args_seg.ptr, HASH_SIZE);
  if (ret != 0) {
    return ERROR_CL_MISMATCH_LOCK_HASH;
  }
  return CKB_SUCCESS;
}

/* to unlock via timeout, all inputs' since value should greater than or equals
 * to PHASE2_TIMEOUT_SINCE
 */
int check_unlock_via_timeout() {
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

int main() {
  uint8_t unlock_input_cell_index;
  int ret = load_witness_lock_args(0, CKB_SOURCE_GROUP_INPUT,
                                   &unlock_input_cell_index, 1);
  if (ret == CKB_SUCCESS) {
    /* unlock via input cell */
    ret = check_unlock_via_input(unlock_input_cell_index);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
  } else {
    /* unlock via timeout */
    ret = check_unlock_via_timeout();
    if (ret != CKB_SUCCESS) {
      return ret;
    }
  }
  return CKB_SUCCESS;
}
