/* custodian lock
 * this lock is used for custodian DCKB cell when withdraw from NervosDAO
 * 1. inputs should include a custodian cell which generated from same
 * transaction of DAO cells. or
 * 2. inputs have `since` field.
 *   a. the `since` flags is set to relative epochs
 *   b. the `since` value is greater than or equals to PHASE2_TIMEOUT_SINCE
 */

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

int main() { return -1; }
