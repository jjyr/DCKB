/* DCKB type script
 * DCKB is an extended UDT,
 * support transfer DCKB token while the native CKB is locked in NervosDAO,
 * DCKB owner can withdraw native CKB and interests from NervosDAO by destroy
 * corresponded DCKB.
 *
 * DCKB format:
 * data: tokens(16 bytes) | height(8 bytes)
 * > 16 bytes u128 number to store the TOKEN.
 * > 8 bytes u64 number to store the block number.
 *
 * Align block:
 * 1. In a transaction, all inputs and outputs DCKB cells should aligned to a
 * same block number.
 * 2. Align means we update the height of DCKB to a heigher block number,
 * and update the amount by apply NervosDAO formula.
 * 3. All inputs DCKB cell should has a index of dep_headers in the witness's
 * input_type, the index is denoted by a u8 number, which point to the header of
 * their current block number
 * 4. The first output DCKB cell should has a index of dep_headers in the
 * witness's output_type, the index is denoted by a u8 number, which point to a
 * block header that all outputs should align to.
 *
 * Verification:
 * This type script make sure the equation between inputs and outputs(all coins
 * are aligned):
 * 1. inputs DCKB >= outputs DCKB
 * 2. new DCKB == deposited NervosDAO
 * 3. all outputs DCKB's block number must align to aligned block number
 *
 * Get DCKB:
 * 1. send a NervosDAO deposition request
 * 2. put a output in the same tx to create corresponded DCKB
 * 3. the height should set to 0
 *
 * Transfer DCKB:
 * 1. The first DCKB input must has highest block number compares to other
 * inputs.
 * 2. Outputs DCKB must aligned to this number.
 * 3. verify inputs amount is equals to outputs amount (after aligned).
 *
 * Withdraw DCKB:
 * 1. Perform NervosDAO withdraw phase 1.
 * 2. Prepare a DCKB input that has enough coins to cover the withdraw CKB
 * coins.
 * 3. Put a withdrawed output.
 *
 */

#include "blake2b.h"
#include "ckb_syscalls.h"
#include "common.h"
#include "const.h"
#include "protocol.h"
#include "stdio.h"

int main() {
  printf("hello");
  int ret;
  uint8_t type_hash[HASH_SIZE];
  uint64_t len = HASH_SIZE;
  /* load self type hash */
  ret = ckb_load_script_hash(type_hash, &len, 0);
  printf("load self script ret %d", ret);
  if (ret != CKB_SUCCESS || len != HASH_SIZE) {
    return ERROR_SYSCALL;
  }
  /* load aligned target header */
  dao_header_data_t align_target_data;
  ret = load_dao_header_data_by_cell(0, CKB_SOURCE_GROUP_INPUT, 1,
                                     &align_target_data);
  printf("load aligned target ret %d", ret);
  if (ret != CKB_SUCCESS && ret != ERROR_LOAD_DAO_HEADER_DATA) {
    return ret;
  }
  /* only transfer DCKB need align target data, we lazy raise this error */
  int has_aligned_target = ret == CKB_SUCCESS;

  /* fetch inputs */
  TokenInfo input_dckb_cells[MAX_SWAP_CELLS];
  int input_dckb_cells_cnt;
  ret = fetch_inputs(type_hash, NULL, NULL, NULL, NULL, &input_dckb_cells_cnt,
                     input_dckb_cells);
  printf("fetch inputs ret %d", ret);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  /* fetch outputs */
  int deposited_dao_cells_cnt = 0;
  SwapInfo deposited_dao_cells[MAX_SWAP_CELLS];
  int output_new_dckb_cells_cnt = 0;
  SwapInfo output_new_dckb_cells[MAX_SWAP_CELLS];
  int output_dckb_cells_cnt = 0;
  TokenInfo output_dckb_cells[MAX_SWAP_CELLS];
  ret = fetch_outputs(type_hash, &deposited_dao_cells_cnt, deposited_dao_cells,
                      &output_new_dckb_cells_cnt, output_new_dckb_cells,
                      &output_dckb_cells_cnt, output_dckb_cells);
  printf("fetch outputs ret %d", ret);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  printf("deposited_dao_cells_cnt %d output_uninit_cnt %d output_init_cnt %d",
         deposited_dao_cells_cnt, output_new_dckb_cells_cnt,
         output_dckb_cells_cnt);
  /* check equations
   * 1. inputs DCKB >= outputs DCKB
   * 2. new DCKB == deposited NervosDAO
   */
  if (input_dckb_cells_cnt > 0 && !has_aligned_target) {
    return ERROR_LOAD_ALIGN_TARGET;
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

  if (output_dckb_cells_cnt > 0 && !has_aligned_target) {
    return ERROR_LOAD_ALIGN_TARGET;
  }
  uint64_t total_output_dckb = 0;
  for (int i = 0; i < output_dckb_cells_cnt; i++) {
    if (output_dckb_cells[i].block_number != align_target_data.block_number) {
      printf("output align to %ld, expected %ld",
             output_dckb_cells[i].block_number, align_target_data.block_number);
      return ERROR_DCKB_OUTPUT_ALIGN;
    }
    if (__builtin_uaddl_overflow(total_output_dckb, output_dckb_cells[i].amount,
                                 &total_output_dckb)) {
      return ERROR_OVERFLOW;
    }
  }

  /* 1. inputs DCKB >= outputs DCKB */
  if (total_input_dckb < total_output_dckb) {
    printf(
        "equation 1 total_input_dckb %ld "
        "total_output_dckb %ld",
        total_input_dckb, total_output_dckb);
    return ERROR_DCKB_INCORRECT_OUTPUT;
  }

  /* 2. new DCKB == deposited NervosDAO */
  uint64_t total_output_new_dckb = 0;
  for (int i = 0; i < output_new_dckb_cells_cnt; i++) {
    uint64_t amount = (uint64_t)output_new_dckb_cells[i].amount;
    if (amount != output_new_dckb_cells[i].amount) {
      return ERROR_OVERFLOW;
    }
    if (__builtin_uaddl_overflow(total_output_new_dckb, amount,
                                 &total_output_new_dckb)) {
      return ERROR_OVERFLOW;
    }
  }

  uint64_t total_deposited_dao = 0;
  for (int i = 0; i < deposited_dao_cells_cnt; i++) {
    uint64_t amount = (uint64_t)deposited_dao_cells[i].amount;
    if (amount != deposited_dao_cells[i].amount) {
      return ERROR_OVERFLOW;
      /* remove DAO cell occupied capacity */
    }
    if (__builtin_usubl_overflow(amount, DAO_OCCUPIED_CAPACITY, &amount)) {
      return ERROR_OVERFLOW;
    }
    if (__builtin_uaddl_overflow(total_deposited_dao, amount,
                                 &total_deposited_dao)) {
      return ERROR_OVERFLOW;
    }
  }
  if (total_output_new_dckb != total_deposited_dao) {
    printf("new dckb amount %ld, deposited_dao amount %ld",
           (uint64_t)total_output_new_dckb, (uint64_t)total_deposited_dao);
    return ERROR_DCKB_INCORRECT_OUTPUT_UNINIT_TOKEN;
  }

  printf("done");
  return CKB_SUCCESS;
}
