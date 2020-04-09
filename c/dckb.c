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
 * Align block number:
 * > Align block number is a u64 number indicates to dep_headers,
 *   denoted by the first DCKB input's witness type args.
 * > All outputs DCKB cell's must aligned to the header,
 *   which means the header number should heigher than or at least equals to
 * DCKB cells. > Align means that we update the height of DCKB, and update the
 * amount by apply NervosDAO formula.
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
#include "protocol.h"
#include "stdio.h"

#define SCRIPT_SIZE 32768
#define MAX_HEADER_SIZE 32768

int load_align_target_header(uint64_t *index) {
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
  mol_seg_t type_seg = MolReader_WitnessArgs_get_input_type(&witness_seg);

  if (MolReader_BytesOpt_is_none(&type_seg)) {
    return ERROR_LOAD_ALIGN_INDEX;
  }

  mol_seg_t type_bytes_seg = MolReader_Bytes_raw_bytes(&type_seg);
  if (type_bytes_seg.size != 8) {
    return ERROR_LOAD_ALIGN_INDEX;
  }

  *index = *(uint64_t *)type_bytes_seg.ptr;
  return CKB_SUCCESS;
}

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
  uint64_t align_header_index = 0;
  ret = load_align_target_header(&align_header_index);
  printf("load aligned target ret %d", ret);
  if (ret != CKB_SUCCESS && ret != CKB_INDEX_OUT_OF_BOUND) {
    return ret;
  }
  int has_align_header = ret == CKB_SUCCESS;
  dao_header_data_t align_target_data;
  if (has_align_header) {
    ret = load_dao_header_data(align_header_index, CKB_SOURCE_HEADER_DEP,
                               &align_target_data);
    printf("load aligned header ret %d", ret);
    if (ret != CKB_SUCCESS && ret != CKB_INDEX_OUT_OF_BOUND) {
      return ERROR_LOAD_HEADER;
    }
  }

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
  uint64_t calculated_capacity;
  uint64_t total_input_dckb = 0;
  for (int i = 0; i < input_dckb_cells_cnt; i++) {
    ret = align_dao_compensation(i, CKB_SOURCE_INPUT, align_target_data,
                                 input_dckb_cells[i].block_number,
                                 input_dckb_cells[i].amount,
                                 &calculated_capacity);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (__builtin_uaddl_overflow(total_input_dckb, calculated_capacity,
                                 &total_input_dckb)) {
      return ERROR_OVERFLOW;
    }
  }

  uint64_t total_output_dckb = 0;
  for (int i = 0; i < output_dckb_cells_cnt; i++) {
    if (output_dckb_cells[i].block_number != align_target_data.block_number) {
      return ERROR_OUTPUT_ALIGN;
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
    return ERROR_INCORRECT_OUTPUT_DCKB;
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
    }
    if (__builtin_uaddl_overflow(total_deposited_dao, amount,
                                 &total_deposited_dao)) {
      return ERROR_OVERFLOW;
    }
  }
  if (total_output_new_dckb != total_deposited_dao) {
    printf("new dckb amount %ld, deposited_dao amount %ld",
           (uint64_t)total_output_new_dckb, (uint64_t)total_deposited_dao);
    return ERROR_INCORRECT_UNINIT_OUTPUT_DCKB;
  }

  printf("done");
  return CKB_SUCCESS;
}
