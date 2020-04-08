/* WCKB type script
 * WCKB is an extended UDT,
 * support transfer WCKB token while the native CKB is locked in NervosDAO,
 * WCKB owner can withdraw native CKB and interests from NervosDAO by destroy
 * corresponded WCKB.
 *
 * WCKB format:
 * data: tokens(16 bytes) | height(8 bytes)
 * > 16 bytes u128 number to store the TOKEN.
 * > 8 bytes u64 number to store the block number.
 *
 * Align block number:
 * > Align block number is a u64 number indicates to dep_headers,
 *   denoted by the first WCKB input's witness type args.
 * > All outputs WCKB cell's must aligned to the header,
 *   which means the header number should heigher than or at least equals to
 * WCKB cells. > Align means that we update the height of WCKB, and update the
 * amount by apply NervosDAO formula.
 *
 * Verification:
 * This type script make sure the equation between inputs and outputs(all coins
 * are aligned):
 * 1. inputs WCKB >= outputs WCKB
 * 2. new WCKB == deposited NervosDAO
 * 3. all outputs WCKB's block number must align to aligned block number
 *
 * Get WCKB:
 * 1. send a NervosDAO deposition request
 * 2. put a output in the same tx to create corresponded WCKB
 * 3. the height should set to 0
 *
 * Transfer WCKB:
 * 1. The first WCKB input must has highest block number compares to other
 * inputs.
 * 2. Outputs WCKB must aligned to this number.
 * 3. verify inputs amount is equals to outputs amount (after aligned).
 *
 * Withdraw WCKB:
 * 1. Perform NervosDAO withdraw phase 1.
 * 2. Prepare a WCKB input that has enough coins to cover the withdraw CKB
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
  TokenInfo input_wckb_infos[MAX_SWAP_CELLS];
  int input_wckb_cnt;
  ret = fetch_inputs(type_hash, NULL, NULL, NULL, NULL, &input_wckb_cnt,
                     input_wckb_infos);
  printf("fetch inputs ret %d", ret);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  /* fetch outputs */
  int deposited_dao_cnt = 0;
  SwapInfo deposited_dao[MAX_SWAP_CELLS];
  int output_new_wckb_cells_cnt = 0;
  SwapInfo output_new_wckb_cells[MAX_SWAP_CELLS];
  int output_wckb_cells_cnt = 0;
  TokenInfo output_wckb_cells[MAX_SWAP_CELLS];
  ret = fetch_outputs(type_hash, &deposited_dao_cnt, deposited_dao,
                      &output_new_wckb_cells_cnt, output_new_wckb_cells,
                      &output_wckb_cells_cnt, output_wckb_cells);
  printf("fetch outputs ret %d", ret);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  printf("deposited_dao_cnt %d output_uninit_cnt %d output_init_cnt %d",
         deposited_dao_cnt, output_new_wckb_cells_cnt, output_wckb_cells_cnt);
  /* check equations
   * 1. inputs WCKB >= outputs WCKB
   * 2. new WCKB == deposited NervosDAO
   */
  uint64_t calculated_capacity;
  uint64_t total_input_wckb = 0;
  for (int i = 0; i < input_wckb_cnt; i++) {
    ret = align_dao_compensation(i, CKB_SOURCE_INPUT, align_target_data,
                                 input_wckb_infos[i].block_number,
                                 input_wckb_infos[i].amount,
                                 &calculated_capacity);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    total_input_wckb += calculated_capacity;
  }

  uint64_t total_output_wckb = 0;
  for (int i = 0; i < output_wckb_cells_cnt; i++) {
    if (output_wckb_cells[i].block_number != align_target_data.block_number) {
      return ERROR_OUTPUT_ALIGN;
    }
    total_output_wckb += output_wckb_cells[i].amount;
  }

  /* 1. inputs WCKB >= outputs WCKB */
  if (total_input_wckb < total_output_wckb) {
    printf(
        "equation 1 total_input_wckb %ld "
        "total_output_wckb %ld",
        total_input_wckb, total_output_wckb);
    return ERROR_INCORRECT_OUTPUT_WCKB;
  }

  /* 2. new WCKB == deposited NervosDAO */
  uint64_t total_output_new_wckb = 0;
  for (int i = 0; i < output_new_wckb_cells_cnt; i++) {
    total_output_new_wckb += (uint64_t)output_new_wckb_cells[i].amount;
  }

  uint64_t total_deposited_dao = 0;
  for (int i = 0; i < deposited_dao_cnt; i++) {
    total_deposited_dao += (uint64_t)deposited_dao[i].amount;
  }
  if (total_output_new_wckb != total_deposited_dao) {
    printf("new wckb amount %ld, deposited_dao amount %ld",
           (uint64_t)total_output_new_wckb, (uint64_t)total_deposited_dao);
    return ERROR_INCORRECT_UNINIT_OUTPUT_WCKB;
  }

  printf("done");
  return CKB_SUCCESS;
}
