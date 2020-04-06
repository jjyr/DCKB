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
 * 1. inputs WCKB - withdraw NervosDAO == outputs WCKB
 * 2. uninited WCKB == deposited NervosDAO
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
#include "dao_utils.h"
#include "defs.h"
#include "protocol.h"

#define SCRIPT_SIZE 32768
#define CKB_LEN 8
#define UDT_LEN 16
#define MAX_HEADER_SIZE 32768
#define MAX_SWAPS 256
#define DAO_OCCUPIED_CAPACITY 10200000000

static char dbuf[100];

typedef struct {
  unsigned char lock_hash[HASH_SIZE];
  uint128_t amount;
} SwapInfo;

typedef struct {
  uint64_t block_number;
  uint128_t amount;
} TokenInfo;

int load_align_target_header(uint64_t *index) {
  int ret;
  uint64_t len = 0;
  unsigned char witness[MAX_WITNESS_SIZE];

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

/* check inputs, return input WCKB */
int fetch_inputs(unsigned char *type_hash, int *withdraw_dao_cnt,
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

/* check outputs WCKB
 * 1. check uninitialized(height is 0) WCKB that mapping to DAO
 * 2. check initialized(height > 0) WCKB that equals to inputs
 */
int fetch_outputs(unsigned char *wckb_type_hash, uint64_t align_block_number,
                  int *deposited_dao_cnt, SwapInfo deposited_dao[MAX_SWAPS],
                  int *new_wckb_cell_cnt, SwapInfo new_wckb_cell[MAX_SWAPS],
                  int *wckb_cell_cnt, TokenInfo wckb_cell[MAX_SWAPS]) {
  *deposited_dao_cnt = 0;
  *new_wckb_cell_cnt = 0;
  *wckb_cell_cnt = 0;
  int ret;
  /* iterate all outputs */
  int i = 0;
  while (1) {
    unsigned char output_type_hash[HASH_SIZE];
    uint64_t len = HASH_SIZE;
    ret = ckb_checked_load_cell_by_field(output_type_hash, &len, 0, i,
                                         CKB_SOURCE_OUTPUT,
                                         CKB_CELL_FIELD_TYPE_HASH);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret == CKB_ITEM_MISSING) {
      i++;
      continue;
    }
    if (ret != CKB_SUCCESS || len != HASH_SIZE) {
      return ERROR_LOAD_TYPE_HASH;
    }
    len = BLOCK_NUM_LEN + UDT_LEN;
    uint8_t buf[BLOCK_NUM_LEN + UDT_LEN];
    ret = ckb_load_cell_data(buf, &len, 0, i, CKB_SOURCE_OUTPUT);
    if (ret == CKB_ITEM_MISSING) {
      i++;
      continue;
    }
    if (ret != CKB_SUCCESS || len > (UDT_LEN + BLOCK_NUM_LEN)) {
      return ERROR_LOAD_WCKB_DATA;
    }
    int is_dao = is_dao_deposit_cell(output_type_hash, buf, len);
    if (is_dao) {
      ckb_debug("check a new deposit cell");
      /* check deposited dao cell */
      uint64_t occupied_capacity;
      len = CKB_LEN;
      ret = ckb_checked_load_cell_by_field(&occupied_capacity, &len, 0, i,
                                           CKB_SOURCE_OUTPUT,
                                           CKB_CELL_FIELD_OCCUPIED_CAPACITY);
      if (ret != CKB_SUCCESS || len != CKB_LEN) {
        return ERROR_SYSCALL;
      }
      if (occupied_capacity != DAO_OCCUPIED_CAPACITY) {
        sprintf(dbuf, "output DAO occupied capacity %ld, expected %ld",
                occupied_capacity, DAO_OCCUPIED_CAPACITY);
        ckb_debug(dbuf);
        i += 1;
        continue;
      }
      uint64_t amount;
      unsigned char lock_hash[HASH_SIZE];
      len = HASH_SIZE;
      ret = ckb_checked_load_cell_by_field(
          lock_hash, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_LOCK_HASH);
      if (ret == CKB_INDEX_OUT_OF_BOUND) {
        break;
      }
      if (ret != CKB_SUCCESS || len != HASH_SIZE) {
        return ERROR_SYSCALL;
      }
      len = CKB_LEN;
      ret = ckb_checked_load_cell_by_field(
          &amount, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_CAPACITY);
      if (ret != CKB_SUCCESS || len != CKB_LEN) {
        return ERROR_SYSCALL;
      }
      /* record deposited dao amount */
      if (*deposited_dao_cnt >= MAX_SWAPS) {
        return ERROR_TOO_MANY_SWAPS;
      }
      int new_i = *deposited_dao_cnt;
      *deposited_dao_cnt += 1;
      deposited_dao[new_i].amount = amount;
      memcpy(deposited_dao[new_i].lock_hash, lock_hash, HASH_SIZE);
    } else if (memcmp(output_type_hash, wckb_type_hash, HASH_SIZE) == 0) {
      /* check wckb cell */
      /* read wckb info */
      uint128_t amount;
      uint64_t block_number;
      if (len != (UDT_LEN + BLOCK_NUM_LEN)) {
        return ERROR_LOAD_WCKB_DATA;
      }
      amount = *(uint128_t *)buf;
      block_number = *(uint64_t *)(buf + UDT_LEN);
      if (block_number == 0) {
        /* wckb is unitialized, record the amount */
        unsigned char lock_hash[HASH_SIZE];
        len = HASH_SIZE;
        ret = ckb_checked_load_cell_by_field(
            lock_hash, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_LOCK_HASH);
        if (ret == CKB_INDEX_OUT_OF_BOUND) {
          break;
        }
        if (ret != CKB_SUCCESS || len != HASH_SIZE) {
          return ERROR_SYSCALL;
        }
        /* initialize new instance */
        if (*new_wckb_cell_cnt >= MAX_SWAPS) {
          return ERROR_TOO_MANY_SWAPS;
        }
        int new_i = *new_wckb_cell_cnt;
        *new_wckb_cell_cnt += 1;
        new_wckb_cell[new_i].amount = amount;
        memcpy(new_wckb_cell[new_i].lock_hash, lock_hash, HASH_SIZE);
      } else {
        /* wckb is initialized */
        if (block_number != align_block_number) {
          return ERROR_OUTPUT_ALIGN;
        }
        /* initialize new instance */
        if (*wckb_cell_cnt >= MAX_SWAPS) {
          return ERROR_TOO_MANY_SWAPS;
        }
        int new_i = *wckb_cell_cnt;
        *wckb_cell_cnt += 1;
        wckb_cell[new_i].amount = amount;
        wckb_cell[new_i].block_number = block_number;
      }
    }
    i++;
  }
  return CKB_SUCCESS;
}

int align_dao(size_t i, size_t source, dao_header_data_t align_target_data,
              uint64_t deposited_block_number, uint64_t original_capacity,
              uint64_t *calculated_capacity) {
  if (align_target_data.block_number == deposited_block_number) {
    *calculated_capacity = original_capacity;
    return CKB_SUCCESS;
  }

  if (align_target_data.block_number < deposited_block_number) {
    sprintf(dbuf, "align %ld deposit block %ld", align_target_data.block_number,
            deposited_block_number);
    ckb_debug(dbuf);
    return ERROR_ALIGN;
  }
  dao_header_data_t deposit_data;
  int ret = load_dao_header_data(i, source, &deposit_data);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  /* uninitialized wckb */
  if (deposited_block_number == 0) {
    deposited_block_number = deposit_data.block_number;
  }
  return calculate_dao_input_capacity(DAO_OCCUPIED_CAPACITY, deposit_data,
                                      align_target_data, deposited_block_number,
                                      original_capacity, calculated_capacity);
}

int main() {
  ckb_debug("hello");
  int ret;
  unsigned char type_hash[HASH_SIZE];
  uint64_t len = HASH_SIZE;
  /* load self type hash */
  ret = ckb_load_script_hash(type_hash, &len, 0);
  sprintf(dbuf, "load self script ret %d", ret);
  ckb_debug(dbuf);
  if (ret != CKB_SUCCESS || len != HASH_SIZE) {
    return ERROR_SYSCALL;
  }
  /* load aligned target header */
  uint64_t align_header_index = 0;
  ret = load_align_target_header(&align_header_index);
  sprintf(dbuf, "load aligned target ret %d", ret);
  ckb_debug(dbuf);
  if (ret != CKB_SUCCESS && ret != CKB_INDEX_OUT_OF_BOUND) {
    return ret;
  }
  int has_align_header = ret == CKB_SUCCESS;
  dao_header_data_t align_target_data;
  if (has_align_header) {
    ret = load_dao_header_data(align_header_index, CKB_SOURCE_HEADER_DEP,
                               &align_target_data);
    sprintf(dbuf, "load aligned header ret %d", ret);
    ckb_debug(dbuf);
    if (ret != CKB_SUCCESS && ret != CKB_INDEX_OUT_OF_BOUND) {
      return ERROR_LOAD_HEADER;
    }
  }

  /* fetch inputs */
  TokenInfo withdraw_dao_infos[MAX_SWAPS];
  int withdraw_dao_cnt;
  TokenInfo input_wckb_infos[MAX_SWAPS];
  int input_wckb_cnt;
  ret = fetch_inputs(type_hash, &withdraw_dao_cnt, withdraw_dao_infos,
                     &input_wckb_cnt, input_wckb_infos);
  sprintf(dbuf, "fetch inputs ret %d", ret);
  ckb_debug(dbuf);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  /* fetch outputs */
  int deposited_dao_cnt = 0;
  SwapInfo deposited_dao[MAX_SWAPS];
  int output_new_wckb_cells_cnt = 0;
  SwapInfo output_new_wckb_cells[MAX_SWAPS];
  int output_wckb_cells_cnt = 0;
  TokenInfo output_wckb_cells[MAX_SWAPS];
  ret = fetch_outputs(type_hash, align_target_data.block_number,
                      &deposited_dao_cnt, deposited_dao,
                      &output_new_wckb_cells_cnt, output_new_wckb_cells,
                      &output_wckb_cells_cnt, output_wckb_cells);
  sprintf(dbuf, "fetch outputs ret %d", ret);
  ckb_debug(dbuf);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  sprintf(dbuf, "deposited_dao_cnt %d output_uninit_cnt %d output_init_cnt %d",
          deposited_dao_cnt, output_new_wckb_cells_cnt, output_wckb_cells_cnt);
  ckb_debug(dbuf);
  /* check equations
   * 1. inputs WCKB - withdraw NervosDAO == outputs WCKB
   * 2. uninited WCKB == deposited NervosDAO
   */
  uint64_t calculated_capacity;
  uint64_t total_withdraw_dao = 0;
  for (int i = 0; i < withdraw_dao_cnt; i++) {
    ret = align_dao(i, CKB_SOURCE_INPUT, align_target_data,
                    withdraw_dao_infos[i].block_number,
                    withdraw_dao_infos[i].amount, &calculated_capacity);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    sprintf(dbuf, "withdraw dao deposit at %ld money %ld calculated %ld",
            withdraw_dao_infos[i].block_number,
            (uint64_t)withdraw_dao_infos[i].amount, calculated_capacity);
    ckb_debug(dbuf);
    total_withdraw_dao += calculated_capacity;
  }

  uint64_t total_input_wckb = 0;
  for (int i = 0; i < input_wckb_cnt; i++) {
    ret = align_dao(i, CKB_SOURCE_INPUT, align_target_data,
                    input_wckb_infos[i].block_number,
                    input_wckb_infos[i].amount, &calculated_capacity);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    total_input_wckb += calculated_capacity;
  }

  uint64_t total_output_wckb = 0;
  for (int i = 0; i < output_wckb_cells_cnt; i++) {
    ret = align_dao(i, CKB_SOURCE_OUTPUT, align_target_data,
                    output_wckb_cells[i].block_number,
                    output_wckb_cells[i].amount, &calculated_capacity);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    total_output_wckb += calculated_capacity;
  }

  /* 1. inputs WCKB - withdraw NervosDAO == outputs WCKB */
  if (!(total_input_wckb - total_withdraw_dao == total_output_wckb)) {
    sprintf(dbuf,
            "equation 1 total_input_wckb %ld total_withdraw_dao %ld "
            "total_output_wckb %ld",
            total_input_wckb, total_withdraw_dao, total_output_wckb);
    ckb_debug(dbuf);
    return ERROR_INCORRECT_OUTPUT_WCKB;
  }

  /* 2. uninited WCKB == deposited NervosDAO */
  uint64_t total_output_new_wckb = 0;
  for (int i = 0; i < output_new_wckb_cells_cnt; i++) {
    total_output_new_wckb += (uint64_t)output_new_wckb_cells[i].amount;
  }

  uint64_t total_deposited_dao = 0;
  for (int i = 0; i < deposited_dao_cnt; i++) {
    total_deposited_dao += (uint64_t)deposited_dao[i].amount;
  }
  if (total_output_new_wckb != total_deposited_dao) {
    sprintf(dbuf, "uninit amount %ld, deposited_dao amount %ld",
            (uint64_t)total_output_new_wckb, (uint64_t)total_deposited_dao);
    ckb_debug(dbuf);
    return ERROR_INCORRECT_UNINIT_OUTPUT_WCKB;
  }

  ckb_debug("bye");
  return CKB_SUCCESS;
}
