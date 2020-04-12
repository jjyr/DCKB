/*
common.h

Defines commonly used high level functions and constants.
*/

/* uint128 type */
typedef unsigned __int128 uint128_t;

/* Errors */
/* common errors */
#define ERROR_ARGUMENTS_LEN -1
#define ERROR_ENCODING -2
#define ERROR_SYSCALL -3
#define ERROR_OVERFLOW -4
#define ERROR_LOAD_HEADER -10
#define ERROR_LOAD_SCRIPT -11
#define ERROR_LOAD_TYPE_ID -12
#define ERROR_LOAD_WITNESS_ARGS -13
#define ERROR_LOAD_ALIGN_INDEX -14
#define ERROR_LOAD_TYPE_HASH -15
#define ERROR_LOAD_OCCUPIED_CAPACITY -16
#define ERROR_LOAD_CAPACITY -17
#define ERROR_LOAD_DCKB_DATA -18
#define ERROR_LOAD_HEADER_INDEX -19

/* dckb errors */
#define ERROR_DCKB_INCORRECT_OUTPUT -30
#define ERROR_DCKB_TOO_MANY_SWAPS -31
#define ERROR_DCKB_INCORRECT_OUTPUT_UNINIT_TOKEN -32
#define ERROR_DCKB_ALIGN -33
#define ERROR_DCKB_OUTPUT_ALIGN -34

/* unlock_deposit errors */
#define ERROR_DL_CONFLICT_WITHDRAW_PHASE -40
#define ERROR_DL_CONFLICT_DAO_TYPE_HASH -41
#define ERROR_DL_NO_PROXY_CELL_INDEX -42
#define ERROR_DL_WRONG_DESTROY_AMOUNT -43
#define ERROR_DL_INVALID_LOCK_PROXY -44
#define ERROR_DL_INVALID_SINCE -45

/* since */
#define SINCE_VALUE_BITS 56
#define SINCE_VALUE_MASK 0x00ffffffffffffff
#define SINCE_EPOCH_FRACTION_FLAG 0b00100000

#define MAX_SCRIPT_SIZE 32768
#define MAX_HEADER_SIZE 32768

/* Contract related */
#define MAX_SWAP_CELLS 256
#define CKB_LEN 8
#define SINCE_LEN 8
#define BLOCK_NUM_LEN 8
#define UDT_LEN 16
#define HASH_SIZE 32
#define DAO_OCCUPIED_CAPACITY 10200000000

#include "ckb_syscalls.h"
#include "dao_utils.h"
#include "protocol.h"
#include "stdio.h"

typedef struct {
  uint128_t amount;
} SwapInfo;

typedef struct {
  uint64_t block_number;
  uint128_t amount;
  uint32_t cell_index;
} TokenInfo;

/* fetch inputs coins */
int fetch_inputs(unsigned char *dckb_type_hash, int *withdraw1_dao_cnt,
                 TokenInfo withdraw1_dao_infos[MAX_SWAP_CELLS],
                 int *withdraw2_dao_cnt,
                 TokenInfo withdraw2_dao_infos[MAX_SWAP_CELLS],
                 int *input_dckb_cnt,
                 TokenInfo input_dckb_infos[MAX_SWAP_CELLS]) {
  if (withdraw1_dao_cnt) *withdraw1_dao_cnt = 0;
  if (withdraw2_dao_cnt) *withdraw2_dao_cnt = 0;
  if (input_dckb_cnt) *input_dckb_cnt = 0;
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
      goto next;
    }
    printf("load cell type ret %d len %ld", ret, len);
    if (ret != CKB_SUCCESS || len != HASH_SIZE) {
      return ERROR_LOAD_TYPE_HASH;
    }
    uint8_t buf[UDT_LEN + BLOCK_NUM_LEN];
    len = UDT_LEN + BLOCK_NUM_LEN;
    ret = ckb_load_cell_data(buf, &len, 0, i, CKB_SOURCE_INPUT);
    if (ret == CKB_ITEM_MISSING) {
      goto next;
    }
    printf("load input cell data ret %d len %ld", ret, len);
    if (ret != CKB_SUCCESS || len > UDT_LEN + BLOCK_NUM_LEN) {
      return ERROR_LOAD_TYPE_HASH;
    }
    int is_dao = is_dao_type(input_type_hash);
    if (is_dao) {
      printf("check a new withdraw cell");
      /* withdraw NervosDAO */
      uint64_t deposited_block_number = *(uint64_t *)buf;
      len = CKB_LEN;
      uint64_t original_capacity;
      ret = ckb_checked_load_cell_by_field((uint8_t *)&original_capacity, &len,
                                           0, i, CKB_SOURCE_INPUT,
                                           CKB_CELL_FIELD_CAPACITY);
      if (ret != CKB_SUCCESS || len != CKB_LEN) {
        return ERROR_LOAD_CAPACITY;
      }
      /* record withdraw amount */
      if (is_dao_withdraw1_cell(buf, len)) {
        if (!withdraw1_dao_cnt || !withdraw1_dao_infos) {
          goto next;
        }
        int j = *withdraw1_dao_cnt;
        *withdraw1_dao_cnt += 1;
        withdraw1_dao_infos[j].amount = original_capacity;
        withdraw1_dao_infos[j].block_number = deposited_block_number;
        withdraw1_dao_infos[j].cell_index = i;
      } else {
        if (!withdraw2_dao_cnt || !withdraw2_dao_infos) {
          goto next;
        }
        int j = *withdraw2_dao_cnt;
        *withdraw2_dao_cnt += 1;
        withdraw2_dao_infos[j].amount = original_capacity;
        withdraw2_dao_infos[j].block_number = deposited_block_number;
        withdraw2_dao_infos[j].cell_index = i;
      }
    } else if (memcmp(input_type_hash, dckb_type_hash, HASH_SIZE) == 0) {
      /* DCKB */
      uint128_t amount;
      uint64_t block_number;
      if (len != UDT_LEN + BLOCK_NUM_LEN) {
        return ERROR_LOAD_DCKB_DATA;
      }
      amount = *(uint128_t *)buf;
      block_number = *(uint64_t *)(buf + UDT_LEN);
      /* record input amount */
      int j = *input_dckb_cnt;
      *input_dckb_cnt += 1;
      input_dckb_infos[j].amount = amount;
      input_dckb_infos[j].block_number = block_number;
      input_dckb_infos[j].cell_index = i;
    }
  next:
    i++;
  }
  return CKB_SUCCESS;
}

/* fetch outputs coins */
int fetch_outputs(unsigned char *dckb_type_hash, int *deposited_dao_cnt,
                  SwapInfo deposited_dao[MAX_SWAP_CELLS],
                  int *new_dckb_cell_cnt,
                  SwapInfo new_dckb_cell[MAX_SWAP_CELLS], int *dckb_cell_cnt,
                  TokenInfo dckb_cell[MAX_SWAP_CELLS]) {
  if (deposited_dao_cnt) *deposited_dao_cnt = 0;
  if (new_dckb_cell_cnt) *new_dckb_cell_cnt = 0;
  if (dckb_cell_cnt) *dckb_cell_cnt = 0;
  int ret;
  /* iterate all outputs */
  int i = 0;
  while (1) {
    unsigned char output_type_hash[HASH_SIZE];
    uint64_t len = HASH_SIZE;
    ret = ckb_checked_load_cell_by_field(output_type_hash, &len, 0, i,
                                         CKB_SOURCE_OUTPUT,
                                         CKB_CELL_FIELD_TYPE_HASH);
    printf("load output type ret %d", ret);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret == CKB_ITEM_MISSING) {
      goto next;
    }
    if (ret != CKB_SUCCESS || len != HASH_SIZE) {
      return ERROR_LOAD_TYPE_HASH;
    }
    len = BLOCK_NUM_LEN + UDT_LEN;
    uint8_t buf[BLOCK_NUM_LEN + UDT_LEN];
    ret = ckb_load_cell_data(buf, &len, 0, i, CKB_SOURCE_OUTPUT);
    if (ret == CKB_ITEM_MISSING) {
      goto next;
    }
    if (ret != CKB_SUCCESS || len > (UDT_LEN + BLOCK_NUM_LEN)) {
      return ERROR_LOAD_DCKB_DATA;
    }
    int is_dao = is_dao_type(output_type_hash) && is_dao_deposit_cell(buf, len);
    printf("check output is dao %d", is_dao);
    if (is_dao) {
      printf("check a new deposit cell");
      if (!deposited_dao_cnt || !deposited_dao) goto next;
      /* check deposited dao cell */
      uint64_t amount;
      len = CKB_LEN;
      ret = ckb_checked_load_cell_by_field(
          &amount, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_CAPACITY);
      if (ret != CKB_SUCCESS || len != CKB_LEN) {
        return ERROR_SYSCALL;
      }
      /* record deposited dao amount */
      if (*deposited_dao_cnt >= MAX_SWAP_CELLS) {
        return ERROR_DCKB_TOO_MANY_SWAPS;
      }
      int new_i = *deposited_dao_cnt;
      *deposited_dao_cnt += 1;
      deposited_dao[new_i].amount = amount;
    } else if (memcmp(output_type_hash, dckb_type_hash, HASH_SIZE) == 0) {
      /* check dckb cell */
      uint128_t amount;
      uint64_t block_number;
      if (len != (UDT_LEN + BLOCK_NUM_LEN)) {
        return ERROR_LOAD_DCKB_DATA;
      }
      amount = *(uint128_t *)buf;
      block_number = *(uint64_t *)(buf + UDT_LEN);
      printf("fetch output -> dckb block_number %ld", block_number);
      if (block_number == 0) {
        if (!new_dckb_cell_cnt || !new_dckb_cell) goto next;
        /* new dckb */
        if (*new_dckb_cell_cnt >= MAX_SWAP_CELLS) {
          return ERROR_DCKB_TOO_MANY_SWAPS;
        }
        int new_i = *new_dckb_cell_cnt;
        *new_dckb_cell_cnt += 1;
        new_dckb_cell[new_i].amount = amount;
      } else {
        if (!dckb_cell_cnt || !dckb_cell) goto next;
        /* dckb */
        if (*dckb_cell_cnt >= MAX_SWAP_CELLS) {
          return ERROR_DCKB_TOO_MANY_SWAPS;
        }
        int new_i = *dckb_cell_cnt;
        *dckb_cell_cnt += 1;
        dckb_cell[new_i].amount = amount;
        dckb_cell[new_i].block_number = block_number;
      }
    }
  next:
    i++;
  }
  return CKB_SUCCESS;
}

int align_dao_compensation(size_t i, size_t source,
                           dao_header_data_t align_target_data,
                           uint64_t deposited_block_number,
                           uint64_t original_capacity,
                           uint64_t *calculated_capacity) {
  if (align_target_data.block_number == deposited_block_number) {
    *calculated_capacity = original_capacity;
    return CKB_SUCCESS;
  }

  if (align_target_data.block_number < deposited_block_number) {
    printf("align %ld deposit block %ld", align_target_data.block_number,
           deposited_block_number);
    return ERROR_DCKB_ALIGN;
  }
  dao_header_data_t deposit_data;
  int ret = load_dao_header_data(i, source, &deposit_data);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  /* new dckb */
  if (deposited_block_number == 0) {
    deposited_block_number = deposit_data.block_number;
  }
  return calculate_dao_input_capacity(DAO_OCCUPIED_CAPACITY, deposit_data,
                                      align_target_data, deposited_block_number,
                                      original_capacity, calculated_capacity);
}
