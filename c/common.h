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

/* load errors */
#define ERROR_LOAD_HEADER -60
#define ERROR_LOAD_SCRIPT -61
#define ERROR_LOAD_TYPE_ID -62
#define ERROR_LOAD_WITNESS_ARGS -63
#define ERROR_LOAD_DAO_HEADER_DATA -64
#define ERROR_LOAD_TYPE_HASH -65
#define ERROR_LOAD_OCCUPIED_CAPACITY -66
#define ERROR_LOAD_CAPACITY -67
#define ERROR_LOAD_DCKB_DATA -68
#define ERROR_LOAD_HEADER_INDEX -69
#define ERROR_LOAD_OUT_POINT -70
#define ERROR_LOAD_ALIGN_TARGET -71
#define ERROR_INCORRECT_DAO_LOCK -72
#define ERROR_DAO_LOCK_CHECK -73

/* dckb errors */
#define ERROR_DCKB_INCORRECT_OUTPUT -30
#define ERROR_DCKB_TOO_MANY_SWAPS -31
#define ERROR_DCKB_INCORRECT_OUTPUT_UNINIT_TOKEN -32
#define ERROR_DCKB_ALIGN -33
#define ERROR_DCKB_OUTPUT_ALIGN -34

/* dao lock errors */
#define ERROR_DL_CONFLICT_WITHDRAW_PHASE -40
#define ERROR_DL_CONFLICT_DAO_TYPE_HASH -41
#define ERROR_DL_NO_CUSTODIAN_CELL_INDEX -42
#define ERROR_DL_INCORRECT_DESTROY_AMOUNT -43
#define ERROR_DL_INVALID_CUSTODIAN_CELL -44
#define ERROR_DL_MISMATCH_CUSTODIAN_CELL_TX_HASH -45
#define ERROR_DL_INVALID_SINCE -46
#define ERROR_DL_REFUND_CKB_NOT_ENOUGH -47

/* custodian lock errors */
#define ERROR_CL_MISMATCH_LOCK_HASH -80

#define MAX_SCRIPT_SIZE 32768
#define MAX_HEADER_SIZE 32768
#define OUT_POINT_SIZE 36

/* Contract related */
#define MAX_SWAP_CELLS 256
#define CKB_LEN 8
#define SINCE_LEN 8
#define BLOCK_NUM_LEN 8
#define UDT_LEN 16
#define HASH_SIZE 32
#define DAO_OCCUPIED_CAPACITY 14600000000          // 146 Bytes
#define MAX_DEPOSIT_DAO_CAPACITY 1000000000000000  // 10_000_000 CKB
#define HASH_TYPE_DATA 0
#define HASH_TYPE_TYPE_ID 1

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

int parse_dckb_data(uint128_t *amount, uint64_t *block_number, uint8_t *data,
                    size_t data_len) {
  if (data_len != UDT_LEN + BLOCK_NUM_LEN) {
    return ERROR_LOAD_DCKB_DATA;
  }
  *amount = *(uint128_t *)data;
  *block_number = *(uint64_t *)(data + UDT_LEN);
  return CKB_SUCCESS;
}

int check_dao_lock(const uint8_t dao_lock_code_hash[HASH_SIZE], uint64_t i,
                   uint64_t source) {
  if (dao_lock_code_hash == NULL) {
    return ERROR_DAO_LOCK_CHECK;
  }
  uint8_t script[MAX_SCRIPT_SIZE];
  uint64_t len = MAX_SCRIPT_SIZE;
  int ret = ckb_checked_load_cell_by_field(script, &len, 0, i, source,
                                           CKB_CELL_FIELD_LOCK);
  if (ret != CKB_SUCCESS || len > MAX_SCRIPT_SIZE) {
    return ERROR_ENCODING;
  }
  mol_seg_t script_seg;
  script_seg.ptr = script;
  script_seg.size = len;
  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }
  mol_seg_t code_hash_seg = MolReader_Script_get_code_hash(&script_seg);
  mol_seg_t hash_type_seg = MolReader_Script_get_hash_type(&script_seg);
  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t raw_args_seg = MolReader_Bytes_raw_bytes(&args_seg);
  /* check code hash */
  ret = memcmp(code_hash_seg.ptr, dao_lock_code_hash, HASH_SIZE);
  if (ret != 0) {
    printf("unexpected deposit lock code hash");
    return ERROR_INCORRECT_DAO_LOCK;
  }
  /* check hash type */
  if (*hash_type_seg.ptr != HASH_TYPE_DATA) {
    printf("unexpected deposit lock hash type");
    return ERROR_INCORRECT_DAO_LOCK;
  }
  /* check args */
  if (raw_args_seg.size != HASH_SIZE * 2) {
    printf("unexpected deposit args size %d", raw_args_seg.size);
    return ERROR_INCORRECT_DAO_LOCK;
  }
  uint8_t script_hash[HASH_SIZE];
  len = HASH_SIZE;
  ret = ckb_load_script_hash(script_hash, &len, 0);
  if (ret != CKB_SUCCESS || len != HASH_SIZE) {
    return ERROR_ENCODING;
  }
  ret = memcmp(script_hash, raw_args_seg.ptr, HASH_SIZE);
  if (ret != 0) {
    printf("unexpected deposit lock args");
    return ERROR_INCORRECT_DAO_LOCK;
  }
  return CKB_SUCCESS;
}

/* fetch inputs coins */
int fetch_inputs(const uint8_t dckb_type_hash[HASH_SIZE],
                 const uint8_t dao_lock_code_hash[HASH_SIZE],
                 int *withdraw1_dao_cnt,
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
      /* only count deposit lock dao cells */
      ret = check_dao_lock(dao_lock_code_hash, i, CKB_SOURCE_INPUT);
      printf("check deposit lock ret %d", ret);
      if (ret != CKB_SUCCESS) {
        goto next;
      }
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
      ret = parse_dckb_data(&amount, &block_number, buf, len);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
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
int fetch_outputs(const uint8_t dckb_type_hash[HASH_SIZE],
                  const uint8_t dao_lock_code_hash[HASH_SIZE],
                  int *deposited_dao_cnt,
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
      /* only count deposit lock dao cells */
      ret = check_dao_lock(dao_lock_code_hash, i, CKB_SOURCE_OUTPUT);
      printf("check deposit lock ret %d", ret);
      if (ret != CKB_SUCCESS) {
        goto next;
      }
      /* check deposited dao cell */
      uint64_t amount;
      len = CKB_LEN;
      ret = ckb_checked_load_cell_by_field(
          &amount, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_CAPACITY);
      if (ret != CKB_SUCCESS || len != CKB_LEN) {
        return ERROR_SYSCALL;
      }
      /* a sinlge DAO cell contained capacity must less than this limitation */
      if (amount > MAX_DEPOSIT_DAO_CAPACITY) {
        goto next;
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
      ret = parse_dckb_data(&amount, &block_number, buf, len);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
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

int load_witness_lock_args(uint64_t index, uint64_t source, uint8_t *lock_arg,
                           size_t lock_arg_len) {
  int ret;
  uint64_t len = MAX_WITNESS_SIZE;
  uint8_t witness[MAX_WITNESS_SIZE];
  ret = ckb_load_witness(witness, &len, 0, index, source);
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
    return ERROR_LOAD_WITNESS_ARGS;
  }

  mol_seg_t lock_bytes_seg = MolReader_Bytes_raw_bytes(&lock_seg);
  if (lock_bytes_seg.size != lock_arg_len) {
    return ERROR_LOAD_WITNESS_ARGS;
  }
  memcpy(lock_arg, lock_bytes_seg.ptr, lock_arg_len);
  return CKB_SUCCESS;
}

int search_dao_header_data(uint64_t expected_block_number,
                           dao_header_data_t *dao_header_data) {
  int ret;
  int i = 0;
  while (1) {
    ret = load_dao_header_data(i, CKB_SOURCE_HEADER_DEP, dao_header_data);
    if (ret != CKB_SUCCESS) {
      return ERROR_LOAD_HEADER;
    }
    // find the header
    if (dao_header_data->block_number == expected_block_number) {
      return CKB_SUCCESS;
    }
    i++;
  }

  return ERROR_LOAD_HEADER;
}

int load_align_target_dao_header_data(uint64_t i, uint64_t source,
                                      dao_header_data_t *dao_header_data) {
  int ret;
  uint64_t len = 0;
  uint8_t witness[MAX_WITNESS_SIZE];

  len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(witness, &len, 0, i, source);
  if (ret != CKB_SUCCESS) {
    return ERROR_LOAD_DAO_HEADER_DATA;
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
    printf("type_seg is none");
    return ERROR_LOAD_DAO_HEADER_DATA;
  }

  mol_seg_t type_bytes_seg = MolReader_Bytes_raw_bytes(&type_seg);
  // load align target block number from witness
  if (type_bytes_seg.size != 8) {
    printf("bytes len is %d", type_bytes_seg.size);
    return ERROR_LOAD_DAO_HEADER_DATA;
  }

  uint64_t align_target_block_number = *(uint64_t *)type_bytes_seg.ptr;

  ret = search_dao_header_data(align_target_block_number, dao_header_data);
  printf("load dao header number %ld ret %d", align_target_block_number, ret);
  if (ret != CKB_SUCCESS) {
    return ERROR_LOAD_HEADER;
  }
  return CKB_SUCCESS;
}

int align_dckb_cell(size_t i, size_t source,
                    dao_header_data_t align_target_data,
                    uint64_t deposited_block_number, uint64_t original_capacity,
                    uint64_t *calculated_capacity) {
  dao_header_data_t deposit_data;

  /* new dckb */
  if (deposited_block_number == 0) {
    int ret = load_dao_header_data(i, source, &deposit_data);
    printf("new dckb deposit block ret %d", ret);
    if (ret != CKB_SUCCESS) {
      return ERROR_LOAD_DAO_HEADER_DATA;
    }
    printf("new dckb deposit block %ld", deposit_data.block_number);
    deposited_block_number = deposit_data.block_number;
  } else {
    int ret = search_dao_header_data(deposited_block_number, &deposit_data);
    printf("load dao header data by cell i %ld source %ld ret %d", i, source,
           ret);
    if (ret != CKB_SUCCESS) {
      return ERROR_LOAD_DAO_HEADER_DATA;
    }
  }

  if (align_target_data.block_number == deposited_block_number) {
    *calculated_capacity = original_capacity;
    return CKB_SUCCESS;
  }

  if (align_target_data.block_number < deposited_block_number) {
    printf("align error target number %ld deposit number %ld",
           align_target_data.block_number, deposited_block_number);
    return ERROR_DCKB_ALIGN;
  }

  return calculate_dao_input_capacity(0, deposit_data, align_target_data,
                                      deposited_block_number, original_capacity,
                                      calculated_capacity);
}
