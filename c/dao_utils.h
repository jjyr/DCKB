/* Copy from
 * https://github.com/nervosnetwork/ckb-system-scripts/blob/master/c/dao.c
 */

#include "protocol.h"
#include "stdio.h"

#define ERROR_UNKNOWN -1
#define ERROR_WRONG_NUMBER_OF_ARGUMENTS -2
#define ERROR_BUFFER_NOT_ENOUGH -10
#define ERROR_WITNESS_TOO_LONG -12
#define ERROR_INVALID_WITHDRAW_BLOCK -14
#define ERROR_INCORRECT_CAPACITY -15
#define ERROR_INCORRECT_EPOCH -16
#define ERROR_INCORRECT_SINCE -17
#define ERROR_TOO_MANY_OUTPUT_CELLS -18
#define ERROR_NEWLY_CREATED_CELL -19
#define ERROR_INVALID_WITHDRAWING_CELL -20
#define ERROR_SCRIPT_TOO_LONG -21

#define HEADER_SIZE 4096
/* 32 KB */
#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768

/*
 * For simplicity, a transaction containing Nervos DAO script is limited to
 * 64 output cells so we can simplify processing. Later we might upgrade this
 * script to relax this limitation.
 */
#define MAX_OUTPUT_LENGTH 64

#define LOCK_PERIOD_EPOCHES 180

#define EPOCH_NUMBER_OFFSET 0
#define EPOCH_NUMBER_BITS 24
#define EPOCH_NUMBER_MASK ((1 << EPOCH_NUMBER_BITS) - 1)
#define EPOCH_INDEX_OFFSET EPOCH_NUMBER_BITS
#define EPOCH_INDEX_BITS 16
#define EPOCH_INDEX_MASK ((1 << EPOCH_INDEX_BITS) - 1)
#define EPOCH_LENGTH_OFFSET (EPOCH_NUMBER_BITS + EPOCH_INDEX_BITS)
#define EPOCH_LENGTH_BITS 16
#define EPOCH_LENGTH_MASK ((1 << EPOCH_LENGTH_BITS) - 1)

/* Type hash of NervosDAO script,
 * blake2b(Script(hash_type: Type, code_hash: <type_id>))
 */
const uint8_t NERVOS_DAO_TYPE_HASH[] = {
    226, 137, 104, 157, 176, 16, 226, 115, 88,  4,  92, 188, 116, 239, 156, 196,
    231, 126, 183, 229, 44,  62, 66,  68,  125, 44, 0,  201, 226, 74,  236, 8,
};

/* Function to check DAO cells */

int is_dao_type(unsigned char type_hash[HASH_SIZE]) {
  int ret = memcmp(NERVOS_DAO_TYPE_HASH, type_hash, HASH_SIZE);
  printf("ret %i", ret);
  return ret == 0;
}

int is_dao_deposit_cell(uint8_t *data, uint64_t data_len) {
  /* check data length */
  if (data_len != BLOCK_NUM_LEN) {
    return 0;
  }
  /* check data */
  for (int i = 0; i < BLOCK_NUM_LEN; i++) {
    if (data[i] != 0) {
      return 0;
    }
  }
  return 1;
}

int is_dao_withdraw1_cell(uint8_t *data, uint64_t data_len) {
  if (data_len != BLOCK_NUM_LEN) {
    return 0;
  }
  uint64_t block_number = *(uint64_t *)data;
  if (block_number == 0) {
    return 0;
  }
  return 1;
}

/* Functions to calculate DAO compensation */

typedef struct {
  uint64_t block_number;
  uint64_t epoch_number;
  uint64_t epoch_index;
  uint64_t epoch_length;
  uint8_t dao[32];
} dao_header_data_t;

static int extract_epoch_info(uint64_t epoch, int allow_zero_epoch_length,
                              uint64_t *epoch_number, uint64_t *epoch_index,
                              uint64_t *epoch_length) {
  uint64_t index = (epoch >> EPOCH_INDEX_OFFSET) & EPOCH_INDEX_MASK;
  uint64_t length = (epoch >> EPOCH_LENGTH_OFFSET) & EPOCH_LENGTH_MASK;
  if (length == 0) {
    if (allow_zero_epoch_length) {
      index = 0;
      length = 1;
    } else {
      return ERROR_INCORRECT_EPOCH;
    }
  }
  if (index >= length) {
    return ERROR_INCORRECT_EPOCH;
  }
  *epoch_number = (epoch >> EPOCH_NUMBER_OFFSET) & EPOCH_NUMBER_MASK;
  *epoch_index = index;
  *epoch_length = length;
  return CKB_SUCCESS;
}

/*
 * Fetch deposit header hash from the input type part in witness, it should be
 * exactly 8 bytes long. Kept as a separate function so witness buffer
 * can be cleaned as soon as it is not needed.
 */
static int extract_deposit_header_index(size_t input_index, size_t *index) {
  int ret;
  uint64_t len = 0;
  unsigned char witness[MAX_WITNESS_SIZE];

  len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(witness, &len, 0, input_index, CKB_SOURCE_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > MAX_WITNESS_SIZE) {
    return ERROR_WITNESS_TOO_LONG;
  }

  mol_seg_t witness_seg;
  witness_seg.ptr = (uint8_t *)witness;
  witness_seg.size = len;

  if (MolReader_WitnessArgs_verify(&witness_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }
  /* Load type args */
  mol_seg_t type_seg = MolReader_WitnessArgs_get_input_type(&witness_seg);

  if (MolReader_BytesOpt_is_none(&type_seg)) {
    return ERROR_ENCODING;
  }

  mol_seg_t type_bytes_seg = MolReader_Bytes_raw_bytes(&type_seg);
  if (type_bytes_seg.size != 8) {
    return ERROR_ENCODING;
  }

  *index = *type_bytes_seg.ptr;
  return CKB_SUCCESS;
}

int load_dao_header_data(size_t index, size_t source, dao_header_data_t *data) {
  uint8_t buffer[HEADER_SIZE];
  uint64_t len = HEADER_SIZE;
  int ret = ckb_load_header(buffer, &len, 0, index, source);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len > HEADER_SIZE) {
    return ERROR_BUFFER_NOT_ENOUGH;
  }

  mol_seg_t header_seg;
  header_seg.ptr = (uint8_t *)buffer;
  header_seg.size = len;

  if (MolReader_Header_verify(&header_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  mol_seg_t raw_seg = MolReader_Header_get_raw(&header_seg);
  mol_seg_t dao_seg = MolReader_RawHeader_get_dao(&raw_seg);
  mol_seg_t epoch_seg = MolReader_RawHeader_get_epoch(&raw_seg);
  mol_seg_t block_number_seg = MolReader_RawHeader_get_number(&raw_seg);

  data->block_number = *((uint64_t *)block_number_seg.ptr);
  memcpy(data->dao, dao_seg.ptr, 32);
  return extract_epoch_info(*((uint64_t *)epoch_seg.ptr), 0,
                            &(data->epoch_number), &(data->epoch_index),
                            &(data->epoch_length));
}

int calculate_dao_input_capacity(uint64_t occupied_capacity,
                                 dao_header_data_t deposit_data,
                                 dao_header_data_t align_target_data,
                                 uint64_t deposited_block_number,
                                 uint64_t original_capacity,
                                 uint64_t *calculated_capacity) {
  /* deposited_block_number must match actual deposit block */
  if (deposited_block_number != deposit_data.block_number) {
    return ERROR_INVALID_WITHDRAW_BLOCK;
  }

  uint64_t deposit_accumulate_rate = *((uint64_t *)(&deposit_data.dao[8]));
  uint64_t withdraw_accumulate_rate =
      *((uint64_t *)(&align_target_data.dao[8]));
  uint64_t counted_capacity = 0;
  if (__builtin_usubl_overflow(original_capacity, occupied_capacity,
                               &counted_capacity)) {
    printf("original_capacity %ld occupied_capacity %ld", original_capacity,
           occupied_capacity);
    return ERROR_OVERFLOW;
  }

  __int128 withdraw_counted_capacity = ((__int128)counted_capacity) *
                                       ((__int128)withdraw_accumulate_rate) /
                                       ((__int128)deposit_accumulate_rate);

  uint64_t withdraw_capacity = 0;
  if (__builtin_uaddl_overflow(occupied_capacity,
                               (uint64_t)withdraw_counted_capacity,
                               &withdraw_capacity)) {
    printf("original_capacity %ld occupied_capacity %ld", original_capacity,
           (uint64_t)withdraw_counted_capacity);
    return ERROR_OVERFLOW;
  }

  *calculated_capacity = withdraw_capacity;
  return CKB_SUCCESS;
}
