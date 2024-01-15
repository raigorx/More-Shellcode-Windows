#pragma once
#include <stdbool.h>
#include <stdlib.h>

typedef struct {
  unsigned char* const buffer;
  size_t size;
} uc_buffer;

typedef struct {
  char* const buffer;
  size_t size;
  size_t offset;
} opcode_str_buffer;

typedef struct {
  void* const buffer;
  size_t size;
} generic_buffer;

void debug_info();

#ifdef __cplusplus
extern "C" {
#endif

generic_buffer generate_dynamic_array(size_t size, size_t elem_size);

uc_buffer get_self_asm_bytes(const unsigned char* const begin_addr,
                             const unsigned char* const end_addr);

opcode_str_buffer asm_opcodes_to_string(uc_buffer opcodes_raw, bool use_prefix);

void print_asm_opcodes(const unsigned char* const begin_addr,
                       const unsigned char* const end_addr);

void print_result_msg(const unsigned char* const begin_addr,
                      const unsigned char* const end_addr);

#ifdef __cplusplus
}
#endif