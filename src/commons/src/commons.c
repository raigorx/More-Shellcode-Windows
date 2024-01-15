#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "../includes/commons.h"

generic_buffer generate_dynamic_array(size_t size, size_t elem_size) {
  void* const buffer = calloc(size, elem_size);
  if (buffer == NULL) {
    printf("Error allocating memory\n");
    exit(EXIT_FAILURE);
  }

  return (generic_buffer){.buffer = buffer, .size = size};
}

uc_buffer get_self_asm_bytes(const unsigned char* const begin_addr,
                             const unsigned char* const end_addr) {
  const size_t opcodes_raw_size = end_addr - begin_addr;

  generic_buffer tmp_buffer =
      generate_dynamic_array(opcodes_raw_size, sizeof(unsigned char));

  uc_buffer opcodes_raw = {.buffer = tmp_buffer.buffer,
                           .size = opcodes_raw_size};

  for (size_t i = 0; i < opcodes_raw.size; i++) {
    opcodes_raw.buffer[i] = begin_addr[i];
  }

  return opcodes_raw;
}

opcode_str_buffer asm_opcodes_to_string(uc_buffer opcodes_raw,
                                        bool use_prefix) {
  const char* const format = use_prefix ? "0x%02X," : "%02X";

  // Assuming maximum size of a formatted byte is 5 characters (e.g., "0xFF,") +
  // 1 space
  size_t opcodes_str_size =
      (opcodes_raw.size * 6) + 1;  // +1 for the null-terminator

  generic_buffer tmp_buffer =
      generate_dynamic_array(opcodes_str_size, sizeof(char));

  opcode_str_buffer opcodes_str = {.buffer = tmp_buffer.buffer,
                                   .size = opcodes_str_size};

  size_t offset = 0;
  size_t i;
  for (i = 0; i < opcodes_raw.size - 1; i++) {
    offset += sprintf_s(opcodes_str.buffer + offset, opcodes_str.size, format,
                        opcodes_raw.buffer[i]);
    offset += sprintf_s(opcodes_str.buffer + offset, opcodes_str_size, " ");
  }

  offset += sprintf_s(opcodes_str.buffer + offset, opcodes_str_size, format,
                      opcodes_raw.buffer[i]);
  opcodes_str.offset = offset;
  return opcodes_str;
}

void print_asm_opcodes(const unsigned char* const begin_addr,
                       const unsigned char* const end_addr) {
  uc_buffer opcodes_raw = get_self_asm_bytes(begin_addr, end_addr);
  opcode_str_buffer opcodes_str = asm_opcodes_to_string(opcodes_raw, false);
  opcodes_str.buffer[opcodes_str.offset] = '\0';

  printf("%s", opcodes_str.buffer);
  free(opcodes_raw.buffer);
  free(opcodes_str.buffer);
}

void print_result_msg(const unsigned char* const begin_addr,
                      const unsigned char* const end_addr) {
  printf("%s", "Self assembly bytes:\n");
  print_asm_opcodes(begin_addr, end_addr);
  printf("%s", "\nYou can copy/paste the opcode ");
  printf("%s", "bytes above in a online disassembler\n");
  printf("%s", "and compare it with godbolt compiler for better insight\n");
}