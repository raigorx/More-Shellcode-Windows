#include <vector>
#include <string>

#include "../includes/gen_commons.hpp"
#include "../../commons/includes/commons.h"

std::string get_asm_opcodes_str(unsigned char* const begin_addr,
                                unsigned char* const end_addr) {
  using std::string, std::vector;

  uc_buffer opcodes_raw = get_self_asm_bytes(begin_addr, end_addr);

  string opcodes_str = asm_opcodes_to_string(opcodes_raw, true).buffer;
  free(opcodes_raw.buffer);
  return opcodes_str;
}
