#include <cstdlib>
#include <cstring>
#include <vector>

#include "../../commons/includes/commons.h"
#include "../../commons/includes/compiler.h"
#include "../../commons/includes/os_tweaks.h"

int main() {
  using std::vector;

  auto begin_addr = static_cast<unsigned char*>(get_address_after_call());

  /*
    KERNEL32 ascii code for reference:
    32 33 4c 45 4e 52 45 4B

    Hello ascii code for reference:
    48 65 6C 6C 6F

    CLANG 16 always use relative position or pointer to access array
    of characters for non literal and literals

    MSVC 19 use relative position or pointer to access array
    of characters but use hardcode mov bytes for non_literal

    GCC 13 with -O0 "KERNEL32" is hardcode in one mov instruction
    movabs rax,0x32334c454e52454b

    however "Hello" is hardcode in two movs
    mov    DWORD PTR [rbp-0x27],0x6c6c6548
    mov    WORD PTR [rbp-0x23],0x6f

    the number of mov instructions generate by GCC 13 seems to depends
    on the size of the string

    if the string in non literal arrays are duplicate, GCC 13 will
    use the address of the first string to access the second string
    but if its not duplicated non_literal arrays will be hardcode

    pointer to string always have a relative position or pointer
    in all three compilers GCC/MSVC/CLANG
  */
  unsigned char one_mov[] = "KERNEL32";
  const unsigned char two_mov[] = "Hello";
  const unsigned char str_duplicate[] = {'K', 'E', 'R', 'N', 'E',
                                         'L', '3', '2', '\0'};
  const unsigned char non_literal[] = {'L', 'i', 't', 'e', 'r', 'a', 'l', '\0'};
  // literal string must be const in C++
  const char* pointer_str = "Ptr Hello";

  one_mov[0] = 'A';
  /*
    a pointer to string literal don't tell the compiler where to store the
    string literal just pointer to this string literal, so the place where the
    string literal is stored is implementation dependent which can be in a read
    only memory leading to a exception

    however if the memory permissions are set to write the exception will not
    throw
  */

  set_full_memory_permission(static_cast<const void*>(pointer_str),
                              strlen(pointer_str));

  const_cast<char*>(pointer_str)[0] = 'B';

  auto end_addr = static_cast<unsigned char*>(get_address_after_call());

  constexpr int instructions_before_return = 5;
  end_addr -= instructions_before_return;

  print_result_msg(begin_addr, end_addr);

  return EXIT_SUCCESS;
}
