#ifndef _WIN32
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>

#include "../../includes/os_tweaks.h"

void set_full_memory_permission(const void* memory_ptr, size_t size) {
  // Get the system's page size
  size_t pagesize = sysconf(_SC_PAGESIZE);

  // Calculate aligned starting address
  uintptr_t addr = (uintptr_t)memory_ptr;
  uintptr_t aligned_addr = addr & ~(pagesize - 1);

  // Calculate the number of bytes we need to cover from the aligned address to
  // the end of our region
  size_t diff = addr - aligned_addr;
  size_t len_to_protect = diff + size;

  if (mprotect((void*)aligned_addr, len_to_protect, PROT_READ | PROT_WRITE | PROT_EXEC) ==
      -1) {
    perror("mprotect");
  }
}
#endif