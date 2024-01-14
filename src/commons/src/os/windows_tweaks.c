#ifdef _WIN32
#include <windows.h>
#include <stdio.h>

#include "../../includes/os_tweaks.h"

void debug_info() {
  const LPCVOID no_source = NULL;

  const DWORD error_code = GetLastError();

  const DWORD default_language = 0;

  LPTSTR error_msg_buffer;

  const DWORD min_error_msg_buffer_size = 0;

  va_list* const no_arguments = NULL;

  FormatMessage(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
          FORMAT_MESSAGE_IGNORE_INSERTS,
      no_source, error_code, default_language,
      (LPTSTR)&error_msg_buffer,  //  it expect LPTSTR* casted to LPTSTR
      min_error_msg_buffer_size, no_arguments);

  if (!error_msg_buffer) {
    wprintf(L"Format message failed error code: %lu\n", error_code);
    exit(EXIT_FAILURE);
  }

  wprintf(L"Error code %ul\n", error_code);
  wprintf(L" and error message: %s\n", *error_msg_buffer);
}

void set_full_memory_permission(const void* memory_ptr, size_t size) {
  DWORD old_protection;
  BOOL vp_result =
      VirtualProtect(memory_ptr, size, PAGE_EXECUTE_READWRITE, &old_protection);
  if (vp_result == 0) {
    wprintf(L"VirtualProtect failed\n");
    debug_info();
    exit(EXIT_FAILURE);
  }
}

#endif