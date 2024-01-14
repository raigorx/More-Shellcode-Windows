#include <windows.h>

#include <memory>
#include <iostream>

#include "../../includes/os_tweaks.h"

void debug_info() {
  using std::unique_ptr;
  using std::wcout, std::endl;

  constexpr LPCVOID noSource = nullptr;

  const DWORD errorCode = GetLastError();

  constexpr DWORD defaultLanguage = 0;

  const unique_ptr<LPTSTR, decltype(&LocalFree)> errorMsgBuffer{
      static_cast<LPTSTR *>(LocalAlloc(LPTR, sizeof(TCHAR))), &LocalFree};

  constexpr DWORD minErrorMsgBufferSize = 0;

  constexpr va_list *noArguments = nullptr;

  FormatMessage(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
          FORMAT_MESSAGE_IGNORE_INSERTS,
      noSource, errorCode, defaultLanguage,
      static_cast<LPWSTR>(static_cast<void *>(
          errorMsgBuffer.get())),  //  it expect LPTSTR* casted to LPTSTR
      minErrorMsgBufferSize, noArguments);

  if (!errorMsgBuffer) {
    wcout << "Format message failed error code: " + errorCode << endl;
    exit(EXIT_FAILURE);
  }

  wcout << "Error code " << errorCode;
  wcout << " and error message: " << *errorMsgBuffer << endl;
}

void set_full_memory_permission(const void *memory_ptr, size_t size) {
  using std::unique_ptr, std::make_unique;
  using std::wcout, std::endl;

  //  As far as I know in older windows version like win7 you can
  //  execute directly the shellcode without the needs of change memory
  //  permissions.
  //  VirtualProtect requires that oldProtect points to valid memory so nullptr
  //  or 0 doesn't work. new DWORD can do the trick too but this last one
  //  requires to free the memory or it leaks.
  const unique_ptr<DWORD> oldProtect{make_unique<DWORD>()};
  BOOL vp_result = VirtualProtect((LPVOID)memory_ptr, size,
                                  PAGE_EXECUTE_READWRITE, oldProtect.get());
  if (vp_result == 0) {
    wcout << L"VirtualProtect failed" << endl;
    debug_info();
    exit(EXIT_FAILURE);
  }
}