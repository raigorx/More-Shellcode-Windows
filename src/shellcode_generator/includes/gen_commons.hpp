#pragma once
#include <string>
#include <vector>

#include <windows.h>

using WinExec_t = UINT(WINAPI*)(LPCSTR lpCmdLine, UINT uCmdShow);

extern "C" {
INT mem_cmp(CONST VOID* str1, CONST VOID* str2, SIZE_T n);
HANDLE LocalGetModuleHandle(CONST CHAR* sModuleName);
PVOID LocalGetProcAddress(HANDLE pBase, CONST CHAR* sFuncName);
}

std::string get_asm_opcodes_str(unsigned char* const begin_addr,
                                unsigned char* const end_addr);