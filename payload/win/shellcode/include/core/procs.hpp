#ifndef HERMIT_PROCS_HPP
#define HERMIT_PROCS_HPP

#include "core/utils.hpp"

#include <windows.h>

// WINAPI
typedef HMODULE (WINAPI* LPPROC_LOADLIBRARYA)(LPCSTR lpLibFileName);
typedef FARPROC (WINAPI* LPPROC_GETPROCADDRESS)(HMODULE hModule, LPCSTR lpProcName);
typedef int     (WINAPI* LPPROC_MESSAGEBOXA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
typedef int     (WINAPI* LPPROC_MESSAGEBOXW)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);
typedef LPVOID  (WINAPI* LPPROC_VIRTUALALLOC)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL    (WINAPI* LPPROC_VIRTUALPROTECT)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef UINT    (WINAPI* LPPROC_WINEXEC)(LPCSTR lpCmdLine, UINT uCmdShow);

namespace Procs
{
    PVOID GetProcAddressByName(HANDLE hBase, CONST CHAR* sFuncName, SIZE_T dwFuncNameLen);
}


#endif // HERMIT_PROCS_HPP