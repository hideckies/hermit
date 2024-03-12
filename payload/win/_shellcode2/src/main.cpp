// Reference:
// https://www.ired.team/offensive-security/code-injection-process-injection\/writing-and-compiling-shellcode-in-c#id-2.-generating-assembly-listing
#include <windows.h>
#include "peb.hpp"

#pragma code_seg(".text")

__declspec(allocate(".text"))
wchar_t kernel32Str[] = L"kernel32.dll";

__declspec(allocate(".text"))
char loadLibStr[] = "LoadLibraryA";

int main()
{
    // Stack based strings for libraries and functions the shellcode needs
    wchar_t nameKernel32Dll[]   = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0 };
    char nameLoadLibraryA[]     = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
    char nameGetProcAddress[]   = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s', 0 };
    char nameUser32Dll[]        = { 'u','s','e','r','3','2','.','d','l','l', 0 };
    char nameMessageBoxW[]      = { 'M','e','s','s','a','g','e','B','o','x','W', 0 };

    // stack based strings to be passed to the messagebox win api
    wchar_t msgContent[]    = { 'H','e','l','l','o', ' ', 'W','o','r','l','d','!', 0 };
    wchar_t msgTitle[]      = { 'D','e','m','o','!', 0 };

    // resolve kernel32 image base
    LPVOID base = GetModuleByName((const LPWSTR)nameKernel32Dll);
    if (!base) {
        return 1;
    }

    // resolve loadlibraryA() address
    LPVOID loadLib = GetFuncByName((HMODULE)base, (LPSTR)nameLoadLibraryA);
    if (!loadLib) {
        return 2;
    }

    // resolve getprocaddress() address
    LPVOID getProc = GetFuncByName((HMODULE)base, (LPSTR)nameGetProcAddress);
    if (!getProc) {
        return 3;
    }

    // loadlibrarya and getprocaddress function definitions
    HMODULE(WINAPI * _LoadLibraryA)(LPCSTR lpLibFileName) = (HMODULE(WINAPI*)(LPCSTR))loadLib;
    FARPROC(WINAPI * _GetProcAddress)(HMODULE hModule, LPCSTR lpProcName)
        = (FARPROC(WINAPI*)(HMODULE, LPCSTR)) getProc;

    // load user32.dll
    LPVOID u32Dll = _LoadLibraryA(nameUser32Dll);

    // messageboxw function definition
    int (WINAPI * _MessageBoxW)(
        _In_opt_ HWND hWnd,
        _In_opt_ LPCWSTR lpText,
        _In_opt_ LPCWSTR lpCaption,
        _In_ UINT uType) = (int (WINAPI*)(
            _In_opt_ HWND,
            _In_opt_ LPCWSTR,
            _In_opt_ LPCWSTR,
            _In_ UINT)) _GetProcAddress((HMODULE)u32Dll, nameMessageBoxW);

    if (_MessageBoxW == NULL) return 4;

    // invoke the message box winapi
    _MessageBoxW(0, msgContent, msgTitle, MB_OK);

    return 0;
}