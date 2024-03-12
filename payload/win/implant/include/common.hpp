#ifndef HERMIT_COMMON_HPP
#define HERMIT_COMMON_HPP

#include <windows.h>

#define DLLEXPORT __declspec(dllexport)

#define sleep(n) Sleep(n * 1000)

INT DisplayMessageBoxA(LPCSTR text, LPCSTR caption);
INT DisplayMessageBoxW(LPCWSTR text, LPCWSTR caption);
INT DisplayErrorMessageBoxW(LPCWSTR caption);

#endif // HERMIT_COMMON_HPP