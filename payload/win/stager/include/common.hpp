#ifndef HERMIT_COMMON_HPP
#define HERMIT_COMMON_HPP

#include <windows.h>
#include "macros.hpp"

INT DisplayMessageBoxA(LPCSTR text, LPCSTR caption);
INT DisplayMessageBoxW(LPCWSTR text, LPCWSTR caption);
INT DisplayErrorMessageBoxW(LPCWSTR caption);

#endif // HERMIT_COMMON_HPP