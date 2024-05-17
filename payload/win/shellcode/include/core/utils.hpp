#ifndef HERMIT_UTILS_HPP
#define HERMIT_UTILS_HPP

#include <windows.h>

namespace Utils
{
    INT MemCmp(const void* str1, const void* str2, SIZE_T n);
    SIZE_T StrLenA(LPCSTR str);
    SIZE_T StrLenW(LPCWSTR str);

}

#endif // HERMIT_UTILS_HPP