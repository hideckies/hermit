#include "core/utils.hpp"

namespace Utils
{
    INT MemCmp(const void* str1, const void* str2, SIZE_T n)
    {
        CONST UCHAR* s1 = (CONST UCHAR*)str1;
        CONST UCHAR* s2 = (CONST UCHAR*)str2;

        while (n--)
        {
            if (*s1 != *s2)
            {
                return *s1 - *s2;
            }
            s1++;
            s2++;
        }
        return 0;
    }

    // Reference:
    // https://github.com/HavocFramework/Havoc/blob/ea3646e055eb1612dcc956130fd632029dbf0b86/payloads/DllLdr/Source/Entry.c#L393
    SIZE_T StrLenA(LPCSTR str)
    {
        LPCSTR str2 = str;
        for (str2 = str; *str2; ++str2);
        return (str2 - str);
    }

    SIZE_T StrLenW(LPCWSTR str)
    {
        LPCWSTR str2;
        for (str2 = str; *str2; ++str2);
        return (str2 - str);
    }
}