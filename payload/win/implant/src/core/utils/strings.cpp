#include "core/utils.hpp"

namespace Strings
{
    SIZE_T StrLenA(LPCSTR str)
    {
        LPCSTR str2;

        if ( str == NULL )
            return 0;

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