#ifndef HERMIT_CORE_STDOUT_HPP
#define HERMIT_CORE_STDOUT_HPP

#include <windows.h>

namespace Stdout
{
    INT DisplayMessageBoxA(LPCSTR text, LPCSTR caption);
    INT DisplayMessageBoxW(LPCWSTR text, LPCWSTR caption);
    INT DisplayErrorMessageBoxW(LPCWSTR caption);
}


#endif // HERMIT_CORE_STDOUT_HPP