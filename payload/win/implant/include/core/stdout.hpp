#ifndef HERMIT_CORE_STDOUT_HPP
#define HERMIT_CORE_STDOUT_HPP

#include "core/procs.hpp"
#include "core/utils.hpp"

#include <windows.h>

namespace Stdout
{
    std::wstring GetErrorMessage(DWORD dwErrorCode);
    INT DisplayMessageBoxA(LPCSTR text, LPCSTR caption);
    INT DisplayMessageBoxW(LPCWSTR text, LPCWSTR caption);
    INT DisplayErrorMessageBoxW(LPCWSTR caption);
}

#endif // HERMIT_CORE_STDOUT_HPP