#ifndef HERMIT_CORE_UTILS_HPP
#define HERMIT_CORE_UTILS_HPP

#include <windows.h>
#include <string>

namespace Utils::Convert
{
    // wstring -> string (UTF8)
    std::string UTF8Encode(const std::wstring& wstr);
    // string (UTF8) -> wstring
    std::wstring UTF8Decode(const std::string& str);

    // LPSTR -> wchar_t*
    wchar_t* LPSTRToWCHAR_T(LPSTR lpStr);
}

#endif // HERMIT_CORE_UTILS_HPP