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

    // DWORD (unsigned long) -> wstring
    std::wstring DWORDToWstring(DWORD dwSrc);

    // LPSTR -> wchar_t*
    wchar_t* LPSTRToWCHAR_T(LPSTR lpStr);

    // String(PCHAR) -> Hash(DWORD)
    DWORD StrToHashA(PCHAR pChar);
}

#endif // HERMIT_CORE_UTILS_HPP