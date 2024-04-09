#ifndef HERMIT_CORE_UTILS_HPP
#define HERMIT_CORE_UTILS_HPP

#include <windows.h>
#include <string>
#include <vector>

namespace Utils::Convert
{
    // vector<BYTE> -> string
    std::string VecByteToString(std::vector<BYTE> bytes);
    // vector<char> -> string
    std::string VecCharToString(std::vector<char> chars);

    // wstring -> string (UTF8)
    std::string UTF8Encode(const std::wstring& wstr);
    // string (UTF8) -> wstring
    std::wstring UTF8Decode(const std::string& str);

    // wstring -> DWORD (unsigned long)
    DWORD WstringToDWORD(const std::wstring& wstr, int base);
    // DWORD (unsigned long) -> wstring
    std::wstring DWORDToWstring(DWORD dwSrc);

    // LPCWSTR -> string
    std::string LPCWSTRToString(LPCWSTR lpcwStr);
}

#endif // HERMIT_CORE_UTILS_HPP