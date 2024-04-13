#ifndef HERMIT_CORE_UTILS_HPP
#define HERMIT_CORE_UTILS_HPP

#include <windows.h>
#include <ctime>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>

namespace Utils::Convert
{
    // BYTE* -> string
    std::string BytePointerToString(const BYTE* pByte);

    // wstring -> string (UTF8)
    std::string UTF8Encode(const std::wstring& wstr);
    // string (UTF8) -> wstring
    std::wstring UTF8Decode(const std::string& str);

    // wstring -> DWORD (unsigned long)
    DWORD WstringToDWORD(const std::wstring& wstr, int base);
    // DWORD (unsigned long) -> wstring
    std::wstring DWORDToWstring(DWORD dwSrc);

    // LPSTR -> wchar_t*
    wchar_t* LPSTRToWCHAR_T(LPSTR lpStr);

    // IPv4(wstring) -> DWORD
    DWORD IPv4ToDWORD(const std::wstring& wIP);
}

namespace Utils::Random
{
    INT RandomINT();
    VOID RandomSleep(INT nSleep, INT nJitter);
}

namespace Utils::Split
{
    std::vector<std::wstring> Split(std::wstring text, wchar_t delimiter);
}

#endif // HERMIT_CORE_UTILS_HPP