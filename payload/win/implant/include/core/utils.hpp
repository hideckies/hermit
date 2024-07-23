#ifndef HERMIT_CORE_UTILS_HPP
#define HERMIT_CORE_UTILS_HPP

#include <windows.h>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <random>
#include <string>
#include <sstream>
#include <vector>

namespace Utils::Convert
{
    // BYTE* -> string
    std::string BytePointerToString(const BYTE* pByte);
    // vector<BYTE> -> string
    std::string VecByteToHexString(const std::vector<BYTE> bytes);

    // wstring -> string (UTF8)
    std::string UTF8Encode(const std::wstring& wstr);
    // string (UTF8) -> wstring
    std::wstring UTF8Decode(const std::string& str);

    // WORD (unsigned short) -> wstring
    std::wstring WORDToWstring(WORD wSrc);

    // wstring -> DWORD (unsigned long)
    DWORD WstringToDWORD(const std::wstring& wstr, int base);
    // DWORD (unsigned long) -> wstring
    std::wstring DWORDToWstring(DWORD dwSrc);

    // LPSTR -> PWCHAR
    PWCHAR LPSTRToPWCHAR(LPSTR lpStr);

    // IPv4(wstring) -> DWORD
    DWORD IPv4ToDWORD(const std::wstring& wIP);
}

namespace Utils::Random
{
    INT RandomINT();
    std::wstring RandomString(INT nLen);
    VOID RandomSleep(INT nSleep, INT nJitter);
}

namespace Utils::Split
{
    std::vector<std::wstring> Split(std::wstring text, wchar_t delimiter);
}

namespace Utils::Strings
{
    SIZE_T StrLenA(LPCSTR str);
    SIZE_T StrLenW(LPCWSTR str);
}

#endif // HERMIT_CORE_UTILS_HPP