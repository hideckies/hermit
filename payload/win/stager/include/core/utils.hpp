#ifndef HERMIT_CORE_UTILS_HPP
#define HERMIT_CORE_UTILS_HPP

#include <windows.h>
#include <string>
#include <vector>

namespace Utils::Convert
{
    // vector<char> -> string
    std::string VecCharToString(std::vector<char> chars);
    // wstring -> string (UTF8)
    std::string UTF8Encode(const std::wstring& wstr);
    // string (UTF8) -> wstring
    std::wstring UTF8Decode(const std::string& str);

    // LPCWSTR -> string
    std::string LPCWSTRToString(LPCWSTR lpcwStr);
}

#endif // HERMIT_CORE_UTILS_HPP