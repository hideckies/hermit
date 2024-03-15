#ifndef HERMIT_CONVERT_HPP
#define HERMIT_CONVERT_HPP

#include <windows.h>
#include <string>
#include <vector>

// vector<char> -> string
std::string VecCharToString(std::vector<char> chars);
// wstring -> string (UTF8)
std::string UTF8Encode(const std::wstring& wstr);
// string (UTF8) -> wstring
std::wstring UTF8Decode(const std::string& str);

// LPCWSTR -> string
std::string ConvertLPCWSTRToString(LPCWSTR lpcwStr);

#endif // HERMIT_CONVERT_HPP