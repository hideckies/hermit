#ifndef HERMIT_CONVERT_HPP
#define HERMIT_CONVERT_HPP

#include <windows.h>
#include <string>
#include <vector>
#include <iomanip>
#include <iostream>
#include <string>
#include <sstream>

// vector<char> -> string
std::string VecCharToString(std::vector<char> chars);
// wstring -> string (UTF8)
std::string UTF8Encode(const std::wstring &wstr);
// string (UTF8) -> wstring
std::wstring UTF8Decode(const std::string &str);

// LPSTR -> wchar_t*
wchar_t* ConvertLPSTRToWCHAR_T(LPSTR lpStr);

// LPCWSTR -> string
std::string ConvertLPCWSTRToString(LPCWSTR lpcwStr);

// string -> LPCWSTR
LPCWSTR ConvertStringToLPCWSTR(const std::string& text);

#endif // HERMIT_CONVERT_HPP