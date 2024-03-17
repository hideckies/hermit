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
std::string UTF8Encode(const std::wstring& wstr);
// string (UTF8) -> wstring
std::wstring UTF8Decode(const std::string& str);

// wstring -> DWORD (unsigned long)
DWORD ConvertWstringToDWORD(const std::wstring& wstr, int base);
// DWORD (unsigned long) -> wstring
std::wstring ConvertDWORDToWstring(DWORD dwSrc);

// LPSTR -> wchar_t*
wchar_t* ConvertLPSTRToWCHAR_T(LPSTR lpStr);

#endif // HERMIT_CONVERT_HPP