#ifndef HERMIT_CONVERT_HPP
#define HERMIT_CONVERT_HPP

#include <windows.h>
#include <string>
#include <iomanip>
#include <iostream>
#include <string>
#include <sstream>

// LPSTR -> wchar_t*
wchar_t* ConvertLPSTRToWCHAR_T(LPSTR lpStr);

// LPCWSTR -> string
std::string ConvertLPCWSTRToString(LPCWSTR lpcwStr);

// string -> LPCWSTR
LPCWSTR ConvertStringToLPCWSTR(const std::string& text);
// string -> wstring
std::wstring ConvertStringToWstring(const std::string& text);

// wstring -> string
std::string ConvertWstringToString(const std::wstring& wText);

#endif // HERMIT_CONVERT_HPP