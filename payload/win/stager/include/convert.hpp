#ifndef HERMIT_CONVERT_HPP
#define HERMIT_CONVERT_HPP

#include <windows.h>
#include <string>

// LPCWSTR -> string
std::string ConvertLPCWSTRToString(LPCWSTR lpcwStr);

// string -> wstring
std::wstring ConvertStringToWstring(const std::string& text);

// wstring -> string
std::string ConvertWstringToString(const std::wstring& wText);

#endif // HERMIT_CONVERT_HPP