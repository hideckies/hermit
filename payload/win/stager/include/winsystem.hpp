#ifndef HERMIT_WINSYSTEM_HPP
#define HERMIT_WINSYSTEM_HPP

#include <windows.h>
#include <string>
#include <tlhelp32.h>
#include "common.hpp"
#include "convert.hpp"
#include "macros.hpp"

std::wstring GetEnvStrings(const std::wstring& envVar);
std::wstring GetArch(WORD wProcessorArchitecture);
std::wstring GetInitialInfo(); // Get system information as json for sending it to the server.
DWORD GetProcessIdByName(LPCWSTR lpProcessName);

std::wstring ExecuteCmd(const std::wstring& cmd);
BOOL ExecuteFile(const std::wstring& filePath);

#endif // HERMIT_WININFO_HPP