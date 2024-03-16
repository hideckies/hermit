#ifndef HERMIT_WINSYSTEM_HPP
#define HERMIT_WINSYSTEM_HPP

#include <windows.h>
#include <string>
#include "common.hpp"
#include "convert.hpp"
#include "types.hpp"

std::wstring GetArch(WORD wProcessorArchitecture);
std::wstring GetInitialInfo();

std::wstring ExecuteCmd(const std::wstring& cmd);
BOOL ExecuteFile(const std::wstring& filePath);

BOOL CheckPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege);
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);

#endif // HERMIT_WINSYSTEM_HPP