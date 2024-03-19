#ifndef HERMIT_REGISTRY_HPP
#define HERMIT_REGISTRY_HPP

#include <windows.h>
#include <winreg.h>
#include <string>
#include <vector>
#include "common.hpp"
#include "convert.hpp"
#include "macros.hpp"

HKEY GetRegRootKey(const std::wstring& wRootKey);
std::vector<std::wstring> ListRegSubKeys(
    HKEY hRootKey,
    const std::wstring& wSubKey,
    DWORD dwOptions,
    BOOL bRecurse
);
std::wstring GetRegSubKeys(
    const std::wstring& wRootKey,
    const std::wstring& wSubKey,
    BOOL bRecurse
);
std::wstring GetRegValues(
    const std::wstring& wRootKey,
    const std::wstring& wSubKey,
    BOOL bRecurse
);

#endif // HERMIT_REGISTRY_HPP