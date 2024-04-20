#include "core/technique.hpp"

namespace Technique::Injection
{
    BOOL DllInjection(
        Procs::PPROCS   pProcs,
        DWORD           dwPID,
        LPVOID          lpDllPath,
        DWORD           dwDllPathSize
    ) {
        HANDLE hProcess;
        HANDLE hThread;
        PVOID pBaseAddr;

        hProcess = System::Process::ProcessOpen(
            pProcs,
            dwPID,
            PROCESS_ALL_ACCESS
        );
        if (!hProcess)
        {
            return FALSE;
        }

        pBaseAddr = System::Process::VirtualMemoryAllocate(
            pProcs,
            hProcess,
            dwDllPathSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
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
            lpDllPath,
            dwDllPathSize,
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

        PTHREAD_START_ROUTINE threadStartRoutineAddr = (PTHREAD_START_ROUTINE)GetProcAddress(
            GetModuleHandle(TEXT("kernel32")),
            "LoadLibraryW"
        );
        if (!threadStartRoutineAddr)
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

        hThread = System::Process::RemoteThreadCreate(
            pProcs,
            hProcess,
            threadStartRoutineAddr,
            pBaseAddr
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