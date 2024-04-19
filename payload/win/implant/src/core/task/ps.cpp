#include "core/task.hpp"

namespace Task
{
    std::wstring PsKill(Procs::PPROCS pProcs, const std::wstring& wPid)
    {
        DWORD dwPid = Utils::Convert::WstringToDWORD(wPid, 10);

        HANDLE hProcess = System::Process::ProcessOpen(
            pProcs,
            dwPid,
            PROCESS_TERMINATE
        );
        if (!hProcess)
        {
            return L"Error: Could not open the process.";
        }

        if (!System::Process::ProcessTerminate(pProcs, hProcess, EXIT_SUCCESS))
        {
            pProcs->lpNtClose(hProcess);
            return L"Error: Could not terminte the process.";
        }

        pProcs->lpNtClose(hProcess);

        return L"Success: Process has been terminated.";
    }

    std::wstring PsLs(Procs::PPROCS pProcs)
    {
        HANDLE hSnapshot;
        PROCESSENTRY32W pe32;

        DWORD dwCurrentPid = GetCurrentProcessId();

        hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE)
        {
            return L"Error: Could not create snapshot.";
        }

        pe32.dwSize = sizeof(PROCESSENTRY32W);
        
        if (!Process32FirstW(hSnapshot, &pe32))
        {
            CloseHandle(hSnapshot);
            // Procs::Call::HCloseHandle(pProcs, hSnapshot);
            return L"Error: Could not get the first process.";
        }

        std::wstring wProcesses = L"";

        do {
            DWORD dwPid = pe32.th32ProcessID;
            std::wstring wPid = Utils::Convert::DWORDToWstring(dwPid);
            std::wstring wProcessName(pe32.szExeFile);

            // If the pid is current pid, prepend asterisk (*) to the line.
            std::wstring wPrefix = L" ";
            if (dwPid == dwCurrentPid)
            {
                wPrefix = L"*";
            }

            wProcesses += wPrefix + wPid + L"\t" + wProcessName + L"\n";
        } while (Process32NextW(hSnapshot, &pe32));

        CloseHandle(hSnapshot);
        // Procs::Call::HCloseHandle(pProcs, hSnapshot);

        if (wcscmp(wProcesses.c_str(), L"") == 0)
        {
            return L"Error: Processes not found.";
        }

        // Finally, preprend the header in the output.
        std::wstring wHeader = L"PID\tName\n";
        std::wstring wHeaderBar = L"---\t----\n";

        return wHeader + wHeaderBar + wProcesses;
    }
}