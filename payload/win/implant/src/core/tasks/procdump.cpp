#include "core/task.hpp"

namespace Task
{
    std::wstring Procdump(const std::wstring& wPid)
    {
         DWORD dwPid = Utils::Convert::WstringToDWORD(wPid, 10);
        // std::wstring wDumpFilePath = L"tmp.dmp";
        std::wstring wDumpFilePath = System::Env::GetStrings(L"%TEMP%") + L"\\tmp.dmp";

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
            return L"Error: Could not dump the process.";
        }

        CloseHandle(hFile);
        CloseHandle(hProcess);

        return wDumpFilePath.c_str();
    }
}