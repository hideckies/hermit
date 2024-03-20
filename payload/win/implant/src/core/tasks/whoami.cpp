#include "core/task.hpp"

namespace Task
{
    std::wstring Whoami()
    {
        std::wstring result;

        WCHAR wInfoBuf[INFO_BUFFER_SIZE] = {'\0'};
        DWORD dwBufCharCount = INFO_BUFFER_SIZE;

        if (!GetComputerNameW(wInfoBuf, &dwBufCharCount))
        {
            return L"Error: Could not get the computer name.";
        }

        result += std::wstring(wInfoBuf);
        dwBufCharCount = INFO_BUFFER_SIZE;
        
        if (!GetUserNameW(wInfoBuf, &dwBufCharCount))
        {
            return L"Error: Could not get the username.";
        }

        result += std::wstring(L"\\");
        result += std::wstring(wInfoBuf);

        return result;
    }

    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserexw
    std::wstring WhoamiPriv()
    {
        return L"test.";
    }
}