#include "core/task.hpp"

namespace Task
{
    std::wstring Pwd()
    {
        WCHAR wBuffer[MAX_PATH];
        DWORD dwRet;

        dwRet = GetCurrentDirectoryW(MAX_PATH, wBuffer);
        if (dwRet == 0 || dwRet > MAX_PATH)
        {
            return L"Error: Could not get current directory.";
        }
        
        return std::wstring(wBuffer);
    }
}