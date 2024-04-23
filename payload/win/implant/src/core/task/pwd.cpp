#include "core/task.hpp"

namespace Task
{
    std::wstring Pwd(State::PSTATE pState)
    {
        WCHAR wBuffer[MAX_PATH];        
        ULONG dwRet = pState->pProcs->lpRtlGetCurrentDirectory_U(
            MAX_PATH,
            wBuffer
        );
        if (dwRet == 0 || dwRet > MAX_PATH)
        {
            return L"Error: Failed to get current directory.";
        }
        
        return std::wstring(wBuffer);
    }
}