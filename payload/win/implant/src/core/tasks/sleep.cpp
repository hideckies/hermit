#include "core/task.hpp"

namespace Task
{
    std::wstring Sleep(const std::wstring& wSleepTime, INT &nSleep)
    {
        INT newSleepTime = std::stoi(wSleepTime);
        nSleep = newSleepTime;
        return L"Success: The sleep time has been updated.";
    }
}