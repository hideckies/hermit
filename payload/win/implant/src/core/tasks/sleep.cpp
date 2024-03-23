#include "core/task.hpp"

namespace Task
{
    std::wstring Sleep(State::StateManager& sm, const std::wstring& wSleepTime)
    {
        INT newSleepTime = std::stoi(wSleepTime);
        sm.SetSleep(newSleepTime);
        return L"Success: The sleep time has been updated.";
    }
}