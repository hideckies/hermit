#include "core/task.hpp"

namespace Task
{
    std::wstring Sleep(State::PState pState, const std::wstring& wSleep)
    {
        INT nSleep = std::stoi(wSleep);
        pState->nSleep = nSleep;
        return L"Success: The sleep time has been updated.";
    }
}