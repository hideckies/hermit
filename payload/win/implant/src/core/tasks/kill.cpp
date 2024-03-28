#include "core/task.hpp"

namespace Task
{
    std::wstring Kill(State::PState pState)
    {
        pState->bQuit = TRUE;
        return L"Success: Exit after completing remaining processes.";
    }
}