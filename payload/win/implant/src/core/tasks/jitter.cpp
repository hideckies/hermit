#include "core/task.hpp"

namespace Task
{
    std::wstring JitterSet(State::PSTATE pState, const std::wstring& wJitter)
    {
        INT nJitter = std::stoi(wJitter);
        pState->nJitter = nJitter;
        return L"Success: The jitter time has been updated.";
    }
}