#include "core/task.hpp"

namespace Task
{
    std::wstring KillDateSet(State::PSTATE pState, const std::wstring& wKillDate)
    {
        INT nKillDate = std::stoi(wKillDate);
        pState->nKillDate = nKillDate;
        return L"Success: The killdate has been updated.";
    }
}
