#include "core/task.hpp"

namespace Task
{
    std::wstring GroupLs(State::PSTATE pState)
    {
        std::wstring result = L"";

        std::vector<std::wstring> groups = System::Group::AllGroupsGet(pState->pProcs);
        if (groups.size() == 0)
        {
            return L"Error: Groups not found.";
        }

        for (const std::wstring& group : groups)
        {
            result += group + L"\n";
        }

        return result;
    }
}