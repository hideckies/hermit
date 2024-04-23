#include "core/task.hpp"

namespace Task
{
    std::wstring GroupLs()
    {
        std::wstring result = L"";

        std::vector<std::wstring> groups = System::Group::AllGroupsGet();
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