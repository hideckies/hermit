#include "core/task.hpp"

namespace Task
{
    std::wstring Users(State::PSTATE pState)
    {
        std::wstring result = L"";

        std::vector<std::wstring> users = System::User::AllUsersGet();
        if (users.size() == 0)
        {
            return L"Error: Users not found.";
        }

        for (const std::wstring& user : users)
        {
            result += user + L"\n";
        }

        return result;
    }
}