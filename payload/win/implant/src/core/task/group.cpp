#include "core/task.hpp"

namespace Task
{
    std::wstring GroupAdd(State::PSTATE pState, const std::wstring& wName)
    {
        std::wstring result = L"";

        LOCALGROUP_INFO_1 gi;
        gi.lgrpi1_name = const_cast<LPWSTR>(wName.c_str());
        gi.lgrpi1_comment = nullptr;

        DWORD dwLevel = 1;
        DWORD dwError = 0;

        NET_API_STATUS status = NetLocalGroupAdd(
            nullptr,
            dwLevel,
            (LPBYTE)&gi,
            &dwError
        );
        if (status == NERR_Success)
        {
            result = L"Success: Group \"" + wName + L"\" has been added successfully.";
        }
        else if (status == ERROR_ACCESS_DENIED)
        {
            result = L"Error: Access Denied";
        }
        else
        {
            result = L"Error: Failed to create a group.";
        }

        return result;
    }

    std::wstring GroupAddUser(State::PSTATE pState, const std::wstring& wGroupname, const std::wstring&wUsername)
    {
        std::wstring result = L"";

        LOCALGROUP_MEMBERS_INFO_3 gi;
        gi.lgrmi3_domainandname = const_cast<LPWSTR>(wUsername.c_str());

        DWORD dwLevel = 3;
        DWORD dwTotalEntries = 1;

        NET_API_STATUS status = NetLocalGroupAddMembers(
            nullptr,
            wGroupname.c_str(),
            dwLevel,
            (LPBYTE)&gi,
            dwTotalEntries
        );
        if (status == NERR_Success)
        {
            result = L"Success: User \"" + wUsername + L"\" has been added to the group \"" + wGroupname + L"\" successfully.";
        }
        else if (status == ERROR_ACCESS_DENIED)
        {
            result = L"Error: Access Denied";
        }
        else
        {
            result = L"Error: Failed to add user to group.";
        }

        return result;
    }

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

    std::wstring GroupRm(State::PSTATE pState, const std::wstring& wName)
    {
        std::wstring result = L"";

        NET_API_STATUS status = NetLocalGroupDel(
            nullptr,
            wName.c_str()
        );
        if (status == NERR_Success)
        {
            result = L"Success: Group \"" + wName + L"\" has been deleted successfully.";
        }
        else if (status == ERROR_ACCESS_DENIED)
        {
            result = L"Error: Access Denied";
        }
        else
        {
            result = L"Error: Failed to delete group.";
        }

        return result;
    }

    std::wstring GroupRmUser(State::PSTATE pState, const std::wstring& wGroupname, const std::wstring&wUsername)
    {
        std::wstring result = L"";

        LOCALGROUP_MEMBERS_INFO_3 gi;
        gi.lgrmi3_domainandname = const_cast<LPWSTR>(wUsername.c_str());

        DWORD dwLevel = 3;
        DWORD dwTotalEntries = 1;

        NET_API_STATUS status = NetLocalGroupDelMembers(
            nullptr,
            wGroupname.c_str(),
            dwLevel,
            (LPBYTE)&gi,
            dwTotalEntries
        );
        if (status == NERR_Success)
        {
            result = L"Success: User \"" + wUsername + L"\" has been deleted from the group \"" + wGroupname + L"\" successfully.";
        }
        else if (status == ERROR_ACCESS_DENIED)
        {
            result = L"Error: Access Denied";
        }
        else
        {
            result = L"Error: Failed to delete user from group.";
        }

        return result;
    }

    std::wstring GroupUsers(State::PSTATE pState, const std::wstring& wGroupname)
    {
        std::wstring result = L"";

        LPLOCALGROUP_MEMBERS_INFO_3 pBuf = nullptr;
        DWORD dwEntriesRead = 0;
        DWORD dwTotalEntries = 0;

        NET_API_STATUS status = NetLocalGroupGetMembers(
            nullptr,
            wGroupname.c_str(),
            3,
            (LPBYTE*)&pBuf,
            MAX_PREFERRED_LENGTH,
            &dwEntriesRead,
            &dwTotalEntries,
            nullptr
        );
        if (status == NERR_Success)
        {
            for (DWORD i = 0; i < dwEntriesRead; i++)
            {
                result += std::wstring(pBuf[i].lgrmi3_domainandname) + L"\n";
            }
        }
        else if (status == ERROR_ACCESS_DENIED)
        {
            result = L"Error: Access Denied";
        }
        else
        {
            result = L"Error: Failed to delete user from group.";
        }

        return result;
    }
}