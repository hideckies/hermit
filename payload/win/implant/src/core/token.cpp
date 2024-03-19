#include "token.hpp"

std::wstring EnumerateTokens()
{
    HANDLE hObj = NULL;
    PVOID pProcessInfo = NULL;
    PVOID pObjInfo = NULL;
    ULONG ulLength = 0;
    NTSTATUS ntStatus;

    if (!NT_SUCCESS(NtQuerySystemInformation(SystemProcessInformation, pProcessInfo, 0, &ulLength)))
    {
        return L"Error: Could not query system process information";
    }

    // ntStatus = NtQueryObject(hObj, objInfoClass, pObjInfo, 0, &ulLength);
    // if (ntStatus != NT_SUCCESS)
    // {
    //     return L"Error: Could not query object information.";
    // }

    // if (!GetTokenInformation(token, TokenUser, TokenUserInfo, BUF_SIZE, &tokenLen))
    // {
    //     return L"Error: Could not get token information.";
    // }

    // Information for impersonate
    // if (!GetTokenInformation(token, TokenImpersonationLevel, TokenImpersonationInfo, BUF_SIZE, &tokenLen))
    // {
    //     return L"Error: Could not get token information.";
    // }


    // if (!LookupAccountSidW(
    //     NULL,
    //     ((TOKEN_USER*)TokenUserInfo)->User.Sid,
    //     username,
    //     &usernameLen,
    //     domainName,
    //     &domainNameLen,
    //     (PSID_NAME_USE)&sidType
    // )) {
    //     return L"Error: Could not lookup account SID";
    // }

    // ImpersonateLoggedOnUser(token_list[i].token);

    // // Create primary token
    // if (!DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, impersonation_level, TokenPrimary, &primary_token))

    // CreateProcessAsUserW();

    return L"Warning: The task has not been implemented yet.";
}