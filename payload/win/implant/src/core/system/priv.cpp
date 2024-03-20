#include "core/system.hpp"

namespace System::Priv
{
	BOOL CheckPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege)
	{
		PRIVILEGE_SET ps;
		LUID luid;
		BOOL bResult;

		if (!LookupPrivilegeValue(
			NULL,
			lpszPrivilege,
			&luid
		))
		{
			return FALSE;
		}

		ps.PrivilegeCount = 1;
		ps.Control = PRIVILEGE_SET_ALL_NECESSARY;
		ps.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
		ps.Privilege[0].Luid = luid;
		PrivilegeCheck(hToken, &ps, &bResult);
		if (!bResult)
		{
			return FALSE;
		}

		return TRUE;
	}
	
	// Reference:
	// https://learn.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
	BOOL SetPrivilege(
		HANDLE hToken,
		LPCTSTR lpszPrivilege,
		BOOL bEnablePrivilege
	) {
		TOKEN_PRIVILEGES tp;
		LUID luid;

		if (!LookupPrivilegeValue(
			NULL,
			lpszPrivilege,
			&luid
		))
		{
			return FALSE;
		}

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		if (bEnablePrivilege)
		{
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		}
		else
		{
			tp.Privileges[0].Attributes = 0;
		}

		// Enable the privilege or disable all privileges.
		if (!AdjustTokenPrivileges(
			hToken,
			FALSE,
			&tp,
			sizeof(TOKEN_PRIVILEGES),
			(PTOKEN_PRIVILEGES)NULL,
			(PDWORD)NULL
		))
		{
			return FALSE;
		}

		if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		{
			return FALSE;
		}

		return TRUE;
	}
}

