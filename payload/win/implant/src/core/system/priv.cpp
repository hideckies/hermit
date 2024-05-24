#include "core/system.hpp"

namespace System::Priv
{
	BOOL PrivilegeCheck(
		Procs::PPROCS pProcs,
		HANDLE hToken,
		LPCTSTR lpszPrivilege
	) {
		LUID luid;

		// Check if the privilege name exists.
		if (!pProcs->lpLookupPrivilegeValueW(
			NULL,
			lpszPrivilege,
			&luid
		))
		{
			return FALSE;
		}

		PRIVILEGE_SET ps;
		BOOL bResult = FALSE;

		ps.PrivilegeCount = 1;
		ps.Control = PRIVILEGE_SET_ALL_NECESSARY;
		ps.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
		ps.Privilege[0].Luid = luid;

		// NtPrivilegeCheck is not working, so use WINAPI.
		pProcs->lpPrivilegeCheck(hToken, &ps, &bResult);

		return bResult;
	}
	
	BOOL PrivilegeSet(
		Procs::PPROCS pProcs,
		HANDLE hToken,
		LPCTSTR lpszPrivilege,
		BOOL bEnablePrivilege
	) {
		TOKEN_PRIVILEGES tp;
		LUID luid;

		if (!pProcs->lpLookupPrivilegeValueW(
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
		if (!pProcs->lpAdjustTokenPrivileges(
			hToken,
			FALSE,
			&tp,
			sizeof(TOKEN_PRIVILEGES),
			(PTOKEN_PRIVILEGES)NULL,
			(PDWORD)NULL
		)) {
			return FALSE;
		}

		if (pProcs->lpGetLastError() == ERROR_NOT_ALL_ASSIGNED)
		{
			return FALSE;
		}

		return TRUE;
	}
}

