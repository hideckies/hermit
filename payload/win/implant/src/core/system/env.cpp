#include "core/system.hpp"

namespace System::Env
{
	std::wstring EnvStringsGet(Procs::PPROCS pProcs, const std::wstring& envVar)
	{
		wchar_t envStrings[INFO_BUFFER_SIZE];

		DWORD envStringsLen = pProcs->lpExpandEnvironmentStringsW(
			envVar.c_str(),
			envStrings,
			INFO_BUFFER_SIZE
		);

		return envStrings;
	}

	// Reference:
	// https://github.com/microsoft/Detours/blob/4b8c659f549b0ab21cf649377c7a84eb708f5e68/samples/tracebld/trcbld.cpp#L815
	std::map<std::wstring, std::wstring> EnvAllGet(Procs::PPROCS pProcs)
	{
        std::map<std::wstring, std::wstring> result;

		std::wstring key;
		std::wstring val;

		NTSTATUS status;

		// Get all environment variables.
		LPWCH pwStrings = pProcs->lpGetEnvironmentStringsW();
		PCWSTR pwEnv = (PCWSTR)pwStrings;

		while (*pwEnv != '\0')
		{
			WCHAR wzKey[MAX_PATH];
			PWCHAR pwzDst = wzKey;
			PCWSTR pwzVal = NULL;

			if (*pwEnv == '=')
				*pwzDst++ = *pwEnv++;
			while (*pwEnv != '\0' && *pwEnv != '=')
			{
				*pwzDst++ = *pwEnv++;
			}
			*pwzDst++ = '\0';

			if (*pwEnv == '=')
			{
				pwEnv++;
			}

			pwzVal = pwEnv;
			while (*pwEnv != '\0')
			{
				pwEnv++;
			}
			if (*pwEnv == '\0')
			{
				pwEnv++;
			}
			if (wzKey[0] != '=')
			{
				result.insert(std::make_pair(wzKey, pwzVal));
			}

		}

		pProcs->lpFreeEnvironmentStringsW(pwStrings);

		return result;
	}
}