#ifndef HERMIT_HERMIT_HPP
#define HERMIT_HERMIT_HPP

#include <windows.h>
#include <winhttp.h>
#include <string>
#include <wchar.h>
#include "types.hpp"
#include "common.hpp"
#include "convert.hpp"

#ifndef IS_DLL
#include "screenshot.hpp"
#endif

#include "task.hpp"
#include "winsystem.hpp"

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

#endif // HERMIT_HERMIT_HPP