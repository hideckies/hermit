#include "core/system.hpp"

namespace System::Process
{
    HANDLE ProcessCreate(
		Procs::PPROCS 	pProcs,
		LPCWSTR 		lpApplicationName,
		DWORD 			dwDesiredAccess,
		HANDLE 			hParentProcess
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
			nullptr
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

    DWORD ProcessGetIdByName(LPCWSTR lpProcessName)
    {
        DWORD pid = 0;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hSnapshot, &pe32))
            {
                do
                {
                    if (lstrcmpi(pe32.szExeFile, lpProcessName) == 0)
                    {
                        pid = pe32.th32ProcessID;
                        break;
                    }
                } while (Process32Next(hSnapshot, &pe32));
                
            }
            CloseHandle(hSnapshot);
        }

        return pid;
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
			dwDesiredAccess,
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
		Procs::PPROCS pProcs,
		HANDLE hProcess,
		DWORD dwSize,
		DWORD dwAllocationType,
		DWORD dwProtect
	) {
        PVOID baseAddr;

		NTSTATUS status = CallSysInvoke(
			&pProcs->sysNtAllocateVirtualMemory,
			pProcs->lpNtAllocateVirtualMemory,
			hProcess,
            &baseAddr,
            0,
            (PSIZE_T)&dwSize,
            dwAllocationType,
            dwProtect
		);
		if (status != STATUS_SUCCESS)
		{
			baseAddr = VirtualAllocEx(
                hProcess,
                nullptr,
                (SIZE_T)dwSize,
                dwAllocationType,
                dwProtect
            );
		}

        return baseAddr;
    }

    BOOL VirtualMemoryFree(
		Procs::PPROCS 	pProcs,
		HANDLE 			hProcess,
		PVOID* 			pBaseAddr,
		SIZE_T 			dwSize,
		DWORD 			dwFreeType
	) {
		NTSTATUS status = CallSysInvoke(
			&pProcs->sysNtFreeVirtualMemory,
			pProcs->lpNtFreeVirtualMemory,
			hProcess,
			pBaseAddr,
			&dwSize,
			dwFreeType
		);
		if (status != STATUS_SUCCESS)
		{
			return VirtualFree(
				pBaseAddr,
				dwSize,
				dwFreeType
			);
		}
	
		return TRUE;
	}

    BOOL VirtualMemoryWrite(
		Procs::PPROCS 	pProcs,
		HANDLE 			hProcess,
		PVOID 			pBaseAddr,
		PVOID 			pBuffer,
		DWORD 			dwBufferSize,
		PDWORD 			lpNumberOfBytesWritten
	) {
		NTSTATUS status = CallSysInvoke(
			&pProcs->sysNtWriteVirtualMemory,
			pProcs->lpNtWriteVirtualMemory,
			hProcess,
			pBaseAddr,
			pBuffer,
			dwBufferSize,
			(PSIZE_T)lpNumberOfBytesWritten
		);
		if (status != STATUS_SUCCESS)
		{
			if (!WriteProcessMemory(
				hProcess,
				pBaseAddr,
				pBuffer,
				dwBufferSize,
				reinterpret_cast<SIZE_T*>(lpNumberOfBytesWritten)
			)) {
				return FALSE;
			}
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
		static OBJECT_ATTRIBUTES oa = { sizeof(oa) };
            
		NTSTATUS status = CallSysInvoke(
			&pProcs->sysNtCreateThreadEx,
			pProcs->lpNtCreateThreadEx,
			&hThread,
			THREAD_ALL_ACCESS,
			nullptr,
			hProcess,
			(PVOID)lpThreadStartRoutineAddr,
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
			NtCurrentProcess() // GetCurrentProcess()
		);
		if (!hProcess)
		{
			return FALSE;
		}

		System::Handle::HandleWait(pProcs, hProcess, FALSE, nullptr);
		System::Handle::HandleClose(pProcs, hProcess);

		return TRUE;
	}
}