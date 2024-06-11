#include "core/system.hpp"

namespace System::Process
{
    HANDLE ProcessCreate(
		Procs::PPROCS	pProcs,
		LPCWSTR			lpApplicationName,
		DWORD 			dwDesiredAccess,
		BOOL			bInheritHandles,
		DWORD           dwCreationFlags,
		HANDLE 			hParentProcess,
		HANDLE			hToken
	) {
		Nt::OBJECT_ATTRIBUTES objAttr;
		Nt::UNICODE_STRING uniAppName;

		CallSysInvoke(
			&pProcs->sysRtlInitUnicodeString,
			pProcs->lpRtlInitUnicodeString,
			&uniAppName,
			lpApplicationName
		);
		ULONG uAttributes = OBJ_CASE_INSENSITIVE;
		if (bInheritHandles)
		{
			uAttributes = OBJ_CASE_INSENSITIVE | OBJ_INHERIT;
		}
		MyInitializeObjectAttributes(&objAttr, &uniAppName, uAttributes, nullptr, nullptr);

		HANDLE hProcess;

		// Create a new process.
		NTSTATUS status = CallSysInvoke(
			&pProcs->sysNtCreateProcessEx,
			pProcs->lpNtCreateProcessEx,
			&hProcess,
			dwDesiredAccess,
			&objAttr,
			hParentProcess,
			(ULONG)dwCreationFlags,
			nullptr,
			nullptr,
			hToken,
			0
		);
		if (status != STATUS_SUCCESS)
		{
			STARTUPINFO si;
			PROCESS_INFORMATION pi;
			RtlZeroMemory(&si, sizeof(si));
			si.cb = sizeof(si);

			if (pProcs->lpCreateProcessW(
				lpApplicationName,
				nullptr,
				nullptr,
				nullptr,
				bInheritHandles,
				dwCreationFlags,
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

    DWORD ProcessGetIdByName(
		Procs::PPROCS pProcs,
		LPCWSTR lpProcessName
	) {
        DWORD pid = 0;
        HANDLE hSnapshot = pProcs->lpCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            if (pProcs->lpProcess32FirstW(hSnapshot, &pe32))
            {
                do
                {
                    if (lstrcmpi(pe32.szExeFile, lpProcessName) == 0)
                    {
                        pid = pe32.th32ProcessID;
                        break;
                    }
                } while (pProcs->lpProcess32NextW(hSnapshot, &pe32));
                
            }
            pProcs->lpCloseHandle(hSnapshot);
        }

        return pid;
    }

	DWORD ProcessGetMainThreadId(
		Procs::PPROCS pProcs,
		DWORD dwProcessId
	) {		
		DWORD dwMainThreadId = 0;
		THREADENTRY32 te32;

		HANDLE hThreadSnap = pProcs->lpCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (hThreadSnap == INVALID_HANDLE_VALUE)
		{
			return 0;
		}

		te32.dwSize = sizeof(THREADENTRY32);

		if (!pProcs->lpThread32First(hThreadSnap, &te32))
		{
			pProcs->lpCloseHandle(hThreadSnap);
			return 0;
		}

		do
		{
			if (te32.th32OwnerProcessID > 1000)
			{
				// Stdout::DisplayMessageBoxW(
				// 	Utils::Convert::DWORDToWstring(te32.th32OwnerProcessID).c_str(),
				// 	L"ProcessGetMainThreadId te32.th32OwnerProcessID"
				// );
			}

			if (te32.th32OwnerProcessID == dwProcessId)
			{
				dwMainThreadId = te32.th32ThreadID;
				break;
			}

		} while (pProcs->lpThread32Next(hThreadSnap, &te32));

		pProcs->lpCloseHandle(hThreadSnap);
		
		return dwMainThreadId;
	}

    HANDLE ProcessOpen(
		Procs::PPROCS pProcs,
		DWORD dwProcessID,
		DWORD dwDesiredAccess
	) {
		HANDLE hProcess;
		Nt::CLIENT_ID clientId;
		clientId.UniqueProcess = reinterpret_cast<HANDLE>(dwProcessID);
		clientId.UniqueThread = nullptr;
		static Nt::OBJECT_ATTRIBUTES oa = { sizeof(oa) };
		
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
			hProcess = pProcs->lpOpenProcess(
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
			if (!pProcs->lpOpenProcessToken(
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
			return pProcs->lpTerminateProcess(hProcess, EXIT_SUCCESS);
		}
		return TRUE;
	}

	PVOID VirtualMemoryAllocate(
		Procs::PPROCS pProcs,
		HANDLE 	hProcess,
		PVOID	pBaseAddr,
		SIZE_T	dwSize,
		DWORD 	dwAllocationType,
		DWORD 	dwProtect
	) {
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
			return pProcs->lpVirtualAllocEx(
                hProcess,
                pBaseAddr,
                dwSize,
                dwAllocationType,
                dwProtect
            );
		}

        return pBaseAddr;
    }

	BOOL VirtualMemoryRead(
        Procs::PPROCS   pProcs,
		HANDLE			hProcess,
		PVOID			pBaseAddr,
		PVOID			pBuffer,
		SIZE_T			dwBufferSize,
		PSIZE_T			lpNumberOfBytesRead
    ) {
		NTSTATUS status = CallSysInvoke(
			&pProcs->sysNtReadVirtualMemory,
			pProcs->lpNtReadVirtualMemory,
			hProcess,
			pBaseAddr,
			pBuffer,
			dwBufferSize,
			lpNumberOfBytesRead
		);
		if (status != STATUS_SUCCESS)
		{
			if (!pProcs->lpReadProcessMemory(
				hProcess,
				(LPCVOID)pBaseAddr,
				pBuffer,
				dwBufferSize,
				lpNumberOfBytesRead
			)) {
				return FALSE;
			}
		}

		return TRUE;
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
			if (!pProcs->lpWriteProcessMemory(
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
			if (!pProcs->lpVirtualProtectEx(
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
			return pProcs->lpVirtualFree(
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

	HANDLE ThreadOpen(
        Procs::PPROCS pProcs,
		DWORD dwDesiredAccess,
		BOOL bInheritHandle
    ) {
		HANDLE hThread;

		// CLIENT_ID clientId;
		// clientId.UniqueProcess = (HANDLE)pbi.

		// NTSTATUS status = CallSysInvoke(
		// 	&pProcs->sysNtOpenThread,
		// 	pProcs->lpNtOpenThread,
		// 	&hThread,
		// 	dwDesiredAccess,

		// );
		// if (status != STATUS_SUCCESS)
		// {
		// 	hThread = OpenThread(
		// 		dwDesiredAccess,
		// 		bInheritHandle,
		// 		dwThreadId
		// 	);
		// }

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

		if (!pProcs->lpCreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
		{
			return L"";
		}

		if (!pProcs->lpSetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0))
		{
			return L"";
		}

		RtlZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
		RtlZeroMemory(&si, sizeof(STARTUPINFOW));

		si.cb = sizeof(STARTUPINFOW);
		si.hStdError = hWritePipe;
		si.hStdOutput = hWritePipe;
		si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
		si.wShowWindow = SW_HIDE;

		// Set application name (full path)
		WCHAR system32Path[MAX_PATH];
		pProcs->lpGetSystemDirectoryW(system32Path, MAX_PATH);
		std::wstring wSystem32Path = std::wstring(system32Path);
		const std::wstring applicationName = wSystem32Path + L"\\cmd.exe";
		// const std::wstring applicationName = wSystem32Path + L"\\WindowsPowerShell\\v1.0\powershell.exe";

		// Set command
		std::wstring commandLine = L"/C " + wCmd;
		// std::wstring commandLine = L"-c " + cmd;

		bResults = pProcs->lpCreateProcessW(
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
		
		pProcs->lpCloseHandle(hWritePipe);

		while (pProcs->lpReadFile(hReadPipe, chBuf, 4095, &dwRead, NULL) && dwRead > 0)
		{
			chBuf[dwRead] = '\0';
			result += std::wstring(chBuf, chBuf + dwRead);
		}

		pProcs->lpCloseHandle(pi.hProcess);
		pProcs->lpCloseHandle(pi.hThread);
		pProcs->lpCloseHandle(hReadPipe);

		return result;
	}

    BOOL ExecuteFile(Procs::PPROCS pProcs, const std::wstring& wFilePath)
	{
		HANDLE hProcess = System::Process::ProcessCreate(
			pProcs,
			wFilePath.c_str(),
			PROCESS_ALL_ACCESS,
			FALSE,
			0,
			NtCurrentProcess(),
			nullptr
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