#include "core/system.hpp"

namespace System::Process
{
	HANDLE ProcessCreate(
		Procs::PPROCS 	pProcs,
		LPCWSTR 		lpApplicationName,
		DWORD 			dwDesiredAccess,
		HANDLE 			hParentProcess
	) {
		NTSTATUS status;
		HANDLE hProcess;
		OBJECT_ATTRIBUTES objAttr;
		UNICODE_STRING uniAppName;

		InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
		RtlInitUnicodeString(&uniAppName, lpApplicationName);

		// Create a new process.
		status = pProcs->lpNtCreateProcess(
			&hProcess,
			dwDesiredAccess,
			&objAttr,
			hParentProcess,
			FALSE,
			NULL,
			NULL,
			NULL
		);
		if (status != STATUS_SUCCESS)
		{
			return NULL;
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
		
		pProcs->lpNtOpenProcess(
			&hProcess,
			dwDesiredAccess,
			&oa,
			&clientId
		);
		return hProcess;
	}

	BOOL ProcessTerminate(
        Procs::PPROCS   pProcs,
        HANDLE          hProcess,
        NTSTATUS        ntStatus
    ) {
		NTSTATUS status = pProcs->lpNtTerminateProcess(hProcess, ntStatus);
		if (status != STATUS_SUCCESS)
		{
			return FALSE;
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

        pProcs->lpNtAllocateVirtualMemory(
            hProcess,
            &baseAddr,
            0,
            (PSIZE_T)&dwSize,
            dwAllocationType,
            dwProtect
        );

        return baseAddr;
    }

	BOOL VirtualMemoryFree(
		Procs::PPROCS 	pProcs,
		HANDLE 			hProcess,
		PVOID* 			lpBaseAddr,
		SIZE_T 			dwSize,
		DWORD 			dwFreeType
	) {
		return pProcs->lpNtFreeVirtualMemory(
			hProcess,
			lpBaseAddr,
			&dwSize,
			dwFreeType
		);
	}

	BOOL VirtualMemoryWrite(
		Procs::PPROCS 	pProcs,
		HANDLE 			hProcess,
		LPVOID 			lpBaseAddr,
		LPVOID 			lpBuffer,
		DWORD 			dwBufferSize,
		PDWORD 			lpNumberOfBytesWritten
	) {
		NTSTATUS status = pProcs->lpNtWriteVirtualMemory(
			hProcess,
			lpBaseAddr,
			(PVOID)lpBuffer,
			dwBufferSize,
			(PSIZE_T)lpNumberOfBytesWritten
		);
		if (status != STATUS_SUCCESS)
		{
			return FALSE;
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
            
		NTSTATUS ntStatus = pProcs->lpNtCreateThreadEx(
			&hThread,
			THREAD_ALL_ACCESS,
			NULL,
			hProcess,
			(PVOID)lpThreadStartRoutineAddr,
			pArgument,
			0,
			0,
			0,
			0,
			NULL
		);
		if (ntStatus != STATUS_SUCCESS)
		{
			return NULL;
		}

		return NULL;
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
		NTSTATUS status;

		sa.nLength = sizeof(SECURITY_ATTRIBUTES);
		sa.bInheritHandle = TRUE;
		sa.lpSecurityDescriptor = NULL;

		// if (!System::Pipe::PipeCreate(pProcs, &hReadPipe, &hWritePipe))
		if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
		{
			return L"";
		}

		// if (!System::Handle::SetHandleInformation(pProcs, &hReadPipe, HANDLE_FLAG_INHERIT, 0))
		if (!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0)) {
			return L"";
		}

		pProcs->lpRtlZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
		pProcs->lpRtlZeroMemory(&pi, sizeof(STARTUPINFOW));

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
		IO_STATUS_BLOCK ioStatusBlock;
    	ULONG bufferSize = 4096;
		std::vector<BYTE> buffer(bufferSize);

		LARGE_INTEGER byteOffset;
        byteOffset.QuadPart = 0;
		
		ULONG bytesRead = 0;
		while (bytesRead < bufferSize)
		{
			status = pProcs->lpNtReadFile(
				hReadPipe,
				NULL,
				NULL,
				NULL,
				&ioStatusBlock,
				buffer.data() + bytesRead,
				bufferSize - bytesRead,
				&byteOffset,
				NULL
			);

			if (status != STATUS_SUCCESS)
			{
				pProcs->lpNtClose(hWritePipe);
				pProcs->lpNtClose(pi.hProcess);
				pProcs->lpNtClose(pi.hThread);
				pProcs->lpNtClose(hReadPipe);
				return L"";
			}

			bytesRead += ioStatusBlock.Information;
			byteOffset.QuadPart += ioStatusBlock.Information;

			if (ioStatusBlock.Information < bufferSize - bytesRead)
			{
				break;
			}
		}

		result = Utils::Convert::UTF8Decode(std::string(buffer.begin(), buffer.end()));
		

		// while (Procs::Call::HReadFile(pProcs, hReadPipe, chBuf, 4095, &dwRead, NULL) && dwRead > 0)
		// {
		// 	chBuf[dwRead] = '\0';
		// 	result += std::wstring(chBuf, chBuf + dwRead);
		// }

		pProcs->lpNtClose(hWritePipe);
		pProcs->lpNtClose(pi.hProcess);
		pProcs->lpNtClose(pi.hThread);
		pProcs->lpNtClose(hReadPipe);

		return result;
	}

	BOOL ExecuteFile(Procs::PPROCS pProcs, const std::wstring& wFilePath)
	{
		// Create a new process.
		NTSTATUS status;
		STARTUPINFO si;
		PROCESS_INFORMATION pi;

		pProcs->lpRtlZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);
		pProcs->lpRtlZeroMemory(&pi, sizeof(pi));

		HANDLE hProcess = System::Process::ProcessCreate(
			pProcs,
			wFilePath.c_str(),
			PROCESS_ALL_ACCESS,
			GetCurrentProcess()
		);
		if (!hProcess)
		{
			return FALSE;
		}

		// Write buffer
		std::wstring wFileAbsPath = System::Fs::GetAbsolutePath(wFilePath, TRUE);
		UNICODE_STRING uniAppName;
		pProcs->lpRtlInitUnicodeString(&uniAppName, wFileAbsPath.c_str());
		DWORD dwBytesWritten;

		if (!System::Process::VirtualMemoryWrite(
			pProcs,
			hProcess,
			reinterpret_cast<PVOID>(0x1000),
			uniAppName.Buffer,
			uniAppName.Length,
			&dwBytesWritten
		)) {
			pProcs->lpNtClose(hProcess);
			return FALSE;
		}

		// Start a new thread
		status = pProcs->lpNtResumeThread(pi.hThread, NULL);
		if (status != STATUS_SUCCESS)
		{
			pProcs->lpNtClose(hProcess);
			return FALSE;
		}

		pProcs->lpNtWaitForSingleObject(pi.hProcess, FALSE, NULL);

		pProcs->lpNtClose(pi.hProcess);
		pProcs->lpNtClose(pi.hThread);

		return TRUE;
	}
}
