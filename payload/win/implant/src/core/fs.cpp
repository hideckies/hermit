#include "fs.hpp"

DWORD g_dwBytesTransferred = 0;

VOID CALLBACK FileIOCompletionRoutine(
  DWORD dwErrorCode,
  DWORD dwNumberOfBytesTransfered,
  LPOVERLAPPED lpOverlapped
) {
    // std::string sNumberOfBytesTransferred = std::to_string(dwNumberOfBytesTransfered);
    g_dwBytesTransferred = dwNumberOfBytesTransfered;
}

std::string MyReadFileA(const std::string& sFile)
{
    HANDLE hFile;
    DWORD dwBytesRead = 0;
    char readBuffer[MAX_BUFFER_SIZE] = {0};
    OVERLAPPED ol = {0};

    hFile = CreateFileA(
        sFile.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return "Error: Unable to open file.";
    }
    if (!ReadFileEx(hFile, readBuffer, MAX_BUFFER_SIZE-1, &ol, FileIOCompletionRoutine))
    {
        CloseHandle(hFile);
        return "Error: Unable to read from file.";
    }
    SleepEx(5000, TRUE);
    dwBytesRead = g_dwBytesTransferred;

    if (dwBytesRead > 0 && dwBytesRead <= MAX_BUFFER_SIZE-1)
    {
        readBuffer[dwBytesRead] = '\0';
        return std::string(readBuffer);
    }
    else if (dwBytesRead == 0)
    {
        return "Error: No data read from file.";
    }
    else
    {
        return "Error: Unexpected value in file.";
    }
}

std::wstring MyReadFileW(const std::wstring& wFile)
{
    HANDLE hFile;
    DWORD dwBytesRead = 0;
    char readBuffer[MAX_BUFFER_SIZE] = {0};
    OVERLAPPED ol = {0};

    hFile = CreateFileW(
        wFile.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return L"Error: Unable to open file.";
    }
    if (!ReadFileEx(hFile, readBuffer, MAX_BUFFER_SIZE-1, &ol, FileIOCompletionRoutine))
    {
        CloseHandle(hFile);
        return L"Error: Unable to read from file.";
    }
    SleepEx(5000, TRUE);
    dwBytesRead = g_dwBytesTransferred;

    if (dwBytesRead > 0 && dwBytesRead <= MAX_BUFFER_SIZE-1)
    {
        readBuffer[dwBytesRead] = '\0';
        std::wstring wReadBuffer = ConvertStringToWstring(std::string(readBuffer));
        return std::wstring(wReadBuffer);
    }
    else if (dwBytesRead == 0)
    {
        return L"Error: No data read from file.";
    }
    else
    {
        return L"Error: Unexpected value in file.";
    }
}

std::vector<BYTE> MyReadFileToByteArray(const std::string& sFilePath)
{
    std::ifstream file(sFilePath, std::ios::binary);

    // Stop eating new lines in binary mode
    file.unsetf(std::ios::skipws);

    // Get the file size
    std::streampos fileSize;
    file.seekg(0, std::ios::end);
    fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    // Reserve capacity
    std::vector<BYTE> vec;
    vec.reserve(fileSize);

    std::copy(
        std::istream_iterator<BYTE>(file),
        std::istream_iterator<BYTE>(),
        std::back_inserter(vec)
    );

    return vec;
}

MyFileData MyReadFileExW(const std::wstring& wFile)
{
    LPVOID lpData;
    DWORD dwDataSize;

    std::string sFile;
    LPCWSTR lpFileExt;
    std::vector<BYTE> vbData;
    std::string sData;

    sFile = ConvertWstringToString(wFile);

    // Get the file extension & Read the contents
    lpFileExt = PathFindExtensionW(wFile.c_str());
    if (lpFileExt && *lpFileExt)
    {
        std::wstring wFileExt(lpFileExt);

        if (
            wcscmp(wFileExt.c_str(), L".gif")   == 0 ||
            wcscmp(wFileExt.c_str(), L".jpg")   == 0 ||
            wcscmp(wFileExt.c_str(), L".jpeg")  == 0 ||
            wcscmp(wFileExt.c_str(), L".png")   == 0
        ) {
            vbData = MyReadFileToByteArray(sFile);
            lpData = (LPVOID)vbData.data();
            dwDataSize = (DWORD)vbData.size();
        }
        else
        {
            sData = MyReadFileA(sFile);
            lpData = (LPVOID)sData.c_str();
            dwDataSize = (DWORD)strlen(sData.c_str());
        }
    }
    else
    {
        // If no file extension,
        vbData = MyReadFileToByteArray(sFile);
        lpData = (LPVOID)&vbData;
        dwDataSize = (DWORD)vbData.size();
    }

    return {lpData, dwDataSize};
}

BOOL MyWriteFileW(const std::wstring& wFile, LPCVOID lpData, DWORD dwDataSize)
{
    HANDLE hFile;
    DWORD dwDataWritten = 0;
    BOOL bResult = FALSE;

    // DisplayMessageBoxA((LPCSTR)lpData, "MyWriteFileW");

    hFile = CreateFileW(
        wFile.c_str(),
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    bResult = WriteFile(
        hFile,
        lpData,
        dwDataSize,
        &dwDataWritten,
        NULL
    );
    if (!bResult)
    {
        return FALSE;
    }
    if (dwDataWritten != dwDataSize)
    {
        return FALSE;
    }

    CloseHandle(hFile);

    return TRUE;
}

std::wstring MyDeleteFileW(const std::wstring& wFile)
{
    if (DeleteFileW(wFile.c_str()))
    {
        return L"A file deleted.";
    } 
    else
    {
        return L"Could not delete a file.";
    }
}