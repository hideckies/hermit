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

std::vector<char> ReadBytesFromFile(const std::wstring& wFilePath)
{
    std::string sFilePath = UTF8Encode(wFilePath);

    std::ifstream file(sFilePath, std::ios::binary);
    if (!file.is_open())
    {
        return std::vector<char>();
    }

    // Get the file size
    file.seekg(0, std::ios::end);
    std::streampos fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    // Reserve capacity
    std::vector<char> buffer(fileSize);

    file.read(buffer.data(), fileSize);
    file.close();

    return buffer;
}

BOOL MyWriteFile(const std::wstring& wFile, LPCVOID lpData, DWORD dwDataSize)
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
