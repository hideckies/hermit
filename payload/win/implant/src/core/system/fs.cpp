#include "core/system.hpp"

DWORD g_dwBytesTransferred = 0;

namespace System::Fs
{
    VOID CALLBACK FileIOCompletionRoutine(
    DWORD dwErrorCode,
    DWORD dwNumberOfBytesTransfered,
    LPOVERLAPPED lpOverlapped
    ) {
        // std::string sNumberOfBytesTransferred = std::to_string(dwNumberOfBytesTransfered);
        g_dwBytesTransferred = dwNumberOfBytesTransfered;
    }

    std::wstring GetAbsolutePath(const std::wstring& wPath)
    {
        DWORD dwRet = 0;
        BOOL success;
        WCHAR wBuffer[MAX_PATH] = TEXT("");
        WCHAR wBuf[MAX_PATH] = TEXT("");
        WCHAR** lppPart = {NULL};

        dwRet = GetFullPathName(
            wPath.c_str(),
            MAX_PATH,
            wBuffer,
            lppPart
        );
        if (dwRet == 0)
        {
            return L"";
        }

        return std::wstring(wBuffer);
    }

    std::vector<std::wstring> GetFilesInDirectory(const std::wstring& wDirPath, BOOL bRecurse)
    {
        std::vector<std::wstring> files = {};

        WIN32_FIND_DATA ffd;
        LARGE_INTEGER fileSize;
        WCHAR wTargetDir[MAX_PATH];
        HANDLE hFind = INVALID_HANDLE_VALUE;
        DWORD dwError = 0;

        StringCchCopyW(wTargetDir, MAX_PATH, wDirPath.c_str());
        StringCchCatW(wTargetDir, MAX_PATH, TEXT("\\*"));

        hFind = FindFirstFile(wTargetDir, &ffd);
        if (hFind == INVALID_HANDLE_VALUE)
        {
            return files;
        }

        do
        {
            std::wstring wPathName = std::wstring(ffd.cFileName);
            if (wPathName == L"." || wPathName == L"..")
            {
                continue;
            }

            std::wstring wFullPathName = wDirPath + L"\\" + wPathName;
            if (wFullPathName == L"")
            {
                continue;
            }

            if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                // std::wstring wFullDirName = GetAbsolutePath(wPathName);

                if (bRecurse && wFullPathName != wDirPath)
                {
                    std::vector<std::wstring> childFiles = GetFilesInDirectory(wFullPathName, bRecurse);
                    files.insert(files.end(), childFiles.begin(), childFiles.end());
                }
                else
                {
                    files.push_back(wFullPathName);
                }
            }
            else
            {
                files.push_back(wFullPathName);
            }
        } while (FindNextFile(hFind, &ffd) != 0);

        return files;
    }
    
    std::vector<BYTE> ReadBytesFromFile(const std::wstring& wFilePath)
    {
        // Open file
        HANDLE hFile = CreateFile(
            wFilePath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        if (hFile == INVALID_HANDLE_VALUE)
        {
            return std::vector<BYTE>();
        }

        // Get file size
        DWORD dwFileSize = GetFileSize(hFile, NULL);
        if (dwFileSize == INVALID_FILE_SIZE)
        {
            CloseHandle(hFile);
            return std::vector<BYTE>();
        }

        // Allocate a buffer
        std::vector<BYTE> buffer(dwFileSize);

        DWORD dwBytesRead;
        if (!ReadFile(hFile, buffer.data(), dwFileSize, &dwBytesRead, NULL))
        {
            CloseHandle(hFile);
            return std::vector<BYTE>();
        }

        CloseHandle(hFile);

        return buffer;
    }

    BOOL MyWriteFile(const std::wstring& wFilePath, LPCVOID lpData, DWORD dwDataSize)
    {
        HANDLE hFile;
        DWORD dwDataWritten = 0;
        BOOL bResult = FALSE;

        // DisplayMessageBoxA((LPCSTR)lpData, "MyWriteFileW");

        hFile = CreateFileW(
            wFilePath.c_str(),
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
}
