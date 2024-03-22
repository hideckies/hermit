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
    
    std::vector<char> ReadBytesFromFile(const std::wstring& wFilePath)
    {
        std::string sFilePath = Utils::Convert::UTF8Encode(wFilePath);

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
