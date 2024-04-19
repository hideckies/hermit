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

    std::wstring GetAbsolutePath(const std::wstring& wPath, BOOL bExtendLength)
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

        if (bExtendLength)
        {
            return L"\\??\\\\" + std::wstring(wBuffer);
        }
        else
        {
            return std::wstring(wBuffer);
        }
    }

    BOOL ChangeCurrentDirectory(
        Procs::PPROCS pProcs,
        const std::wstring& wDestPath
    ) {
         // if (pProcs->lpNtSetInformationProcess)
        // {
        //     NTSTATUS ntStatus = pProcs->lpNtSetInformationProcess(
        //         GetCurrentProcess(),
        //         ProcessCurrentDirectory,
        //         lpPathName,
        //         wcslen(lpPathName) * sizeof(WCHAR)
        //     );
        //     if (ntStatus != 0)
        //     {
        //         return FALSE;
        //     }
        //     return TRUE;
        // }
        // else
        // {
        //     return SetCurrentDirectoryW(lpPathName);
        // }

        return SetCurrentDirectoryW(wDestPath.c_str());
    }

    std::vector<std::wstring> GetFilesInDirectory(Procs::PPROCS pProcs, const std::wstring& wDirPath, BOOL bRecurse)
    {
        std::vector<std::wstring> files = {};

        WIN32_FIND_DATA ffd;
        LARGE_INTEGER fileSize;
        WCHAR wTargetDir[MAX_PATH];
        HANDLE hFind = INVALID_HANDLE_VALUE;
        DWORD dwError = 0;

        pProcs->lpRtlStringCchCopyW(wTargetDir, MAX_PATH, wDirPath.c_str());
        pProcs->lpRtlStringCchCatW(wTargetDir, MAX_PATH, TEXT("\\*"));

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
                    std::vector<std::wstring> childFiles = GetFilesInDirectory(pProcs, wFullPathName, bRecurse);
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

    HANDLE CreateNewDirectory(
        Procs::PPROCS pProcs,
        const std::wstring& wDirPath
    ) {
        std::wstring wDirAbsPath = GetAbsolutePath(wDirPath, TRUE);

        NTSTATUS status;
        HANDLE hDir;

        IO_STATUS_BLOCK ioStatusBlock;
        OBJECT_ATTRIBUTES objAttr;
        UNICODE_STRING uniDirPath;

        pProcs->lpRtlInitUnicodeString(&uniDirPath, wDirAbsPath.c_str());
        InitializeObjectAttributes(&objAttr, &uniDirPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

        status = pProcs->lpNtCreateFile(
            &hDir,
            FILE_GENERIC_WRITE | SYNCHRONIZE,
            &objAttr,
            &ioStatusBlock,
            NULL,
            FILE_ATTRIBUTE_DIRECTORY,
            0,
            FILE_CREATE,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0
        );
        if (status != STATUS_SUCCESS)
        {            
            return NULL;
        }

        return hDir;
    }

    HANDLE CreateNewFile(
        Procs::PPROCS       pProcs,
        const std::wstring& wFilePath
    ) {
        std::wstring wFileAbsPath = System::Fs::GetAbsolutePath(wFilePath, TRUE);

        NTSTATUS status;
        HANDLE hFile;

        // Open file
        IO_STATUS_BLOCK ioStatusBlock;
        OBJECT_ATTRIBUTES objAttr;
        UNICODE_STRING uniFilePath;

        pProcs->lpRtlInitUnicodeString(&uniFilePath, wFileAbsPath.c_str());
        InitializeObjectAttributes(&objAttr, &uniFilePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

        status = pProcs->lpNtCreateFile(
            &hFile,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            &objAttr,
            &ioStatusBlock,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            CREATE_ALWAYS,
            FILE_NON_DIRECTORY_FILE | FILE_ATTRIBUTE_NORMAL,
            NULL,
            0
        );
        if (status != STATUS_SUCCESS)
        {
            return NULL;
        }

        return hFile;
    }
    
    std::vector<BYTE> ReadBytesFromFile(
        Procs::PPROCS       pProcs,
        const std::wstring& wFilePath
    ) {
        std::wstring wFileAbsPath = GetAbsolutePath(wFilePath, TRUE);

        NTSTATUS status;
        HANDLE hFile;

        // Open file
        IO_STATUS_BLOCK ioStatusBlock;
        OBJECT_ATTRIBUTES objAttr;
        UNICODE_STRING uniFilePath;

        pProcs->lpRtlInitUnicodeString(&uniFilePath, wFileAbsPath.c_str());
        InitializeObjectAttributes(&objAttr, &uniFilePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

        status = pProcs->lpNtCreateFile(
            &hFile,
            FILE_GENERIC_READ,
            &objAttr,
            &ioStatusBlock,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0
        );
        if (status != STATUS_SUCCESS)
        {            
            return std::vector<BYTE>();
        }

        // Get file size
        FILE_STANDARD_INFORMATION fileInfo;
        status = pProcs->lpNtQueryInformationFile(
            hFile,
            &ioStatusBlock,
            &fileInfo,
            sizeof(fileInfo),
            FileStandardInformation
        );
        if (status != STATUS_SUCCESS)
        {
            pProcs->lpNtClose(hFile);
            return std::vector<BYTE>();
        }

        // Allocate a buffer
        ULONG bufferSize = (ULONG)fileInfo.EndOfFile.QuadPart;
        // DWORD dwBufferSize = fileInfo.EndOfFile.u.LowPart;
        // Stdout::DisplayMessageBoxW(Utils::Convert::DWORDToWstring(dwBufferSize).c_str(), L"dwBufferSize");
        std::vector<BYTE> buffer(bufferSize);

        // Read file contents
        LARGE_INTEGER byteOffset;
        byteOffset.QuadPart = 0;

        status = pProcs->lpNtReadFile(
            hFile,
            NULL,
            NULL,
            NULL,
            &ioStatusBlock,
            buffer.data(),
            bufferSize,
            &byteOffset,
            NULL
        );
        if (status == STATUS_PENDING)
        {
            status = pProcs->lpNtWaitForSingleObject(hFile, FALSE, NULL);
            if (status != STATUS_SUCCESS)
            {
                pProcs->lpNtClose(hFile);
                return std::vector<BYTE>();
            }
        }
        if (status != STATUS_SUCCESS)
        {
            pProcs->lpNtClose(hFile);
            return std::vector<BYTE>();
        }

        if (ioStatusBlock.Information <= 0)
        {
            pProcs->lpNtClose(hFile);
            return std::vector<BYTE>();
        }

        pProcs->lpNtClose(hFile);

        return buffer;
    }

    BOOL WriteBytesToFile(
        Procs::PPROCS               pProcs,
        const std::wstring&         wFilePath,
        const std::vector<BYTE>&    bytes
    ) {
        std::wstring wFileAbsPath = GetAbsolutePath(wFilePath, TRUE);

        NTSTATUS status;
        HANDLE hFile;

        // Open file
        IO_STATUS_BLOCK ioStatusBlock;
        OBJECT_ATTRIBUTES objAttr;
        UNICODE_STRING uniFilePath;

        pProcs->lpRtlInitUnicodeString(&uniFilePath, wFileAbsPath.c_str());
        InitializeObjectAttributes(&objAttr, &uniFilePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

        status = pProcs->lpNtCreateFile(
            &hFile,
            FILE_GENERIC_WRITE,
            &objAttr,
            &ioStatusBlock,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN_IF,
            FILE_NON_DIRECTORY_FILE,
            NULL,
            0
        );
        if (status != STATUS_SUCCESS)
        {            
            return FALSE;
        }

        // Write data to the file.
        LARGE_INTEGER byteOffset;
        byteOffset.QuadPart = 0;

        status = pProcs->lpNtWriteFile(
            hFile,
            NULL,
            NULL,
            NULL,
            &ioStatusBlock,
            (PVOID)bytes.data(),
            bytes.size(),
            &byteOffset,
            NULL
        );
        if (status == STATUS_PENDING)
        {
            status = pProcs->lpNtWaitForSingleObject(hFile, FALSE, NULL);
            if (status != STATUS_SUCCESS)
            {
                pProcs->lpNtClose(hFile);
                return FALSE;
            }
        }
        if (status != STATUS_SUCCESS)
        {
            pProcs->lpNtClose(hFile);
            return FALSE;
        }

        if (ioStatusBlock.Information <= 0)
        {
            pProcs->lpNtClose(hFile);
            return FALSE;
        }

        pProcs->lpNtClose(hFile);

        return TRUE;
    }

    DWORD FileSizeGet(
        Procs::PPROCS   pProcs,
        HANDLE          hFile
    ) {
        DWORD dwFileSize;

        NTSTATUS status;
        IO_STATUS_BLOCK ioStatusBlock;
        FILE_STANDARD_INFORMATION fileInfo;

        status = pProcs->lpNtQueryInformationFile(
            hFile,
            &ioStatusBlock,
            &fileInfo,
            sizeof(fileInfo),
            FileStandardInformation
        );
        if (status != STATUS_SUCCESS)
        {
            return INVALID_FILE_SIZE;
        }

        dwFileSize = fileInfo.EndOfFile.QuadPart;
        return dwFileSize;
    }
}
