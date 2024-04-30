#include "core/system.hpp"

namespace System::Fs
{
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
}