#include "core/system.hpp"

namespace System::Fs
{
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
}