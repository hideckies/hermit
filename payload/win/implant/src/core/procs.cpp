#include "core/procs.hpp"

namespace Procs
{
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

    VOID FindProcs(
        Procs::PPROCS pProcs,
        HMODULE hNtdll,
        HMODULE hKernel32,
        BOOL bIndirectSyscalls
    ) {
        // NTAPI (Ntdll)
        PVOID pEtwEventWrite                    = GetProcAddressByHash(hNtdll, HASH_FUNC_ETWEVENTWRITE);
        pProcs->lpEtwEventWrite                 = reinterpret_cast<LPPROC_ETWEVENTWRITE>(pEtwEventWrite);
        PVOID pLdrLoadDll                       = GetProcAddressByHash(hNtdll, HASH_FUNC_LDRLOADDLL);
        pProcs->lpLdrLoadDll                    = reinterpret_cast<LPPROC_LDRLOADDLL>(pLdrLoadDll);
        PVOID pNtAdjustPrivilegesToken          = GetProcAddressByHash(hNtdll, HASH_FUNC_NTADJUSTPRIVILEGESTOKEN);
        pProcs->lpNtAdjustPrivilegesToken       = reinterpret_cast<LPPROC_NTADJUSTPRIVILEGESTOKEN>(pNtAdjustPrivilegesToken);
        PVOID pNtAllocateVirtualMemory          = GetProcAddressByHash(hNtdll, HASH_FUNC_NTALLOCATEVIRTUALMEMORY);
        pProcs->lpNtAllocateVirtualMemory       = reinterpret_cast<LPPROC_NTALLOCATEVIRTUALMEMORY>(pNtAllocateVirtualMemory);
        PVOID pNtClose                          = GetProcAddressByHash(hNtdll, HASH_FUNC_NTCLOSE);
        pProcs->lpNtClose                       = reinterpret_cast<LPPROC_NTCLOSE>(pNtClose);
        PVOID pNtCreateFile                     = GetProcAddressByHash(hNtdll, HASH_FUNC_NTCREATEFILE);
        pProcs->lpNtCreateFile                  = reinterpret_cast<LPPROC_NTCREATEFILE>(pNtCreateFile);
        PVOID pNtCreateNamedPipeFile            = GetProcAddressByHash(hNtdll, HASH_FUNC_NTCREATENAMEDPIPEFILE);
        pProcs->lpNtCreateNamedPipeFile         = reinterpret_cast<LPPROC_NTCREATENAMEDPIPEFILE>(pNtCreateNamedPipeFile);
        PVOID pNtCreateProcessEx                = GetProcAddressByHash(hNtdll, HASH_FUNC_NTCREATEPROCESSEX);
        pProcs->lpNtCreateProcessEx             = reinterpret_cast<LPPROC_NTCREATEPROCESSEX>(pNtCreateProcessEx);
        PVOID pNtCreateThreadEx                 = GetProcAddressByHash(hNtdll, HASH_FUNC_NTCREATETHREADEX);
        pProcs->lpNtCreateThreadEx              = reinterpret_cast<LPPROC_NTCREATETHREADEX>(pNtCreateThreadEx);
        PVOID pNtDeleteFile                     = GetProcAddressByHash(hNtdll, HASH_FUNC_NTDELETEFILE);
        pProcs->lpNtDeleteFile                  = reinterpret_cast<LPPROC_NTDELETEFILE>(pNtDeleteFile);
        PVOID pNtDuplicateObject                = GetProcAddressByHash(hNtdll, HASH_FUNC_NTDUPLICATEOBJECT);
        pProcs->lpNtDuplicateObject             = reinterpret_cast<LPPROC_NTDUPLICATEOBJECT>(pNtDuplicateObject);
        PVOID pNtEnumerateValueKey              = GetProcAddressByHash(hNtdll, HASH_FUNC_NTENUMERATEVALUEKEY);
        pProcs->lpNtEnumerateValueKey           = reinterpret_cast<LPPROC_NTENUMERATEVALUEKEY>(pNtEnumerateValueKey);
        PVOID pNtFreeVirtualMemory              = GetProcAddressByHash(hNtdll, HASH_FUNC_NTFREEVIRTUALMEMORY);
        pProcs->lpNtFreeVirtualMemory           = reinterpret_cast<LPPROC_NTFREEVIRTUALMEMORY>(pNtFreeVirtualMemory);
        PVOID pNtFlushInstructionCache          = GetProcAddressByHash(hNtdll, HASH_FUNC_NTFLUSHINSTRUCTIONCACHE);
        pProcs->lpNtFlushInstructionCache       = reinterpret_cast<LPPROC_NTFLUSHINSTRUCTIONCACHE>(pNtFlushInstructionCache);
        PVOID pNtGetContextThread               = GetProcAddressByHash(hNtdll, HASH_FUNC_NTGETCONTEXTTHREAD);
        pProcs->lpNtGetContextThread            = reinterpret_cast<LPPROC_NTGETCONTEXTTHREAD>(pNtGetContextThread);
        PVOID pNtOpenFile                       = GetProcAddressByHash(hNtdll, HASH_FUNC_NTOPENFILE);
        pProcs->lpNtOpenFile                    = reinterpret_cast<LPPROC_NTOPENFILE>(pNtOpenFile);
        PVOID pNtOpenKeyEx                      = GetProcAddressByHash(hNtdll, HASH_FUNC_NTOPENKEYEX);
        pProcs->lpNtOpenKeyEx                   = reinterpret_cast<LPPROC_NTOPENKEYEX>(pNtOpenKeyEx);
        PVOID pNtOpenProcess                    = GetProcAddressByHash(hNtdll, HASH_FUNC_NTOPENPROCESS);
        pProcs->lpNtOpenProcess                 = reinterpret_cast<LPPROC_NTOPENPROCESS>(pNtOpenProcess);
        PVOID pNtOpenProcessToken               = GetProcAddressByHash(hNtdll, HASH_FUNC_NTOPENPROCESSTOKEN);
        pProcs->lpNtOpenProcessToken            = reinterpret_cast<LPPROC_NTOPENPROCESSTOKEN>(pNtOpenProcessToken);
        PVOID pNtPrivilegeCheck                 = GetProcAddressByHash(hNtdll, HASH_FUNC_NTPRIVILEGECHECK);
        pProcs->lpNtPrivilegeCheck              = reinterpret_cast<LPPROC_NTPRIVILEGECHECK>(pNtPrivilegeCheck);
        PVOID pNtProtectVirtualMemory           = GetProcAddressByHash(hNtdll, HASH_FUNC_NTPROTECTVIRTUALMEMORY);
        pProcs->lpNtProtectVirtualMemory        = reinterpret_cast<LPPROC_NTPROTECTVIRTUALMEMORY>(pNtProtectVirtualMemory);
        PVOID pNtQueryInformationFile           = GetProcAddressByHash(hNtdll, HASH_FUNC_NTQUERYINFORMATIONFILE);
        pProcs->lpNtQueryInformationFile        = reinterpret_cast<LPPROC_NTSETINFORMATIONFILE>(pNtQueryInformationFile);
        PVOID pNtQueryInformationProcess        = GetProcAddressByHash(hNtdll, HASH_FUNC_NTQUERYINFORMATIONPROCESS);
        pProcs->lpNtQueryInformationProcess     = reinterpret_cast<LPPROC_NTQUERYINFORMATIONPROCESS>(pNtQueryInformationProcess);
        PVOID pNtQueryInformationToken          = GetProcAddressByHash(hNtdll, HASH_FUNC_NTQUERYINFORMATIONTOKEN);
        pProcs->lpNtQueryInformationToken       = reinterpret_cast<LPPROC_NTQUERYINFORMATIONTOKEN>(pNtQueryInformationToken);
        PVOID pNtQueryKey                       = GetProcAddressByHash(hNtdll, HASH_FUNC_NTQUERYKEY);
        pProcs->lpNtQueryKey                    = reinterpret_cast<LPPROC_NTQUERYKEY>(pNtQueryKey);
        PVOID pNtQuerySystemInformation         = GetProcAddressByHash(hNtdll, HASH_FUNC_NTQUERYSYSTEMINFORMATION);
        pProcs->lpNtQuerySystemInformation      = reinterpret_cast<LPPROC_NTQUERYSYSTEMINFORMATION>(pNtQuerySystemInformation);
        PVOID pNtReadFile                       = GetProcAddressByHash(hNtdll, HASH_FUNC_NTREADFILE);
        pProcs->lpNtReadFile                    = reinterpret_cast<LPPROC_NTREADFILE>(pNtReadFile);
        PVOID pNtReadVirtualMemory              = GetProcAddressByHash(hNtdll, HASH_FUNC_NTREADVIRTUALMEMORY);
        pProcs->lpNtReadVirtualMemory           = reinterpret_cast<LPPROC_NTREADVIRTUALMEMORY>(pNtReadVirtualMemory);
        PVOID pNtResumeThread                   = GetProcAddressByHash(hNtdll, HASH_FUNC_NTRESUMETHREAD);
        pProcs->lpNtResumeThread                = reinterpret_cast<LPPROC_NTRESUMETHREAD>(pNtResumeThread);
        PVOID pNtSetContextThread               = GetProcAddressByHash(hNtdll, HASH_FUNC_NTSETCONTEXTTHREAD);
        pProcs->lpNtSetContextThread            = reinterpret_cast<LPPROC_NTSETCONTEXTTHREAD>(pNtSetContextThread);
        PVOID pNtSetInformationFile             = GetProcAddressByHash(hNtdll, HASH_FUNC_NTSETINFORMATIONFILE);
        pProcs->lpNtSetInformationFile          = reinterpret_cast<LPPROC_NTSETINFORMATIONFILE>(pNtSetInformationFile);
        PVOID pNtSystemDebugControl             = GetProcAddressByHash(hNtdll, HASH_FUNC_NTSYSTEMDEBUGCONTROL);
        pProcs->lpNtSystemDebugControl          = reinterpret_cast<LPPROC_NTSYSTEMDEBUGCONTROL>(pNtSystemDebugControl);
        PVOID pNtTerminateProcess               = GetProcAddressByHash(hNtdll, HASH_FUNC_NTTERMINATEPROCESS);
        pProcs->lpNtTerminateProcess            = reinterpret_cast<LPPROC_NTTERMINATEPROCESS>(pNtTerminateProcess);
        PVOID pNtTraceEvent                     = GetProcAddressByHash(hNtdll, HASH_FUNC_NTTRACEEVENT);
        pProcs->lpNtTraceEvent                  = reinterpret_cast<LPPROC_NTTRACEEVENT>(pNtTraceEvent);
        PVOID pNtUnmapViewOfSection             = GetProcAddressByHash(hNtdll, HASH_FUNC_NTUNMAPVIEWOFSECTION);
        pProcs->lpNtUnmapViewOfSection          = reinterpret_cast<LPPROC_NTUNMAPVIEWOFSECTION>(pNtUnmapViewOfSection);
        PVOID pNtWaitForSingleObject            = GetProcAddressByHash(hNtdll, HASH_FUNC_NTWAITFORSINGLEOBJECT);
        pProcs->lpNtWaitForSingleObject         = reinterpret_cast<LPPROC_NTWAITFORSINGLEOBJECT>(pNtWaitForSingleObject);
        PVOID pNtWriteFile                      = GetProcAddressByHash(hNtdll, HASH_FUNC_NTWRITEFILE);
        pProcs->lpNtWriteFile                   = reinterpret_cast<LPPROC_NTWRITEFILE>(pNtWriteFile);
        PVOID pNtWriteVirtualMemory             = GetProcAddressByHash(hNtdll, HASH_FUNC_NTWRITEVIRTUALMEMORY);
        pProcs->lpNtWriteVirtualMemory          = reinterpret_cast<LPPROC_NTWRITEVIRTUALMEMORY>(pNtWriteVirtualMemory);
        PVOID pRtlAllocateHeap                  = GetProcAddressByHash(hNtdll, HASH_FUNC_RTLALLOCATEHEAP);
        pProcs->lpRtlAllocateHeap               = reinterpret_cast<LPPROC_RTLALLOCATEHEAP>(pRtlAllocateHeap);
        PVOID pRtlGetCurrentDirectory_U         = GetProcAddressByHash(hNtdll, HASH_FUNC_RTLGETCURRENTDIRECTORY_U);
        pProcs->lpRtlGetCurrentDirectory_U      = reinterpret_cast<LPPROC_RTLGETCURRENTDIRECTORY_U>(pRtlGetCurrentDirectory_U);
        PVOID pRtlGetFullPathName_U             = GetProcAddressByHash(hNtdll, HASH_FUNC_RTLGETFULLPATHNAME_U);
        pProcs->lpRtlGetFullPathName_U          = reinterpret_cast<LPPROC_RTLGETFULLPATHNAME_U>(pRtlGetFullPathName_U);
        PVOID pRtlInitUnicodeString             = GetProcAddressByHash(hNtdll, HASH_FUNC_RTLINITUNICODESTRING);
        pProcs->lpRtlInitUnicodeString          = reinterpret_cast<LPPROC_RTLINITUNICODESTRING>(pRtlInitUnicodeString);
        PVOID pRtlSetCurrentDirectory_U         = GetProcAddressByHash(hNtdll, HASH_FUNC_RTLSETCURRENTDIRECTORY_U);
        pProcs->lpRtlSetCurrentDirectory_U      = reinterpret_cast<LPPROC_RTLSETCURRENTDIRECTORY_U>(pRtlSetCurrentDirectory_U);
        PVOID pRtlStringCchCatW                 = GetProcAddressByHash(hNtdll, HASH_FUNC_RTLSTRINGCCHCATW);
        pProcs->lpRtlStringCchCatW              = reinterpret_cast<LPPROC_RTLSTRINGCCHCATW>(pRtlStringCchCatW);
        PVOID pRtlStringCchCopyW                = GetProcAddressByHash(hNtdll, HASH_FUNC_RTLSTRINGCCHCOPYW);
        pProcs->lpRtlStringCchCopyW             = reinterpret_cast<LPPROC_RTLSTRINGCCHCOPYW>(pRtlStringCchCopyW);
        PVOID pRtlStringCchLengthW              = GetProcAddressByHash(hNtdll, HASH_FUNC_RTLSTRINGCCHLENGTHW);
        pProcs->lpRtlStringCchLengthW           = reinterpret_cast<LPPROC_RTLSTRINGCCHLENGTHW>(pRtlStringCchLengthW);
        PVOID pRtlZeroMemory                    = GetProcAddressByHash(hNtdll, HASH_FUNC_RTLZEROMEMORY);
        pProcs->lpRtlZeroMemory                 = reinterpret_cast<LPPROC_RTLZEROMEMORY>(pRtlZeroMemory);

        // WINAPI (Kernel32)
        PVOID pCheckRemoteDebuggerPresent       = GetProcAddressByHash(hKernel32, HASH_FUNC_CHECKREMOTEDEBUGGERPRESENT);
        pProcs->lpCheckRemoteDebuggerPresent    = reinterpret_cast<LPPROC_CHECKREMOTEDEBUGGERPRESENT>(pCheckRemoteDebuggerPresent);
        PVOID pCloseHandle                      = GetProcAddressByHash(hKernel32, HASH_FUNC_CLOSEHANDLE);
        pProcs->lpCloseHandle                   = reinterpret_cast<LPPROC_CLOSEHANDLE>(pCloseHandle);
        PVOID pCreateFileW                      = GetProcAddressByHash(hKernel32, HASH_FUNC_CREATEFILEW);
        pProcs->lpCreateFileW                   = reinterpret_cast<LPPROC_CREATEFILEW>(pCreateFileW);
        PVOID pCreatePipe                       = GetProcAddressByHash(hKernel32, HASH_FUNC_CREATEPIPE);
        pProcs->lpCreatePipe                    = reinterpret_cast<LPPROC_CREATEPIPE>(pCreatePipe);
        PVOID pCreateProcessW                   = GetProcAddressByHash(hKernel32, HASH_FUNC_CREATEPROCESSW);
        pProcs->lpCreateProcessW                = reinterpret_cast<LPPROC_CREATEPROCESSW>(pCreateProcessW);
        PVOID pCreateProcessWithLogonW          = GetProcAddressByHash(hKernel32, HASH_FUNC_CREATEPROCESSWITHLOGONW);
        pProcs->lpCreateProcessWithLogonW       = reinterpret_cast<LPPROC_CREATEPROCESSWITHLOGONW>(pCreateProcessWithLogonW);
        PVOID pCreateRemoteThreadEx             = GetProcAddressByHash(hKernel32, HASH_FUNC_CREATEREMOTETHREADEX);
        pProcs->lpCreateRemoteThreadEx          = reinterpret_cast<LPPROC_CREATEREMOTETHREADEX>(pCreateRemoteThreadEx);
        PVOID pDeleteFileW                      = GetProcAddressByHash(hKernel32, HASH_FUNC_DELETEFILEW);
        pProcs->lpDeleteFileW                   = reinterpret_cast<LPPROC_DELETEFILEW>(pDeleteFileW);
        PVOID pExpandEnvironmentStringsW        = GetProcAddressByHash(hKernel32, HASH_FUNC_EXPANDENVIRONMENTSTRINGSW);
        pProcs->lpExpandEnvironmentStringsW     = reinterpret_cast<LPPROC_EXPANDENVIRONMENTSTRINGSW>(pExpandEnvironmentStringsW);
        PVOID pFreeEnvironmentStringsW          = GetProcAddressByHash(hKernel32, HASH_FUNC_FREEENVIRONMENTSTRINGSW);
        pProcs->lpFreeEnvironmentStringsW       = reinterpret_cast<LPPROC_FREEENVIRONMENTSTRINGSW>(pFreeEnvironmentStringsW);
        PVOID pFindClose                        = GetProcAddressByHash(hKernel32, HASH_FUNC_FINDCLOSE);
        pProcs->lpFindClose                     = reinterpret_cast<LPPROC_FINDCLOSE>(pFindClose);
        PVOID pFindFirstFileW                   = GetProcAddressByHash(hKernel32, HASH_FUNC_FINDFIRSTFILEW);
        pProcs->lpFindFirstFileW                = reinterpret_cast<LPPROC_FINDFIRSTFILEW>(pFindFirstFileW);
        PVOID pFindNextFileW                    = GetProcAddressByHash(hKernel32, HASH_FUNC_FINDNEXTFILEW);
        pProcs->lpFindNextFileW                 = reinterpret_cast<LPPROC_FINDNEXTFILEW>(pFindNextFileW);
        PVOID pFormatMessage                    = GetProcAddressByHash(hKernel32, HASH_FUNC_FORMATMESSAGE);
        pProcs->lpFormatMessage                 = reinterpret_cast<LPPROC_FORMATMESSAGE>(pFormatMessage);
        PVOID pFreeLibrary                      = GetProcAddressByHash(hKernel32, HASH_FUNC_FREELIBRARY);
        pProcs->lpFreeLibrary                   = reinterpret_cast<LPPROC_FREELIBRARY>(pFreeLibrary);
        PVOID pGetComputerNameW                 = GetProcAddressByHash(hKernel32, HASH_FUNC_GETCOMPUTERNAMEW);
        pProcs->lpGetComputerNameW              = reinterpret_cast<LPPROC_GETCOMPUTERNAMEW>(pGetComputerNameW);
        PVOID pGetEnvironmentStringsW           = GetProcAddressByHash(hKernel32, HASH_FUNC_GETENVIRONMENTSTRINGSW);
        pProcs->lpGetEnvironmentStringsW        = reinterpret_cast<LPPROC_GETENVIRONMENTSTRINGSW>(pGetEnvironmentStringsW);
        PVOID pGetLastError                     = GetProcAddressByHash(hKernel32, HASH_FUNC_GETLASTERROR);
        pProcs->lpGetLastError                  = reinterpret_cast<LPPROC_GETLASTERROR>(pGetLastError);
        PVOID pGetModuleFileNameW               = GetProcAddressByHash(hKernel32, HASH_FUNC_GETMODULEFILENAMEW);
        pProcs->lpGetModuleFileNameW            = reinterpret_cast<LPPROC_GETMODULEFILENAMEW>(pGetModuleFileNameW);
        PVOID pGetModuleHandleA                 = GetProcAddressByHash(hKernel32, HASH_FUNC_GETMODULEHANDLEA);
        pProcs->lpGetModuleHandleA              = reinterpret_cast<LPPROC_GETMODULEHANDLEA>(pGetModuleHandleA);
        PVOID pGetProcAddress                   = GetProcAddressByHash(hKernel32, HASH_FUNC_GETPROCADDRESS);
        pProcs->lpGetProcAddress                = reinterpret_cast<LPPROC_GETPROCADDRESS>(pGetProcAddress);
        PVOID pGetProcessHeap                   = GetProcAddressByHash(hKernel32, HASH_FUNC_GETPROCESSHEAP);
        pProcs->lpGetProcessHeap                = reinterpret_cast<LPPROC_GETPROCESSHEAP>(pGetProcessHeap);
        PVOID pGetProcessImageFileNameW         = GetProcAddressByHash(hKernel32, HASH_FUNC_GETPROCESSIMAGEFILENAMEW);
        pProcs->lpGetProcessImageFileNameW      = reinterpret_cast<LPPROC_GETPROCESSIMAGEFILENAMEW>(pGetProcessImageFileNameW);
        PVOID pGetSystemDirectoryW              = GetProcAddressByHash(hKernel32, HASH_FUNC_GETSYSTEMDIRECTORYW);
        pProcs->lpGetSystemDirectoryW           = reinterpret_cast<LPPROC_GETSYSTEMDIRECTORYW>(pGetSystemDirectoryW);
        PVOID pGetSystemInfo                    = GetProcAddressByHash(hKernel32, HASH_FUNC_GETSYSTEMINFO);
        pProcs->lpGetSystemInfo                 = reinterpret_cast<LPPROC_GETSYSTEMINFO>(pGetSystemInfo);
        PVOID pGetSystemTime                    = GetProcAddressByHash(hKernel32, HASH_FUNC_GETSYSTEMTIME);
        pProcs->lpGetSystemTime                 = reinterpret_cast<LPPROC_GETSYSTEMTIME>(pGetSystemTime);
        PVOID pGlobalAlloc                      = GetProcAddressByHash(hKernel32, HASH_FUNC_GLOBALALLOC);
        pProcs->lpGlobalAlloc                   = reinterpret_cast<LPPROC_GLOBALALLOC>(pGlobalAlloc);
        PVOID pGlobalFree                       = GetProcAddressByHash(hKernel32, HASH_FUNC_GLOBALFREE);
        pProcs->lpGlobalFree                    = reinterpret_cast<LPPROC_GLOBALFREE>(pGlobalFree);
        PVOID pHeapAlloc                        = GetProcAddressByHash(hKernel32, HASH_FUNC_HEAPALLOC);
        pProcs->lpHeapAlloc                     = reinterpret_cast<LPPROC_HEAPALLOC>(pHeapAlloc);
        PVOID pHeapFree                         = GetProcAddressByHash(hKernel32, HASH_FUNC_HEAPFREE);
        pProcs->lpHeapFree                      = reinterpret_cast<LPPROC_HEAPFREE>(pHeapFree);
        PVOID pLoadLibraryA                     = GetProcAddressByHash(hKernel32, HASH_FUNC_LOADLIBRARYA);
        pProcs->lpLoadLibraryA                  = reinterpret_cast<LPPROC_LOADLIBRARYA>(pLoadLibraryA);
        PVOID pLoadLibraryW                     = GetProcAddressByHash(hKernel32, HASH_FUNC_LOADLIBRARYW);
        pProcs->lpLoadLibraryW                  = reinterpret_cast<LPPROC_LOADLIBRARYW>(pLoadLibraryW);
        PVOID pLocalAlloc                       = GetProcAddressByHash(hKernel32, HASH_FUNC_LOCALALLOC);
        pProcs->lpLocalAlloc                    = reinterpret_cast<LPPROC_LOCALALLOC>(pLocalAlloc);
        PVOID pLocalFree                        = GetProcAddressByHash(hKernel32, HASH_FUNC_LOCALFREE);
        pProcs->lpLocalFree                     = reinterpret_cast<LPPROC_LOCALFREE>(pLocalFree);
        PVOID pIsDebuggerPresent                = GetProcAddressByHash(hKernel32, HASH_FUNC_ISDEBUGGERPRESENT);
        pProcs->lpIsDebuggerPresent             = reinterpret_cast<LPPROC_ISDEBUGGERPRESENT>(pIsDebuggerPresent);
        PVOID pMoveFileW                        = GetProcAddressByHash(hKernel32, HASH_FUNC_MOVEFILEW);
        pProcs->lpMoveFileW                     = reinterpret_cast<LPPROC_MOVEFILEW>(pMoveFileW);
        PVOID pOpenProcess                      = GetProcAddressByHash(hKernel32, HASH_FUNC_OPENPROCESS);
        pProcs->lpOpenProcess                   = reinterpret_cast<LPPROC_OPENPROCESS>(pOpenProcess);
        PVOID pQueryFullProcessImageNameW       = GetProcAddressByHash(hKernel32, HASH_FUNC_QUERYFULLPROCESSIMAGENAMEW);
        pProcs->lpQueryFullProcessImageNameW    = reinterpret_cast<LPPROC_QUERYFULLPROCESSIMAGENAMEW>(pQueryFullProcessImageNameW);
        PVOID pReadFile                         = GetProcAddressByHash(hKernel32, HASH_FUNC_READFILE);
        pProcs->lpReadFile                      = reinterpret_cast<LPPROC_READFILE>(pReadFile);
        PVOID pReadProcessMemory                = GetProcAddressByHash(hKernel32, HASH_FUNC_READPROCESSMEMORY);
        pProcs->lpReadProcessMemory             = reinterpret_cast<LPPROC_READPROCESSMEMORY>(pReadProcessMemory);
        PVOID pRemoveDirectoryW                 = GetProcAddressByHash(hKernel32, HASH_FUNC_REMOVEDIRECTORYW);
        pProcs->lpRemoveDirectoryW              = reinterpret_cast<LPPROC_REMOVEDIRECTORYW>(pRemoveDirectoryW);
        PVOID pRtlCopyMemory                    = GetProcAddressByHash(hKernel32, HASH_FUNC_RTLCOPYMEMORY);
        pProcs->lpRtlCopyMemory                 = reinterpret_cast<LPPROC_RTLCOPYMEMORY>(pRtlCopyMemory);
        PVOID pSetFileInformationByHandle       = GetProcAddressByHash(hKernel32, HASH_FUNC_SETFILEINFORMATIONBYHANDLE);
        pProcs->lpSetFileInformationByHandle    = reinterpret_cast<LPPROC_SETFILEINFORMATIONBYHANDLE>(pSetFileInformationByHandle);
        PVOID pSetHandleInformation             = GetProcAddressByHash(hKernel32, HASH_FUNC_SETHANDLEINFORMATION);
        pProcs->lpSetHandleInformation          = reinterpret_cast<LPPROC_SETHANDLEINFORMATION>(pSetHandleInformation);
        PVOID pSetThreadContext                 = GetProcAddressByHash(hKernel32, HASH_FUNC_SETTHREADCONTEXT);
        pProcs->lpSetThreadContext              = reinterpret_cast<LPPROC_SETTHREADCONTEXT>(pSetThreadContext);
        PVOID pSystemTimeToFileTime             = GetProcAddressByHash(hKernel32, HASH_FUNC_SYSTEMTIMETOFILETIME);
        pProcs->lpSystemTimeToFileTime          = reinterpret_cast<LPPROC_SYSTEMTIMETOFILETIME>(pSystemTimeToFileTime);
        PVOID pTerminateProcess                 = GetProcAddressByHash(hKernel32, HASH_FUNC_TERMINATEPROCESS);
        pProcs->lpTerminateProcess              = reinterpret_cast<LPPROC_TERMINATEPROCESS>(pTerminateProcess);
        PVOID pVirtualAllocEx                   = GetProcAddressByHash(hKernel32, HASH_FUNC_VIRTUALALLOCEX);
        pProcs->lpVirtualAllocEx                = reinterpret_cast<LPPROC_VIRTUALALLOCEX>(pVirtualAllocEx);
        PVOID pVirtualFree                      = GetProcAddressByHash(hKernel32, HASH_FUNC_VIRTUALFREE);
        pProcs->lpVirtualFree                   = reinterpret_cast<LPPROC_VIRTUALFREE>(pVirtualFree);
        PVOID pVirtualProtect                   = GetProcAddressByHash(hKernel32, HASH_FUNC_VIRTUALPROTECT);
        pProcs->lpVirtualProtect                = reinterpret_cast<LPPROC_VIRTUALPROTECT>(pVirtualProtect);
        PVOID pVirtualProtectEx                 = GetProcAddressByHash(hKernel32, HASH_FUNC_VIRTUALPROTECTEX);
        pProcs->lpVirtualProtectEx              = reinterpret_cast<LPPROC_VIRTUALPROTECTEX>(pVirtualProtectEx);
        PVOID pWriteProcessMemory               = GetProcAddressByHash(hKernel32, HASH_FUNC_WRITEPROCESSMEMORY);
        pProcs->lpWriteProcessMemory            = reinterpret_cast<LPPROC_WRITEPROCESSMEMORY>(pWriteProcessMemory);

        if (bIndirectSyscalls)
        {
            pProcs->sysEtwEventWrite                = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pEtwEventWrite));
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
            pProcs->sysNtFlushInstructionCache      = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtFlushInstructionCache));
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
            pProcs->sysNtTerminateProcess           = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtTerminateProcess));
            pProcs->sysNtTraceEvent                 = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtTraceEvent));
            pProcs->sysNtUnmapViewOfSection         = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtUnmapViewOfSection));
            pProcs->sysNtWaitForSingleObject        = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtWaitForSingleObject));
            pProcs->sysNtWriteFile                  = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtWriteFile));
            pProcs->sysNtWriteVirtualMemory         = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtWriteVirtualMemory));
            pProcs->sysRtlAllocateHeap              = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pRtlAllocateHeap));
            pProcs->sysRtlGetCurrentDirectory_U     = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pRtlGetCurrentDirectory_U));
            pProcs->sysRtlGetFullPathName_U         = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pRtlGetFullPathName_U));
            pProcs->sysRtlInitUnicodeString         = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pRtlInitUnicodeString));          
            pProcs->sysRtlSetCurrentDirectory_U     = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pRtlSetCurrentDirectory_U));
        }
    }

    VOID FindProcsMisc(
        Procs::PPROCS pProcs,
        HMODULE hAdvapi32,
        HMODULE hAmsi,
        HMODULE hBcrypt,
        HMODULE hCrypt32,
        HMODULE hDbghelp,
        HMODULE hIphlpapi,
        HMODULE hNetapi32,
        HMODULE hShell32,
        HMODULE hUser32,
        HMODULE hWinHttp,
        HMODULE hWs2_32
    ) {
        // Advapi32
        PVOID pAdjustTokenPrivileges            = GetProcAddressByHash(hAdvapi32, HASH_FUNC_ADJUSTTOKENPRIVILEGES);
        pProcs->lpAdjustTokenPrivileges         = reinterpret_cast<LPPROC_ADJUSTTOKENPRIVILEGES>(pAdjustTokenPrivileges);
        PVOID pCreateProcessWithTokenW          = GetProcAddressByHash(hAdvapi32, HASH_FUNC_CREATEPROCESSWITHTOKENW);
        pProcs->lpCreateProcessWithTokenW       = reinterpret_cast<LPPROC_CREATEPROCESSWITHTOKENW>(pCreateProcessWithTokenW);
        PVOID pDuplicateTokenEx                 = GetProcAddressByHash(hAdvapi32, HASH_FUNC_DUPLICATETOKENEX);
        pProcs->lpDuplicateTokenEx              = reinterpret_cast<LPPROC_DUPLICATETOKENEX>(pDuplicateTokenEx);
        PVOID pGetTokenInformation              = GetProcAddressByHash(hAdvapi32, HASH_FUNC_GETTOKENINFORMATION);
        pProcs->lpGetTokenInformation           = reinterpret_cast<LPPROC_GETTOKENINFORMATION>(pGetTokenInformation);
        PVOID pGetUserNameW                     = GetProcAddressByHash(hAdvapi32, HASH_FUNC_GETUSERNAMEW);
        pProcs->lpGetUserNameW                  = reinterpret_cast<LPPROC_GETUSERNAMEW>(pGetUserNameW);
        PVOID pImpersonateLoggedOnUser          = GetProcAddressByHash(hAdvapi32, HASH_FUNC_IMPERSONATELOGGEDONUSER);
        pProcs->lpImpersonateLoggedOnUser       = reinterpret_cast<LPPROC_IMPERSONATELOGGEDONUSER>(pImpersonateLoggedOnUser);
        PVOID pLookupPrivilegeNameW             = GetProcAddressByHash(hAdvapi32, HASH_FUNC_LOOKUPPRIVILEGENAMEW);
        pProcs->lpLookupPrivilegeNameW          = reinterpret_cast<LPPROC_LOOKUPPRIVILEGENAMEW>(pLookupPrivilegeNameW);
        PVOID pLookupPrivilegeValueW            = GetProcAddressByHash(hAdvapi32, HASH_FUNC_LOOKUPPRIVILEGEVALUEW);
        pProcs->lpLookupPrivilegeValueW         = reinterpret_cast<LPPROC_LOOKUPPRIVILEGEVALUEW>(pLookupPrivilegeValueW);
        PVOID pOpenProcessToken                 = GetProcAddressByHash(hAdvapi32, HASH_FUNC_OPENPROCESSTOKEN);
        pProcs->lpOpenProcessToken              = reinterpret_cast<LPPROC_OPENPROCESSTOKEN>(pOpenProcessToken);
        PVOID pPrivilegeCheck                   = GetProcAddressByHash(hAdvapi32, HASH_FUNC_PRIVILEGECHECK);
        pProcs->lpPrivilegeCheck                = reinterpret_cast<LPPROC_PRIVILEGECHECK>(pPrivilegeCheck);
        PVOID pRegCloseKey                      = GetProcAddressByHash(hAdvapi32, HASH_FUNC_REGCLOSEKEY);
        pProcs->lpRegCloseKey                   = reinterpret_cast<LPPROC_REGCLOSEKEY>(pRegCloseKey);
        PVOID pRegCreateKeyExW                  = GetProcAddressByHash(hAdvapi32, HASH_FUNC_REGCREATEKEYEXW);
        pProcs->lpRegCreateKeyExW               = reinterpret_cast<LPPROC_REGCREATEKEYEXW>(pRegCreateKeyExW);
        PVOID pRegEnumKeyExW                    = GetProcAddressByHash(hAdvapi32, HASH_FUNC_REGENUMKEYEXW);
        pProcs->lpRegEnumKeyExW                 = reinterpret_cast<LPPROC_REGENUMKEYEXW>(pRegEnumKeyExW);
        PVOID pRegEnumValueW                    = GetProcAddressByHash(hAdvapi32, HASH_FUNC_REGENUMVALUEW);
        pProcs->lpRegEnumValueW                 = reinterpret_cast<LPPROC_REGENUMVALUEW>(pRegEnumValueW);
        PVOID pRegOpenKeyExW                    = GetProcAddressByHash(hAdvapi32, HASH_FUNC_REGOPENKEYEXW);
        pProcs->lpRegOpenKeyExW                 = reinterpret_cast<LPPROC_REGOPENKEYEXW>(pRegOpenKeyExW);
        PVOID pRegQueryInfoKeyW                 = GetProcAddressByHash(hAdvapi32, HASH_FUNC_REGQUERYINFOKEYW);
        pProcs->lpRegQueryInfoKeyW              = reinterpret_cast<LPPROC_REGQUERYINFOKEYW>(pRegQueryInfoKeyW);
        PVOID pRegSaveKeyW                      = GetProcAddressByHash(hAdvapi32, HASH_FUNC_REGSAVEKEYW);
        pProcs->lpRegSaveKeyW                   = reinterpret_cast<LPPROC_REGSAVEKEYW>(pRegSaveKeyW);
        PVOID pRegSetValueExW                   = GetProcAddressByHash(hAdvapi32, HASH_FUNC_REGSETVALUEEXW);
        pProcs->lpRegSetValueExW                = reinterpret_cast<LPPROC_REGSETVALUEEXW>(pRegSetValueExW);
        PVOID pRevertToSelf                     = GetProcAddressByHash(hAdvapi32, HASH_FUNC_REVERTTOSELF);
        pProcs->lpRevertToSelf                  = reinterpret_cast<LPPROC_REVERTTOSELF>(pRevertToSelf);

        // Amsi
        PVOID pAmsiScanBuffer                   = GetProcAddressByHash(hAmsi, HASH_FUNC_AMSISCANBUFFER);
        pProcs->lpAmsiScanBuffer                = reinterpret_cast<LPPROC_AMSISCANBUFFER>(pAmsiScanBuffer);

        // Bcrypt
        PVOID pBCryptCloseAlgorithmProvider     = GetProcAddressByHash(hBcrypt, HASH_FUNC_BCRYPTCLOSEALGORITHMPROVIDER);
        pProcs->lpBCryptCloseAlgorithmProvider  = reinterpret_cast<LPPROC_BCRYPTCLOSEALGORITHMPROVIDER>(pBCryptCloseAlgorithmProvider);
        PVOID pBCryptDecrypt                    = GetProcAddressByHash(hBcrypt, HASH_FUNC_BCRYPTDECRYPT);
        pProcs->lpBCryptDecrypt                 = reinterpret_cast<LPPROC_BCRYPTDECRYPT>(pBCryptDecrypt);
        PVOID pBCryptDestroyKey                 = GetProcAddressByHash(hBcrypt, HASH_FUNC_BCRYPTDESTROYKEY);
        pProcs->lpBCryptDestroyKey              = reinterpret_cast<LPPROC_BCRYPTDESTROYKEY>(pBCryptDestroyKey);
        PVOID pBCryptEncrypt                    = GetProcAddressByHash(hBcrypt, HASH_FUNC_BCRYPTENCRYPT);
        pProcs->lpBCryptEncrypt                 = reinterpret_cast<LPPROC_BCRYPTENCRYPT>(pBCryptEncrypt);
        PVOID pBCryptGenerateSymmetricKey       = GetProcAddressByHash(hBcrypt, HASH_FUNC_BCRYPTGENERATESYMMETRICKEY);
        pProcs->lpBCryptGenerateSymmetricKey    = reinterpret_cast<LPPROC_BCRYPTGENERATESYMMETRICKEY>(pBCryptGenerateSymmetricKey);
        PVOID pBCryptGetProperty                = GetProcAddressByHash(hBcrypt, HASH_FUNC_BCRYPTGETPROPERTY);
        pProcs->lpBCryptGetProperty             = reinterpret_cast<LPPROC_BCRYPTGETPROPERTY>(pBCryptGetProperty);
        PVOID pBCryptOpenAlgorithmProvider      = GetProcAddressByHash(hBcrypt, HASH_FUNC_BCRYPTOPENALGORITHMPROVIDER);
        pProcs->lpBCryptOpenAlgorithmProvider   = reinterpret_cast<LPPROC_BCRYPTOPENALGORITHMPROVIDER>(pBCryptOpenAlgorithmProvider);
        PVOID pBCryptSetProperty                = GetProcAddressByHash(hBcrypt, HASH_FUNC_BCRYPTSETPROPERTY);
        pProcs->lpBCryptSetProperty             = reinterpret_cast<LPPROC_BCRYPTSETPROPERTY>(pBCryptSetProperty);

        // Crypt32
        PVOID pCryptBinaryToStringW             = GetProcAddressByHash(hCrypt32, HASH_FUNC_CRYPTBINARYTOSTRINGW);
        pProcs->lpCryptBinaryToStringW          = reinterpret_cast<LPPROC_CRYPTBINARYTOSTRINGW>(pCryptBinaryToStringW);
        PVOID pCryptStringToBinaryW             = GetProcAddressByHash(hCrypt32, HASH_FUNC_CRYPTSTRINGTOBINARYW);
        pProcs->lpCryptStringToBinaryW          = reinterpret_cast<LPPROC_CRYPTSTRINGTOBINARYW>(pCryptStringToBinaryW);

        // Dbghelp
        PVOID pMiniDumpWriteDump                = GetProcAddressByHash(hDbghelp, HASH_FUNC_MINIDUMPWRITEDUMP);
        pProcs->lpMiniDumpWriteDump             = reinterpret_cast<LPPROC_MINIDUMPWRITEDUMP>(pMiniDumpWriteDump);

        // Iphlpapi
        PVOID pGetAdaptersAddresses             = GetProcAddressByHash(hIphlpapi, HASH_FUNC_GETADAPTERSADDRESSES);
        pProcs->lpGetAdaptersAddresses          = reinterpret_cast<LPPROC_GETADAPTERSADDRESSES>(pGetAdaptersAddresses);
        PVOID pGetTcpTable                      = GetProcAddressByHash(hIphlpapi, HASH_FUNC_GETTCPTABLE);
        pProcs->lpGetTcpTable                   = reinterpret_cast<LPPROC_GETTCPTABLE>(pGetTcpTable);

        // Netapi32
        PVOID pNetApiBufferFree                 = GetProcAddressByHash(hNetapi32, HASH_FUNC_NETAPIBUFFERFREE);
        pProcs->lpNetApiBufferFree              = reinterpret_cast<LPPROC_NETAPIBUFFERFREE>(pNetApiBufferFree);
        PVOID pNetLocalGroupEnum                = GetProcAddressByHash(hNetapi32, HASH_FUNC_NETLOCALGROUPENUM);
        pProcs->lpNetLocalGroupEnum             = reinterpret_cast<LPPROC_NETLOCALGROUPENUM>(pNetLocalGroupEnum);
        PVOID pNetUserEnum                      = GetProcAddressByHash(hNetapi32, HASH_FUNC_NETUSERENUM);
        pProcs->lpNetUserEnum                   = reinterpret_cast<LPPROC_NETUSERENUM>(pNetUserEnum);

        // Shell32
        PVOID pShellExecuteExW                  = GetProcAddressByHash(hShell32, HASH_FUNC_SHELLEXECUTEEXW);
        pProcs->lpShellExecuteExW               = reinterpret_cast<LPPROC_SHELLEXECUTEEXW>(pShellExecuteExW);

        // User32
        PVOID pCreateWindowExW                  = GetProcAddressByHash(hUser32, HASH_FUNC_CREATEWINDOWEXW);
        pProcs->lpCreateWindowExW               = reinterpret_cast<LPPROC_CREATEWINDOWEXW>(pCreateWindowExW);
        // PVOID pDispatchMessage                  = GetProcAddressByHash(hUser32, HASH_FUNC_DISPATCHMESSAGE);
        // pProcs->lpDispatchMessage               = reinterpret_cast<LPPROC_DISPATCHMESSAGE>(pDispatchMessage);
        PVOID pGetForegroundWindow              = GetProcAddressByHash(hUser32, HASH_FUNC_GETFOREGROUNDWINDOW);
        pProcs->lpGetForegroundWindow           = reinterpret_cast<LPPROC_GETFOREGROUNDWINDOW>(pGetForegroundWindow);
        // PVOID pGetMessage                       = GetProcAddressByHash(hUser32, HASH_FUNC_GETMESSAGE);
        // pProcs->lpGetMessage                    = reinterpret_cast<LPPROC_GETMESSAGE>(pGetMessage);
        PVOID pGetSystemMetrics                 = GetProcAddressByHash(hUser32, HASH_FUNC_GETSYSTEMMETRICS);
        pProcs->lpGetSystemMetrics              = reinterpret_cast<LPPROC_GETSYSTEMMETRICS>(pGetSystemMetrics);
        PVOID pLoadAcceleratorsW                = GetProcAddressByHash(hUser32, HASH_FUNC_LOADACCELERATORSW);
        pProcs->lpLoadAcceleratorsW             = reinterpret_cast<LPPROC_LOADACCELERATORSW>(pLoadAcceleratorsW);
        PVOID pLoadCursorW                      = GetProcAddressByHash(hUser32, HASH_FUNC_LOADCURSORW);
        pProcs->lpLoadCursorW                   = reinterpret_cast<LPPROC_LOADCURSORW>(pLoadCursorW);
        PVOID pLoadIconW                        = GetProcAddressByHash(hUser32, HASH_FUNC_LOADICONW);
        pProcs->lpLoadIconW                     = reinterpret_cast<LPPROC_LOADICONW>(pLoadIconW);
        PVOID pRegisterClassExW                 = GetProcAddressByHash(hUser32, HASH_FUNC_REGISTERCLASSEXW);
        pProcs->lpRegisterClassExW              = reinterpret_cast<LPPROC_REGISTERCLASSEXW>(pRegisterClassExW);
        PVOID pShowWindow                       = GetProcAddressByHash(hUser32, HASH_FUNC_SHOWWINDOW);
        pProcs->lpShowWindow                    = reinterpret_cast<LPPROC_SHOWWINDOW>(pShowWindow);
        PVOID pTranslateAcceleratorW            = GetProcAddressByHash(hUser32, HASH_FUNC_TRANSLATEACCELERATORW);
        pProcs->lpTranslateAcceleratorW         = reinterpret_cast<LPPROC_TRANSLATEACCELERATORW>(pTranslateAcceleratorW);
        PVOID pTranslateMessage                 = GetProcAddressByHash(hUser32, HASH_FUNC_TRANSLATEMESSAGE);
        pProcs->lpTranslateMessage              = reinterpret_cast<LPPROC_TRANSLATEMESSAGE>(pTranslateMessage);
        PVOID pUpdateWindow                     = GetProcAddressByHash(hUser32, HASH_FUNC_UPDATEWINDOW);
        pProcs->lpUpdateWindow                  = reinterpret_cast<LPPROC_UPDATEWINDOW>(pUpdateWindow);

        // WinHttp
        PVOID pWinHttpCloseHandle               = GetProcAddressByHash(hWinHttp, HASH_FUNC_WINHTTPCLOSEHANDLE);
        pProcs->lpWinHttpCloseHandle            = reinterpret_cast<LPPROC_WINHTTPCLOSEHANDLE>(pWinHttpCloseHandle);
        PVOID pWinHttpConnect                   = GetProcAddressByHash(hWinHttp, HASH_FUNC_WINHTTPCONNECT);
        pProcs->lpWinHttpConnect                = reinterpret_cast<LPPROC_WINHTTPCONNECT>(pWinHttpConnect);
        PVOID pWinHttpOpen                      = GetProcAddressByHash(hWinHttp, HASH_FUNC_WINHTTPOPEN);
        pProcs->lpWinHttpOpen                   = reinterpret_cast<LPPROC_WINHTTPOPEN>(pWinHttpOpen);
        PVOID pWinHttpOpenRequest               = GetProcAddressByHash(hWinHttp, HASH_FUNC_WINHTTPOPENREQUEST);
        pProcs->lpWinHttpOpenRequest            = reinterpret_cast<LPPROC_WINHTTPOPENREQUEST>(pWinHttpOpenRequest);
        PVOID pWinHttpQueryDataAvailable        = GetProcAddressByHash(hWinHttp, HASH_FUNC_WINHTTPQUERYDATAAVAILABLE);
        pProcs->lpWinHttpQueryDataAvailable     = reinterpret_cast<LPPROC_WINHTTPQUERYDATAAVAILABLE>(pWinHttpQueryDataAvailable);
        PVOID pWinHttpQueryHeaders              = GetProcAddressByHash(hWinHttp, HASH_FUNC_WINHTTPQUERYHEADERS);
        pProcs->lpWinHttpQueryHeaders           = reinterpret_cast<LPPROC_WINHTTPQUERYHEADERS>(pWinHttpQueryHeaders);
        PVOID pWinHttpReceiveResponse           = GetProcAddressByHash(hWinHttp, HASH_FUNC_WINHTTPRECEIVERESPONSE);
        pProcs->lpWinHttpReceiveResponse        = reinterpret_cast<LPPROC_WINHTTPRECEIVERESPONSE>(pWinHttpReceiveResponse);
        PVOID pWinHttpReadData                  = GetProcAddressByHash(hWinHttp, HASH_FUNC_WINHTTPREADDATA);
        pProcs->lpWinHttpReadData               = reinterpret_cast<LPPROC_WINHTTPREADDATA>(pWinHttpReadData);
        PVOID pWinHttpSendRequest               = GetProcAddressByHash(hWinHttp, HASH_FUNC_WINHTTPSENDREQUEST);
        pProcs->lpWinHttpSendRequest            = reinterpret_cast<LPPROC_WINHTTPSENDREQUEST>(pWinHttpSendRequest);
        PVOID pWinHttpSetOption                 = GetProcAddressByHash(hWinHttp, HASH_FUNC_WINHTTPSETOPTION);
        pProcs->lpWinHttpSetOption              = reinterpret_cast<LPPROC_WINHTTPSETOPTION>(pWinHttpSetOption);
        PVOID pWinHttpWriteData                 = GetProcAddressByHash(hWinHttp, HASH_FUNC_WINHTTPWRITEDATA);
        pProcs->lpWinHttpWriteData              = reinterpret_cast<LPPROC_WINHTTPWRITEDATA>(pWinHttpWriteData);

        // Ws2_32
        PVOID pWSACleanup                       = GetProcAddressByHash(hWs2_32, HASH_FUNC_WSACLEANUP);
        pProcs->lpWSACleanup                    = reinterpret_cast<LPPROC_WSACLEANUP>(pWSACleanup);
        PVOID pWSAStartup                       = GetProcAddressByHash(hWs2_32, HASH_FUNC_WSASTARTUP);
        pProcs->lpWSAStartup                    = reinterpret_cast<LPPROC_WSASTARTUP>(pWSAStartup);
    }
}
