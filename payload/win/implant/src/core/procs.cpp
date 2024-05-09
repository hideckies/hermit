#include "core/procs.hpp"

namespace Procs
{
    DWORD GetHashFromString(char* str)
    {
        size_t dwStringLength = strlen(str);
        DWORD dwHash = HASH_IV;

        for (size_t i = 0; i < dwStringLength; i++)
        {
            dwHash = dwHash * RANDOM_ADDR + static_cast<int>(str[i]);
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

        DWORD_PTR dwpExportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

        PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)hModule + dwpExportDirRVA);

        PDWORD pdwAddrOfFuncsRVA = (PDWORD)((DWORD_PTR)hModule + pExportDir->AddressOfFunctions);
        PDWORD pdwAddrOfNamesRVA = (PDWORD)((DWORD_PTR)hModule + pExportDir->AddressOfNames);
        PWORD pdwAddrOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)hModule + pExportDir->AddressOfNameOrdinals);

        for (DWORD i = 0; i < pExportDir->NumberOfFunctions; i++)
        {
            DWORD dwFuncNameRVA = pdwAddrOfNamesRVA[i];
            DWORD_PTR dwpFuncNameRVA = (DWORD_PTR)hModule + dwFuncNameRVA;
            char* sFuncName = (char*)dwpFuncNameRVA;
            DWORD_PTR dwpFuncAddrRVA = 0;

            DWORD dwFuncNameHash = GetHashFromString(sFuncName);
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
        HMODULE hWinHTTPDLL,
        BOOL    bIndirectSyscalls
    ) {
        PPROCS pProcs = new PROCS;
    
        // NT APIs
        PVOID pNtCreateProcessEx                = GetProcAddressByHash(hNTDLL, APIHASH_NTCREATEPROCESSEX);
        pProcs->lpNtCreateProcessEx             = reinterpret_cast<LPPROC_NTCREATEPROCESSEX>(pNtCreateProcessEx);
        PVOID pNtOpenProcess                    = GetProcAddressByHash(hNTDLL, APIHASH_NTOPENPROCESS);
        pProcs->lpNtOpenProcess                 = reinterpret_cast<LPPROC_NTOPENPROCESS>(pNtOpenProcess);
        PVOID pNtOpenProcessToken               = GetProcAddressByHash(hNTDLL, APIHASH_NTOPENPROCESSTOKEN);
        pProcs->lpNtOpenProcessToken            = reinterpret_cast<LPPROC_NTOPENPROCESSTOKEN>(pNtOpenProcessToken);
        PVOID pNtTerminateProcess               = GetProcAddressByHash(hNTDLL, APIHASH_NTTERMINATEPROCESS);
        pProcs->lpNtTerminateProcess            = reinterpret_cast<LPPROC_NTTERMINATEPROCESS>(pNtTerminateProcess);
        PVOID pNtQueryInformationProcess        = GetProcAddressByHash(hNTDLL, APIHASH_NTQUERYINFORMATIONPROCESS);
        pProcs->lpNtQueryInformationProcess     = reinterpret_cast<LPPROC_NTQUERYINFORMATIONPROCESS>(pNtQueryInformationProcess);
        PVOID pNtCreateThreadEx                 = GetProcAddressByHash(hNTDLL, APIHASH_NTCREATETHREADEX);
        pProcs->lpNtCreateThreadEx              = reinterpret_cast<LPPROC_NTCREATETHREADEX>(pNtCreateThreadEx);
        PVOID pNtResumeThread                   = GetProcAddressByHash(hNTDLL, APIHASH_NTRESUMETHREAD);
        pProcs->lpNtResumeThread                = reinterpret_cast<LPPROC_NTRESUMETHREAD>(pNtResumeThread);
        PVOID pNtGetContextThread               = GetProcAddressByHash(hNTDLL, APIHASH_NTGETCONTEXTTHREAD);
        pProcs->lpNtGetContextThread            = reinterpret_cast<LPPROC_NTGETCONTEXTTHREAD>(pNtGetContextThread);
        PVOID pNtSetContextThread               = GetProcAddressByHash(hNTDLL, APIHASH_NTSETCONTEXTTHREAD);
        pProcs->lpNtSetContextThread            = reinterpret_cast<LPPROC_NTSETCONTEXTTHREAD>(pNtSetContextThread);
        PVOID pNtAllocateVirtualMemory          = GetProcAddressByHash(hNTDLL, APIHASH_NTALLOCATEVIRTUALMEMORY);
        pProcs->lpNtAllocateVirtualMemory       = reinterpret_cast<LPPROC_NTALLOCATEVIRTUALMEMORY>(pNtAllocateVirtualMemory);
        PVOID pNtReadVirtualMemory              = GetProcAddressByHash(hNTDLL, APIHASH_NTREADVIRTUALMEMORY);
        pProcs->lpNtReadVirtualMemory           = reinterpret_cast<LPPROC_NTREADVIRTUALMEMORY>(pNtReadVirtualMemory);
        PVOID pNtWriteVirtualMemory             = GetProcAddressByHash(hNTDLL, APIHASH_NTWRITEVIRTUALMEMORY);
        pProcs->lpNtWriteVirtualMemory          = reinterpret_cast<LPPROC_NTWRITEVIRTUALMEMORY>(pNtWriteVirtualMemory);
        PVOID pNtProtectVirtualMemory           = GetProcAddressByHash(hNTDLL, APIHASH_NTPROTECTVIRTUALMEMORY);
        pProcs->lpNtProtectVirtualMemory        = reinterpret_cast<LPPROC_NTPROTECTVIRTUALMEMORY>(pNtProtectVirtualMemory);
        PVOID pNtFreeVirtualMemory              = GetProcAddressByHash(hNTDLL, APIHASH_NTFREEVIRTUALMEMORY);
        pProcs->lpNtFreeVirtualMemory           = reinterpret_cast<LPPROC_NTFREEVIRTUALMEMORY>(pNtFreeVirtualMemory);
        PVOID pNtDuplicateObject                = GetProcAddressByHash(hNTDLL, APIHASH_NTDUPLICATEOBJECT);
        pProcs->lpNtDuplicateObject             = reinterpret_cast<LPPROC_NTDUPLICATEOBJECT>(pNtDuplicateObject);
        PVOID pNtWaitForSingleObject            = GetProcAddressByHash(hNTDLL, APIHASH_NTWAITFORSINGLEOBJECT);
        pProcs->lpNtWaitForSingleObject         = reinterpret_cast<LPPROC_NTWAITFORSINGLEOBJECT>(pNtWaitForSingleObject);
        PVOID pNtClose                          = GetProcAddressByHash(hNTDLL, APIHASH_NTCLOSE);
        pProcs->lpNtClose                       = reinterpret_cast<LPPROC_NTCLOSE>(pNtClose);
        PVOID pNtCreateFile                     = GetProcAddressByHash(hNTDLL, APIHASH_NTCREATEFILE);
        pProcs->lpNtCreateFile                  = reinterpret_cast<LPPROC_NTCREATEFILE>(pNtCreateFile);
        PVOID pNtOpenFile                       = GetProcAddressByHash(hNTDLL, APIHASH_NTOPENFILE);
        pProcs->lpNtOpenFile                    = reinterpret_cast<LPPROC_NTOPENFILE>(pNtOpenFile);
        PVOID pNtReadFile                       = GetProcAddressByHash(hNTDLL, APIHASH_NTREADFILE);
        pProcs->lpNtReadFile                    = reinterpret_cast<LPPROC_NTREADFILE>(pNtReadFile);
        PVOID pNtWriteFile                      = GetProcAddressByHash(hNTDLL, APIHASH_NTWRITEFILE);
        pProcs->lpNtWriteFile                   = reinterpret_cast<LPPROC_NTWRITEFILE>(pNtWriteFile);
        PVOID pNtDeleteFile                     = GetProcAddressByHash(hNTDLL, APIHASH_NTDELETEFILE);
        pProcs->lpNtDeleteFile                  = reinterpret_cast<LPPROC_NTDELETEFILE>(pNtDeleteFile);
        PVOID pNtCreateNamedPipeFile            = GetProcAddressByHash(hNTDLL, APIHASH_NTCREATENAMEDPIPEFILE);
        pProcs->lpNtCreateNamedPipeFile         = reinterpret_cast<LPPROC_NTCREATENAMEDPIPEFILE>(pNtCreateNamedPipeFile);
        PVOID pNtQueryInformationFile           = GetProcAddressByHash(hNTDLL, APIHASH_NTQUERYINFORMATIONFILE);
        pProcs->lpNtQueryInformationFile        = reinterpret_cast<LPPROC_NTSETINFORMATIONFILE>(pNtQueryInformationFile);
        PVOID pNtSetInformationFile             = GetProcAddressByHash(hNTDLL, APIHASH_NTSETINFORMATIONFILE);
        pProcs->lpNtSetInformationFile          = reinterpret_cast<LPPROC_NTSETINFORMATIONFILE>(pNtSetInformationFile);
        PVOID pNtQueryInformationToken          = GetProcAddressByHash(hNTDLL, APIHASH_NTQUERYINFORMATIONTOKEN);
        pProcs->lpNtQueryInformationToken       = reinterpret_cast<LPPROC_NTQUERYINFORMATIONTOKEN>(pNtQueryInformationToken);
        PVOID pNtQuerySystemInformation         = GetProcAddressByHash(hNTDLL, APIHASH_NTQUERYSYSTEMINFORMATION);
        pProcs->lpNtQuerySystemInformation      = reinterpret_cast<LPPROC_NTQUERYSYSTEMINFORMATION>(pNtQuerySystemInformation);
        PVOID pNtSystemDebugControl             = GetProcAddressByHash(hNTDLL, APIHASH_NTSYSTEMDEBUGCONTROL);
        pProcs->lpNtSystemDebugControl          = reinterpret_cast<LPPROC_NTSYSTEMDEBUGCONTROL>(pNtSystemDebugControl);
        PVOID pNtPrivilegeCheck                 = GetProcAddressByHash(hNTDLL, APIHASH_NTPRIVILEGECHECK);
        pProcs->lpNtPrivilegeCheck              = reinterpret_cast<LPPROC_NTPRIVILEGECHECK>(pNtPrivilegeCheck);
        PVOID pNtAdjustPrivilegesToken          = GetProcAddressByHash(hNTDLL, APIHASH_NTADJUSTPRIVILEGESTOKEN);
        pProcs->lpNtAdjustPrivilegesToken       = reinterpret_cast<LPPROC_NTADJUSTPRIVILEGESTOKEN>(pNtAdjustPrivilegesToken);
        PVOID pNtOpenKeyEx                      = GetProcAddressByHash(hNTDLL, APIHASH_NTOPENKEYEX);
        pProcs->lpNtOpenKeyEx                   = reinterpret_cast<LPPROC_NTOPENKEYEX>(pNtOpenKeyEx);
        PVOID pNtQueryKey                       = GetProcAddressByHash(hNTDLL, APIHASH_NTQUERYKEY);
        pProcs->lpNtQueryKey                    = reinterpret_cast<LPPROC_NTQUERYKEY>(pNtQueryKey);
        PVOID pNtEnumerateValueKey              = GetProcAddressByHash(hNTDLL, APIHASH_NTENUMERATEVALUEKEY);
        pProcs->lpNtEnumerateValueKey           = reinterpret_cast<LPPROC_NTENUMERATEVALUEKEY>(pNtEnumerateValueKey);
        PVOID pNtUnmapViewOfSection             = GetProcAddressByHash(hNTDLL, APIHASH_NTUNMAPVIEWOFSECTION);
        pProcs->lpNtUnmapViewOfSection          = reinterpret_cast<LPPROC_NTUNMAPVIEWOFSECTION>(pNtUnmapViewOfSection);

        // NT APIs (Runtime Library)
        PVOID pRtlAllocateHeap                  = GetProcAddressByHash(hNTDLL, APIHASH_RTLALLOCATEHEAP);
        pProcs->lpRtlAllocateHeap               = reinterpret_cast<LPPROC_RTLALLOCATEHEAP>(pRtlAllocateHeap);
        PVOID pRtlZeroMemory                    = GetProcAddressByHash(hNTDLL, APIHASH_RTLZEROMEMORY);
        pProcs->lpRtlZeroMemory                 = reinterpret_cast<LPPROC_RTLZEROMEMORY>(pRtlZeroMemory);
        PVOID pRtlInitUnicodeString             = GetProcAddressByHash(hNTDLL, APIHASH_RTLINITUNICODESTRING);
        pProcs->lpRtlInitUnicodeString          = reinterpret_cast<LPPROC_RTLINITUNICODESTRING>(pRtlInitUnicodeString);
        PVOID pRtlStringCchCatW                 = GetProcAddressByHash(hNTDLL, APIHASH_RTLSTRINGCCHCATW);
        pProcs->lpRtlStringCchCatW              = reinterpret_cast<LPPROC_RTLSTRINGCCHCATW>(pRtlStringCchCatW);
        PVOID pRtlStringCchCopyW                = GetProcAddressByHash(hNTDLL, APIHASH_RTLSTRINGCCHCOPYW);
        pProcs->lpRtlStringCchCopyW             = reinterpret_cast<LPPROC_RTLSTRINGCCHCOPYW>(pRtlStringCchCopyW);
        PVOID pRtlStringCchLengthW              = GetProcAddressByHash(hNTDLL, APIHASH_RTLSTRINGCCHLENGTHW);
        pProcs->lpRtlStringCchLengthW           = reinterpret_cast<LPPROC_RTLSTRINGCCHLENGTHW>(pRtlStringCchLengthW);
        PVOID pRtlGetCurrentDirectory_U         = GetProcAddressByHash(hNTDLL, APIHASH_RTLGETCURRENTDIRECTORY_U);
        pProcs->lpRtlGetCurrentDirectory_U      = reinterpret_cast<LPPROC_RTLGETCURRENTDIRECTORY_U>(pRtlGetCurrentDirectory_U);
        PVOID pRtlSetCurrentDirectory_U         = GetProcAddressByHash(hNTDLL, APIHASH_RTLSETCURRENTDIRECTORY_U);
        pProcs->lpRtlSetCurrentDirectory_U      = reinterpret_cast<LPPROC_RTLSETCURRENTDIRECTORY_U>(pRtlSetCurrentDirectory_U);
        PVOID pRtlGetFullPathName_U             = GetProcAddressByHash(hNTDLL, APIHASH_RTLGETFULLPATHNAME_U);
        pProcs->lpRtlGetFullPathName_U          = reinterpret_cast<LPPROC_RTLGETFULLPATHNAME_U>(pRtlGetFullPathName_U);

        // WINAPIs
        PVOID pQueryFullProcessImageNameW       = GetProcAddressByHash(hKernel32DLL, APIHASH_QUERYFULLPROCESSIMAGENAMEW);
        pProcs->lpQueryFullProcessImageNameW    = reinterpret_cast<LPPROC_QUERYFULLPROCESSIMAGENAMEW>(GetProcAddress(hKernel32DLL, "QueryFullProcessImageNameW"));
        PVOID pSetFileInformationByHandle       = GetProcAddressByHash(hKernel32DLL, APIHASH_SETFILEINFORMATIONBYHANDLE);
        pProcs->lpSetFileInformationByHandle    = reinterpret_cast<LPPROC_SETFILEINFORMATIONBYHANDLE>(pSetFileInformationByHandle);
        PVOID pWinHttpOpen                      = GetProcAddressByHash(hWinHTTPDLL, APIHASH_WINHTTPOPEN);
        pProcs->lpWinHttpOpen                   = reinterpret_cast<LPPROC_WINHTTPOPEN>(pWinHttpOpen);
        PVOID pWinHttpConnect                   = GetProcAddressByHash(hWinHTTPDLL, APIHASH_WINHTTPCONNECT);
        pProcs->lpWinHttpConnect                = reinterpret_cast<LPPROC_WINHTTPCONNECT>(pWinHttpConnect);
        PVOID pWinHttpOpenRequest               = GetProcAddressByHash(hWinHTTPDLL, APIHASH_WINHTTPOPENREQUEST);
        pProcs->lpWinHttpOpenRequest            = reinterpret_cast<LPPROC_WINHTTPOPENREQUEST>(pWinHttpOpenRequest);
        PVOID pWinHttpSetOption                 = GetProcAddressByHash(hWinHTTPDLL, APIHASH_WINHTTPSETOPTION);
        pProcs->lpWinHttpSetOption              = reinterpret_cast<LPPROC_WINHTTPSETOPTION>(pWinHttpSetOption);
        PVOID pWinHttpSendRequest               = GetProcAddressByHash(hWinHTTPDLL, APIHASH_WINHTTPSENDREQUEST);
        pProcs->lpWinHttpSendRequest            = reinterpret_cast<LPPROC_WINHTTPSENDREQUEST>(pWinHttpSendRequest);
        PVOID pWinHttpWriteData                 = GetProcAddressByHash(hWinHTTPDLL, APIHASH_WINHTTPWRITEDATA);
        pProcs->lpWinHttpWriteData              = reinterpret_cast<LPPROC_WINHTTPWRITEDATA>(pWinHttpWriteData);
        PVOID pWinHttpReceiveResponse           = GetProcAddressByHash(hWinHTTPDLL, APIHASH_WINHTTPRECEIVERESPONSE);
        pProcs->lpWinHttpReceiveResponse        = reinterpret_cast<LPPROC_WINHTTPRECEIVERESPONSE>(pWinHttpReceiveResponse);
        PVOID pWinHttpQueryHeaders              = GetProcAddressByHash(hWinHTTPDLL, APIHASH_WINHTTPQUERYHEADERS);
        pProcs->lpWinHttpQueryHeaders           = reinterpret_cast<LPPROC_WINHTTPQUERYHEADERS>(pWinHttpQueryHeaders);
        PVOID pWinHttpQueryDataAvailable        = GetProcAddressByHash(hWinHTTPDLL, APIHASH_WINHTTPQUERYDATAAVAILABLE);
        pProcs->lpWinHttpQueryDataAvailable     = reinterpret_cast<LPPROC_WINHTTPQUERYDATAAVAILABLE>(pWinHttpQueryDataAvailable);
        PVOID pWinHttpReadData                  = GetProcAddressByHash(hWinHTTPDLL, APIHASH_WINHTTPREADDATA);
        pProcs->lpWinHttpReadData               = reinterpret_cast<LPPROC_WINHTTPREADDATA>(pWinHttpReadData);
        PVOID pWinHttpCloseHandle               = GetProcAddressByHash(hWinHTTPDLL, APIHASH_WINHTTPCLOSEHANDLE);
        pProcs->lpWinHttpCloseHandle            = reinterpret_cast<LPPROC_WINHTTPCLOSEHANDLE>(pWinHttpCloseHandle);
        
        if (bIndirectSyscalls)
        {
            pProcs->sysNtCreateProcessEx            = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtCreateProcessEx));
            pProcs->sysNtOpenProcess                = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtOpenProcess));
            pProcs->sysNtOpenProcessToken           = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtOpenProcessToken));
            pProcs->sysNtTerminateProcess           = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtTerminateProcess));
            pProcs->sysNtCreateThreadEx             = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtCreateThreadEx));
            pProcs->sysNtResumeThread               = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtResumeThread));
            pProcs->sysNtGetContextThread           = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtGetContextThread));
            pProcs->sysNtSetContextThread           = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtSetContextThread));
            pProcs->sysNtAllocateVirtualMemory      = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtAllocateVirtualMemory));
            pProcs->sysNtProtectVirtualMemory       = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtProtectVirtualMemory));
            pProcs->sysNtReadVirtualMemory          = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtReadVirtualMemory));
            pProcs->sysNtWriteVirtualMemory         = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtWriteVirtualMemory));
            pProcs->sysNtFreeVirtualMemory          = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtFreeVirtualMemory));
            pProcs->sysNtDuplicateObject            = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtDuplicateObject));
            pProcs->sysNtWaitForSingleObject        = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtWaitForSingleObject));
            pProcs->sysNtClose                      = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtClose));
            pProcs->sysNtCreateFile                 = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtCreateFile));
            pProcs->sysNtOpenFile                   = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtOpenFile));
            pProcs->sysNtReadFile                   = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtReadFile));
            pProcs->sysNtWriteFile                  = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtWriteFile));
            pProcs->sysNtDeleteFile                 = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtDeleteFile));
            pProcs->sysNtCreateNamedPipeFile        = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtCreateNamedPipeFile));
            pProcs->sysNtQueryInformationProcess    = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtQueryInformationProcess));
            pProcs->sysNtQueryInformationFile       = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtQueryInformationFile));
            pProcs->sysNtSetInformationFile         = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtSetInformationFile));
            pProcs->sysNtQueryInformationToken      = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtQueryInformationToken));
            pProcs->sysNtQuerySystemInformation     = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtQuerySystemInformation));
            pProcs->sysNtSystemDebugControl         = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtSystemDebugControl));
            pProcs->sysNtPrivilegeCheck             = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtPrivilegeCheck));
            pProcs->sysNtAdjustPrivilegesToken      = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtAdjustPrivilegesToken));
            pProcs->sysNtOpenKeyEx                  = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtOpenKeyEx));
            pProcs->sysNtQueryKey                   = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtQueryKey));
            pProcs->sysNtEnumerateValueKey          = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtEnumerateValueKey));
            pProcs->sysNtUnmapViewOfSection         = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtUnmapViewOfSection));

            pProcs->sysRtlAllocateHeap              = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pRtlAllocateHeap));
            pProcs->sysRtlInitUnicodeString         = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pRtlInitUnicodeString));          
            pProcs->sysRtlGetCurrentDirectory_U     = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pRtlGetCurrentDirectory_U));
            pProcs->sysRtlSetCurrentDirectory_U     = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pRtlSetCurrentDirectory_U));
            pProcs->sysRtlGetFullPathName_U         = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pRtlGetFullPathName_U));
        }

        return pProcs;
    }
}
