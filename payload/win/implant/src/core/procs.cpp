#include "core/procs.hpp"

namespace Procs
{
    PPROCS FindProcs(HMODULE hKernel32DLL, HMODULE hNTDLL, HMODULE hWinHTTPDLL, BOOL bIndirectSyscalls)
    {
        PPROCS pProcs = new PROCS;
    
        // NT APIs
        pProcs->lpNtCreateProcess               = reinterpret_cast<LPPROC_NTCREATEPROCESS>(GetProcAddress(hNTDLL, "NtCreateProcess"));
        pProcs->lpNtOpenProcess                 = reinterpret_cast<LPPROC_NTOPENPROCESS>(GetProcAddress(hNTDLL, "NtOpenProcess"));
        pProcs->lpNtOpenProcessToken            = reinterpret_cast<LPPROC_NTOPENPROCESSTOKEN>(GetProcAddress(hNTDLL, "NtOpenProcessToken"));
        pProcs->lpNtTerminateProcess            = reinterpret_cast<LPPROC_NTTERMINATEPROCESS>(GetProcAddress(hNTDLL, "NtTerminateProcess"));
        pProcs->lpNtCreateThreadEx              = reinterpret_cast<LPPROC_NTCREATETHREADEX>(GetProcAddress(hNTDLL, "NtCreateThreadEx"));
        pProcs->lpNtResumeThread                = reinterpret_cast<LPPROC_NTRESUMETHREAD>(GetProcAddress(hNTDLL, "NtResumeThread"));
        pProcs->lpNtAllocateVirtualMemory       = reinterpret_cast<LPPROC_NTALLOCATEVIRTUALMEMORY>(GetProcAddress(hNTDLL, "NtAllocateVirtualMemory"));
        pProcs->lpNtWriteVirtualMemory          = reinterpret_cast<LPPROC_NTWRITEVIRTUALMEMORY>(GetProcAddress(hNTDLL, "NtWriteVirtualMemory"));
        pProcs->lpNtFreeVirtualMemory           = reinterpret_cast<LPPROC_NTFREEVIRTUALMEMORY>(GetProcAddress(hNTDLL, "NtFreeVirtualMemory"));
        pProcs->lpNtDuplicateObject             = reinterpret_cast<LPPROC_NTDUPLICATEOBJECT>(GetProcAddress(hNTDLL, "NtDuplicateObject"));
        pProcs->lpNtWaitForSingleObject         = reinterpret_cast<LPPROC_NTWAITFORSINGLEOBJECT>(GetProcAddress(hNTDLL, "NtWaitForSingleObject"));
        pProcs->lpNtClose                       = reinterpret_cast<LPPROC_NTCLOSE>(GetProcAddress(hNTDLL, "NtClose"));
        pProcs->lpNtCreateFile                  = reinterpret_cast<LPPROC_NTCREATEFILE>(GetProcAddress(hNTDLL, "NtCreateFile"));
        pProcs->lpNtOpenFile                    = reinterpret_cast<LPPROC_NTOPENFILE>(GetProcAddress(hNTDLL, "NtOpenFile"));
        pProcs->lpNtReadFile                    = reinterpret_cast<LPPROC_NTREADFILE>(GetProcAddress(hNTDLL, "NtReadFile"));
        pProcs->lpNtWriteFile                   = reinterpret_cast<LPPROC_NTWRITEFILE>(GetProcAddress(hNTDLL, "NtWriteFile"));
        pProcs->lpNtDeleteFile                  = reinterpret_cast<LPPROC_NTDELETEFILE>(GetProcAddress(hNTDLL, "NtDeleteFile"));
        pProcs->lpNtCreateNamedPipeFile         = reinterpret_cast<LPPROC_NTCREATENAMEDPIPEFILE>(GetProcAddress(hNTDLL, "NtCreateNamedPipeFile"));
        pProcs->lpNtQueryInformationProcess     = reinterpret_cast<LPPROC_NTQUERYINFORMATIONPROCESS>(GetProcAddress(hNTDLL, "NtQueryInformationProcess"));
        pProcs->lpNtQueryInformationFile        = reinterpret_cast<LPPROC_NTSETINFORMATIONFILE>(GetProcAddress(hNTDLL, "NtQueryInformationFile"));
        pProcs->lpNtSetInformationFile          = reinterpret_cast<LPPROC_NTSETINFORMATIONFILE>(GetProcAddress(hNTDLL, "NtSetInformationFile"));
        pProcs->lpNtQueryInformationToken       = reinterpret_cast<LPPROC_NTQUERYINFORMATIONTOKEN>(GetProcAddress(hNTDLL, "NtQueryInformationToken"));
        pProcs->lpNtQuerySystemInformation      = reinterpret_cast<LPPROC_NTQUERYSYSTEMINFORMATION>(GetProcAddress(hNTDLL, "NtQuerySystemInformation"));
        pProcs->lpNtSystemDebugControl          = reinterpret_cast<LPPROC_NTSYSTEMDEBUGCONTROL>(GetProcAddress(hNTDLL, "NtSystemDebugControl"));
        pProcs->lpNtPrivilegeCheck              = reinterpret_cast<LPPROC_NTPRIVILEGECHECK>(GetProcAddress(hNTDLL, "NtPrivilegeCheck"));
        pProcs->lpNtAdjustPrivilegesToken       = reinterpret_cast<LPPROC_NTADJUSTPRIVILEGESTOKEN>(GetProcAddress(hNTDLL, "NtAdjustPrivilegesToken"));
        pProcs->lpNtOpenKeyEx                   = reinterpret_cast<LPPROC_NTOPENKEYEX>(GetProcAddress(hNTDLL, "NtOpenKeyEx"));
        pProcs->lpNtQueryKey                    = reinterpret_cast<LPPROC_NTQUERYKEY>(GetProcAddress(hNTDLL, "NtQueryKey"));
        pProcs->lpNtEnumerateValueKey           = reinterpret_cast<LPPROC_NTENUMERATEVALUEKEY>(GetProcAddress(hNTDLL, "NtEnumerateValueKey"));

        // NT APIs (Runtime Library)
        pProcs->lpRtlAllocateHeap               = reinterpret_cast<LPPROC_RTLALLOCATEHEAP>(GetProcAddress(hNTDLL, "RtlAllocateHeap"));
        pProcs->lpRtlInitUnicodeString          = reinterpret_cast<LPPROC_RTLINITUNICODESTRING>(GetProcAddress(hNTDLL, "RtlInitUnicodeString"));
        pProcs->lpRtlStringCchCatW              = reinterpret_cast<LPPROC_RTLSTRINGCCHCATW>(GetProcAddress(hNTDLL, "RtlStringCchCatW"));
        pProcs->lpRtlStringCchCopyW             = reinterpret_cast<LPPROC_RTLSTRINGCCHCOPYW>(GetProcAddress(hNTDLL, "RtlStringCchCopyW"));
        pProcs->lpRtlStringCchLengthW           = reinterpret_cast<LPPROC_RTLSTRINGCCHLENGTHW>(GetProcAddress(hNTDLL, "RtlStringCchLengthW"));
        pProcs->lpRtlGetCurrentDirectory_U      = reinterpret_cast<LPPROC_RTLGETCURRENTDIRECTORY_U>(GetProcAddress(hNTDLL, "RtlGetCurrentDirectory_U"));
        pProcs->lpRtlSetCurrentDirectory_U      = reinterpret_cast<LPPROC_RTLSETCURRENTDIRECTORY_U>(GetProcAddress(hNTDLL, "RtlSetCurrentDirectory_U"));
        pProcs->lpRtlGetFullPathName_U          = reinterpret_cast<LPPROC_RTLGETFULLPATHNAME_U>(GetProcAddress(hNTDLL, "RtlGetFullPathName_U"));

        // WINAPIs
        pProcs->lpWinHttpOpen                   = reinterpret_cast<LPPROC_WINHTTPOPEN>(GetProcAddress(hWinHTTPDLL, "WinHttpOpen"));
        pProcs->lpWinHttpConnect                = reinterpret_cast<LPPROC_WINHTTPCONNECT>(GetProcAddress(hWinHTTPDLL, "WinHttpConnect"));
        pProcs->lpWinHttpOpenRequest            = reinterpret_cast<LPPROC_WINHTTPOPENREQUEST>(GetProcAddress(hWinHTTPDLL, "WinHttpOpenRequest"));
        pProcs->lpWinHttpSetOption              = reinterpret_cast<LPPROC_WINHTTPSETOPTION>(GetProcAddress(hWinHTTPDLL, "WinHttpSetOption"));
        pProcs->lpWinHttpSendRequest            = reinterpret_cast<LPPROC_WINHTTPSENDREQUEST>(GetProcAddress(hWinHTTPDLL, "WinHttpSendRequest"));
        pProcs->lpWinHttpWriteData              = reinterpret_cast<LPPROC_WINHTTPWRITEDATA>(GetProcAddress(hWinHTTPDLL, "WinHttpWriteData"));
        pProcs->lpWinHttpReceiveResponse        = reinterpret_cast<LPPROC_WINHTTPRECEIVERESPONSE>(GetProcAddress(hWinHTTPDLL, "WinHttpReceiveResponse"));
        pProcs->lpWinHttpQueryHeaders           = reinterpret_cast<LPPROC_WINHTTPQUERYHEADERS>(GetProcAddress(hWinHTTPDLL, "WinHttpQueryHeaders"));
        pProcs->lpWinHttpQueryDataAvailable     = reinterpret_cast<LPPROC_WINHTTPQUERYDATAAVAILABLE>(GetProcAddress(hWinHTTPDLL, "WinHttpQueryDataAvailable"));
        pProcs->lpWinHttpReadData               = reinterpret_cast<LPPROC_WINHTTPREADDATA>(GetProcAddress(hWinHTTPDLL, "WinHttpReadData"));
        pProcs->lpWinHttpCloseHandle            = reinterpret_cast<LPPROC_WINHTTPCLOSEHANDLE>(GetProcAddress(hWinHTTPDLL, "WinHttpCloseHandle"));

        // KERNEL32
        pProcs->lpQueryFullProcessImageNameW    = reinterpret_cast<LPPROC_QUERYFULLPROCESSIMAGENAMEW>(GetProcAddress(hKernel32DLL, "QueryFullProcessImageNameW"));
        
        if (bIndirectSyscalls)
        {
            pProcs->sysNtCreateProcess              = Syscalls::FindSyscall(hNTDLL, "NtCreateProcess");
            pProcs->sysNtOpenProcess                = Syscalls::FindSyscall(hNTDLL, "NtOpenProcess");
            pProcs->sysNtOpenProcessToken           = Syscalls::FindSyscall(hNTDLL, "NtOpenProcessToken");
            pProcs->sysNtTerminateProcess           = Syscalls::FindSyscall(hNTDLL, "NtTerminateProcess");
            pProcs->sysNtCreateThreadEx             = Syscalls::FindSyscall(hNTDLL, "NtCreateThreadEx");
            pProcs->sysNtResumeThread               = Syscalls::FindSyscall(hNTDLL, "NtResumeThread");
            pProcs->sysNtAllocateVirtualMemory      = Syscalls::FindSyscall(hNTDLL, "NtAllocateVirtualMemory");
            pProcs->sysNtWriteVirtualMemory         = Syscalls::FindSyscall(hNTDLL, "NtWriteVirtualMemory");
            pProcs->sysNtFreeVirtualMemory          = Syscalls::FindSyscall(hNTDLL, "NtFreeVirtualMemory");
            pProcs->sysNtDuplicateObject            = Syscalls::FindSyscall(hNTDLL, "NtDuplicateObject");
            pProcs->sysNtWaitForSingleObject        = Syscalls::FindSyscall(hNTDLL, "NtWaitForSingleObject");
            pProcs->sysNtClose                      = Syscalls::FindSyscall(hNTDLL, "NtClose");
            pProcs->sysNtCreateFile                 = Syscalls::FindSyscall(hNTDLL, "NtCreateFile");
            pProcs->sysNtOpenFile                   = Syscalls::FindSyscall(hNTDLL, "NtOpenFile");
            pProcs->sysNtReadFile                   = Syscalls::FindSyscall(hNTDLL, "NtReadFile");
            pProcs->sysNtWriteFile                  = Syscalls::FindSyscall(hNTDLL, "NtWriteFile");
            pProcs->sysNtDeleteFile                 = Syscalls::FindSyscall(hNTDLL, "NtDeleteFile");
            pProcs->sysNtCreateNamedPipeFile        = Syscalls::FindSyscall(hNTDLL, "NtCreateNamedPipeFile");
            pProcs->sysNtQueryInformationProcess    = Syscalls::FindSyscall(hNTDLL, "NtQueryInformationProcess");
            pProcs->sysNtQueryInformationFile       = Syscalls::FindSyscall(hNTDLL, "NtQueryInformationFile");
            pProcs->sysNtSetInformationFile         = Syscalls::FindSyscall(hNTDLL, "NtSetInformationFile");
            pProcs->sysNtQueryInformationToken      = Syscalls::FindSyscall(hNTDLL, "NtQueryInformationToken");
            pProcs->sysNtQuerySystemInformation     = Syscalls::FindSyscall(hNTDLL, "NtQuerySystemInformation");
            pProcs->sysNtSystemDebugControl         = Syscalls::FindSyscall(hNTDLL, "NtSystemDebugControl");
            pProcs->sysNtPrivilegeCheck             = Syscalls::FindSyscall(hNTDLL, "NtPrivilegeCheck");
            pProcs->sysNtAdjustPrivilegesToken      = Syscalls::FindSyscall(hNTDLL, "NtAdjustPrivilegesToken");
            pProcs->sysNtOpenKeyEx                  = Syscalls::FindSyscall(hNTDLL, "NtOpenKeyEx");
            pProcs->sysNtQueryKey                   = Syscalls::FindSyscall(hNTDLL, "NtQueryKey");
            pProcs->sysNtEnumerateValueKey          = Syscalls::FindSyscall(hNTDLL, "NtEnumerateValueKey");

            pProcs->sysRtlAllocateHeap              = Syscalls::FindSyscall(hNTDLL, "RtlAllocateHeap");
            pProcs->sysRtlInitUnicodeString         = Syscalls::FindSyscall(hNTDLL, "RtlInitUnicodeString");
            pProcs->sysRtlStringCchCatW             = Syscalls::FindSyscall(hNTDLL, "RtlStringCchCatW");
            pProcs->sysRtlStringCchCopyW            = Syscalls::FindSyscall(hNTDLL, "RtlStringCchCopyW");
            pProcs->sysRtlStringCchLengthW          = Syscalls::FindSyscall(hNTDLL, "RtlStringCchLengthW");
            pProcs->sysRtlGetCurrentDirectory_U     = Syscalls::FindSyscall(hNTDLL, "RtlGetCurrentDirectory_U");
            pProcs->sysRtlSetCurrentDirectory_U     = Syscalls::FindSyscall(hNTDLL, "RtlSetCurrentDirectory_U");
            pProcs->sysRtlGetFullPathName_U         = Syscalls::FindSyscall(hNTDLL, "RtlGetFullPathName_U");
        }

        return pProcs;
    }
}
