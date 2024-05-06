#include "core/procs.hpp"

namespace Procs
{
    PPROCS FindProcs(HMODULE hNTDLL, HMODULE hWinHTTPDLL, BOOL bIndirectSyscall)
    {
        PPROCS pProcs = new PROCS;

        // NTAPIs
        pProcs->lpNtCreateProcessEx         = reinterpret_cast<LPPROC_NTCREATEPROCESSEX>(GetProcAddress(hNTDLL, "NtCreateProcessEx"));
        pProcs->lpNtOpenProcess             = reinterpret_cast<LPPROC_NTOPENPROCESS>(GetProcAddress(hNTDLL, "NtOpenProcess"));
        pProcs->lpNtOpenProcessToken        = reinterpret_cast<LPPROC_NTOPENPROCESSTOKEN>(GetProcAddress(hNTDLL, "NtOpenProcessToken"));
        pProcs->lpNtTerminateProcess        = reinterpret_cast<LPPROC_NTTERMINATEPROCESS>(GetProcAddress(hNTDLL, "NtTerminateProcess"));
        pProcs->lpNtQueryInformationProcess = reinterpret_cast<LPPROC_NTQUERYINFORMATIONPROCESS>(GetProcAddress(hNTDLL, "NtQueryInformationProcess"));
        pProcs->lpNtSetInformationProcess   = reinterpret_cast<LPPROC_NTSETINFORMATIONPROCESS>(GetProcAddress(hNTDLL, "NtSetInformationProcess"));
        pProcs->lpNtCreateThreadEx          = reinterpret_cast<LPPROC_NTCREATETHREADEX>(GetProcAddress(hNTDLL, "NtCreateThreadEx"));
        pProcs->lpNtOpenThread              = reinterpret_cast<LPPROC_NTOPENTHREAD>(GetProcAddress(hNTDLL, "NtOpenThread"));
        pProcs->lpNtResumeThread            = reinterpret_cast<LPPROC_NTRESUMETHREAD>(GetProcAddress(hNTDLL, "NtResumeThread"));
        pProcs->lpNtGetContextThread        = reinterpret_cast<LPPROC_NTGETCONTEXTTHREAD>(GetProcAddress(hNTDLL, "NtGetContextThread"));
        pProcs->lpNtSetContextThread        = reinterpret_cast<LPPROC_NTSETCONTEXTTHREAD>(GetProcAddress(hNTDLL, "NtSetContextThread"));
        pProcs->lpNtAllocateVirtualMemory   = reinterpret_cast<LPPROC_NTALLOCATEVIRTUALMEMORY>(GetProcAddress(hNTDLL, "NtAllocateVirtualMemory"));
        pProcs->lpNtReadVirtualMemory       = reinterpret_cast<LPPROC_NTREADVIRTUALMEMORY>(GetProcAddress(hNTDLL, "NtReadVirtualMemory"));
        pProcs->lpNtWriteVirtualMemory      = reinterpret_cast<LPPROC_NTWRITEVIRTUALMEMORY>(GetProcAddress(hNTDLL, "NtWriteVirtualMemory"));
        pProcs->lpNtProtectVirtualMemory    = reinterpret_cast<LPPROC_NTPROTECTVIRTUALMEMORY>(GetProcAddress(hNTDLL, "NtProtectVirtualMemory"));
        pProcs->lpNtFreeVirtualMemory       = reinterpret_cast<LPPROC_NTFREEVIRTUALMEMORY>(GetProcAddress(hNTDLL, "NtFreeVirtualMemory"));
        pProcs->lpNtDuplicateObject         = reinterpret_cast<LPPROC_NTDUPLICATEOBJECT>(GetProcAddress(hNTDLL, "NtDuplicateObject"));
        pProcs->lpNtWaitForSingleObject     = reinterpret_cast<LPPROC_NTWAITFORSINGLEOBJECT>(GetProcAddress(hNTDLL, "NtWaitForSingleObject"));
        pProcs->lpNtClose                   = reinterpret_cast<LPPROC_NTCLOSE>(GetProcAddress(hNTDLL, "NtClose"));
        pProcs->lpNtCreateFile              = reinterpret_cast<LPPROC_NTCREATEFILE>(GetProcAddress(hNTDLL, "NtCreateFile"));
        pProcs->lpNtReadFile                = reinterpret_cast<LPPROC_NTREADFILE>(GetProcAddress(hNTDLL, "NtReadFile"));
        pProcs->lpNtWriteFile               = reinterpret_cast<LPPROC_NTWRITEFILE>(GetProcAddress(hNTDLL, "NtWriteFile"));
        pProcs->lpNtUnmapViewOfSection      = reinterpret_cast<LPPROC_NTUNMAPVIEWOFSECTION>(GetProcAddress(hNTDLL, "NtUnmapViewOfSection"));

        // NTAPIs (Runtime Library)
        pProcs->lpRtlAllocateHeap           = reinterpret_cast<LPPROC_RTLALLOCATEHEAP>(GetProcAddress(hNTDLL, "RtlAllocateHeap"));
        pProcs->lpRtlZeroMemory             = reinterpret_cast<LPPROC_RTLZEROMEMORY>(GetProcAddress(hNTDLL, "RtlZeroMemory"));
        pProcs->lpRtlInitUnicodeString      = reinterpret_cast<LPPROC_RTLINITUNICODESTRING>(GetProcAddress(hNTDLL, "RtlInitUnicodeString"));
        pProcs->lpRtlStringCchCatW          = reinterpret_cast<LPPROC_RTLSTRINGCCHCATW>(GetProcAddress(hNTDLL, "RtlStringCchCatW"));
        pProcs->lpRtlStringCchCopyW         = reinterpret_cast<LPPROC_RTLSTRINGCCHCOPYW>(GetProcAddress(hNTDLL, "RtlStringCchCopyW"));
        pProcs->lpRtlStringCchLengthW       = reinterpret_cast<LPPROC_RTLSTRINGCCHLENGTHW>(GetProcAddress(hNTDLL, "RtlStringCchLengthW"));
        pProcs->lpRtlNtStatusToDosError     = reinterpret_cast<LPPROC_RTLNTSTATUSTODOSERROR>(GetProcAddress(hNTDLL, "RtlNtStatusToDosError"));
        pProcs->lpRtlGetFullPathName_U      = reinterpret_cast<LPPROC_RTLGETFULLPATHNAME_U>(GetProcAddress(hNTDLL, "RtlGetFullPathName_U"));

        // WINAPIs
        pProcs->lpWinHttpOpen               = reinterpret_cast<LPPROC_WINHTTPOPEN>(GetProcAddress(hWinHTTPDLL, "WinHttpOpen"));
        pProcs->lpWinHttpConnect            = reinterpret_cast<LPPROC_WINHTTPCONNECT>(GetProcAddress(hWinHTTPDLL, "WinHttpConnect"));
        pProcs->lpWinHttpOpenRequest        = reinterpret_cast<LPPROC_WINHTTPOPENREQUEST>(GetProcAddress(hWinHTTPDLL, "WinHttpOpenRequest"));
        pProcs->lpWinHttpSetOption          = reinterpret_cast<LPPROC_WINHTTPSETOPTION>(GetProcAddress(hWinHTTPDLL, "WinHttpSetOption"));
        pProcs->lpWinHttpSendRequest        = reinterpret_cast<LPPROC_WINHTTPSENDREQUEST>(GetProcAddress(hWinHTTPDLL, "WinHttpSendRequest"));
        pProcs->lpWinHttpWriteData          = reinterpret_cast<LPPROC_WINHTTPWRITEDATA>(GetProcAddress(hWinHTTPDLL, "WinHttpWriteData"));
        pProcs->lpWinHttpReceiveResponse    = reinterpret_cast<LPPROC_WINHTTPRECEIVERESPONSE>(GetProcAddress(hWinHTTPDLL, "WinHttpReceiveResponse"));
        pProcs->lpWinHttpQueryHeaders       = reinterpret_cast<LPPROC_WINHTTPQUERYHEADERS>(GetProcAddress(hWinHTTPDLL, "WinHttpQueryHeaders"));
        pProcs->lpWinHttpQueryDataAvailable = reinterpret_cast<LPPROC_WINHTTPQUERYDATAAVAILABLE>(GetProcAddress(hWinHTTPDLL, "WinHttpQueryDataAvailable"));
        pProcs->lpWinHttpReadData           = reinterpret_cast<LPPROC_WINHTTPREADDATA>(GetProcAddress(hWinHTTPDLL, "WinHttpReadData"));
        pProcs->lpWinHttpCloseHandle        = reinterpret_cast<LPPROC_WINHTTPCLOSEHANDLE>(GetProcAddress(hWinHTTPDLL, "WinHttpCloseHandle"));

        if (bIndirectSyscall)
        {
            pProcs->sysNtCreateProcessEx            = Syscalls::FindSyscall(hNTDLL, "NtCreateProcessEx");
            pProcs->sysNtOpenProcess                = Syscalls::FindSyscall(hNTDLL, "NtOpenProcess");
            pProcs->sysNtOpenProcessToken           = Syscalls::FindSyscall(hNTDLL, "NtOpenProcessToken");
            pProcs->sysNtTerminateProcess           = Syscalls::FindSyscall(hNTDLL, "NtTerminateProcess");
            pProcs->sysNtQueryInformationProcess    = Syscalls::FindSyscall(hNTDLL, "NtQueryInformationProcess");
            pProcs->sysNtSetInformationProcess      = Syscalls::FindSyscall(hNTDLL, "NtSetInformationProcess");
            pProcs->sysNtCreateThreadEx             = Syscalls::FindSyscall(hNTDLL, "NtCreateThreadEx");
            pProcs->sysNtOpenThread                 = Syscalls::FindSyscall(hNTDLL, "NtOpenThread");
            pProcs->sysNtResumeThread               = Syscalls::FindSyscall(hNTDLL, "NtResumeThread");
            pProcs->sysNtGetContextThread           = Syscalls::FindSyscall(hNTDLL, "NtGetContextThread");
            pProcs->sysNtSetContextThread           = Syscalls::FindSyscall(hNTDLL, "NtSetContextThread");
            pProcs->sysNtAllocateVirtualMemory      = Syscalls::FindSyscall(hNTDLL, "NtAllocateVirtualMemory");
            pProcs->sysNtReadVirtualMemory          = Syscalls::FindSyscall(hNTDLL, "NtReadVirtualMemory");
            pProcs->sysNtWriteVirtualMemory         = Syscalls::FindSyscall(hNTDLL, "NtWriteVirtualMemory");
            pProcs->sysNtProtectVirtualMemory       = Syscalls::FindSyscall(hNTDLL, "NtProtectVirtualMemory");
            pProcs->sysNtFreeVirtualMemory          = Syscalls::FindSyscall(hNTDLL, "NtFreeVirtualMemory");
            pProcs->sysNtWaitForSingleObject        = Syscalls::FindSyscall(hNTDLL, "NtWaitForSingleObject");
            pProcs->sysNtClose                      = Syscalls::FindSyscall(hNTDLL, "NtClose");
            pProcs->sysNtCreateFile                 = Syscalls::FindSyscall(hNTDLL, "NtCreateFile");
            pProcs->sysNtReadFile                   = Syscalls::FindSyscall(hNTDLL, "NtReadFile");
            pProcs->sysNtWriteFile                  = Syscalls::FindSyscall(hNTDLL, "NtWriteFile");
            pProcs->sysNtQueryInformationFile       = Syscalls::FindSyscall(hNTDLL, "NtQueryInformationFile");
            pProcs->sysNtUnmapViewOfSection         = Syscalls::FindSyscall(hNTDLL, "NtUnmapViewOfSection");

            pProcs->sysRtlInitUnicodeString         = Syscalls::FindSyscall(hNTDLL, "RtlInitUnicodeString");
            pProcs->sysRtlGetFullPathName_U         = Syscalls::FindSyscall(hNTDLL, "RtlGetFullPathName_U");
        }

        return pProcs;
    }
}