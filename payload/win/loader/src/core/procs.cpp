#include "core/procs.hpp"

namespace Procs
{
    PPROCS FindProcs(HMODULE hNTDLL, HMODULE hWinHTTPDLL, BOOL bIndirectSyscall)
    {
        PPROCS pProcs = new PROCS;

        // NTAPIs
        pProcs->lpNtCreateProcess           = reinterpret_cast<LPPROC_NTCREATEPROCESS>(GetProcAddress(hNTDLL, "NtCreateProcess"));
        pProcs->lpNtOpenProcess             = reinterpret_cast<LPPROC_NTOPENPROCESS>(GetProcAddress(hNTDLL, "NtOpenProcess"));
        pProcs->lpNtTerminateProcess        = reinterpret_cast<LPPROC_NTTERMINATEPROCESS>(GetProcAddress(hNTDLL, "NtTerminateProcess"));
        pProcs->lpNtCreateThreadEx          = reinterpret_cast<LPPROC_NTCREATETHREADEX>(GetProcAddress(hNTDLL, "NtCreateThreadEx"));
        pProcs->lpNtResumeThread            = reinterpret_cast<LPPROC_NTRESUMETHREAD>(GetProcAddress(hNTDLL, "NtResumeThread"));
        pProcs->lpNtAllocateVirtualMemory   = reinterpret_cast<LPPROC_NTALLOCATEVIRTUALMEMORY>(GetProcAddress(hNTDLL, "NtAllocateVirtualMemory"));
        pProcs->lpNtWriteVirtualMemory      = reinterpret_cast<LPPROC_NTWRITEVIRTUALMEMORY>(GetProcAddress(hNTDLL, "NtWriteVirtualMemory"));
        pProcs->lpNtFreeVirtualMemory       = reinterpret_cast<LPPROC_NTFREEVIRTUALMEMORY>(GetProcAddress(hNTDLL, "NtFreeVirtualMemory"));
        pProcs->lpNtDuplicateObject         = reinterpret_cast<LPPROC_NTDUPLICATEOBJECT>(GetProcAddress(hNTDLL, "NtDuplicateObject"));
        pProcs->lpNtWaitForSingleObject     = reinterpret_cast<LPPROC_NTWAITFORSINGLEOBJECT>(GetProcAddress(hNTDLL, "NtWaitForSingleObject"));
        pProcs->lpNtClose                   = reinterpret_cast<LPPROC_NTCLOSE>(GetProcAddress(hNTDLL, "NtClose"));
        pProcs->lpNtCreateFile              = reinterpret_cast<LPPROC_NTCREATEFILE>(GetProcAddress(hNTDLL, "NtCreateFile"));
        pProcs->lpNtReadFile                = reinterpret_cast<LPPROC_NTREADFILE>(GetProcAddress(hNTDLL, "NtReadFile"));
        pProcs->lpNtWriteFile               = reinterpret_cast<LPPROC_NTWRITEFILE>(GetProcAddress(hNTDLL, "NtWriteFile"));

        // NTAPIs (Runtime Library)
        pProcs->lpRtlAllocateHeap           = reinterpret_cast<LPPROC_RTLALLOCATEHEAP>(GetProcAddress(hNTDLL, "RtlAllocateHeap"));
        pProcs->lpRtlZeroMemory             = reinterpret_cast<LPPROC_RTLZEROMEMORY>(GetProcAddress(hNTDLL, "RtlZeroMemory"));
        pProcs->lpRtlInitUnicodeString      = reinterpret_cast<LPPROC_RTLINITUNICODESTRING>(GetProcAddress(hNTDLL, "RtlInitUnicodeString"));
        pProcs->lpRtlStringCchCatW          = reinterpret_cast<LPPROC_RTLSTRINGCCHCATW>(GetProcAddress(hNTDLL, "RtlStringCchCatW"));
        pProcs->lpRtlStringCchCopyW         = reinterpret_cast<LPPROC_RTLSTRINGCCHCOPYW>(GetProcAddress(hNTDLL, "RtlStringCchCopyW"));
        pProcs->lpRtlStringCchLengthW       = reinterpret_cast<LPPROC_RTLSTRINGCCHLENGTHW>(GetProcAddress(hNTDLL, "RtlStringCchLengthW"));
        pProcs->lpRtlNtStatusToDosError     = reinterpret_cast<LPPROC_RTLNTSTATUSTODOSERROR>(GetProcAddress(hNTDLL, "RtlNtStatusToDosError"));

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

        return pProcs;
    }
}