#include "core/procs.hpp"

namespace Procs
{
    PPROCS FindProcs(HMODULE hNTDLL, HMODULE hWinHTTPDLL)
    {
        PPROCS pProcs = new PROCS;
        // NT
        pProcs->lpRtlAllocateHeap           = reinterpret_cast<LPPROC_RTLALLOCATEHEAP>(GetProcAddress(hNTDLL, "RtlAllocateHeap"));
        // WinHTTP
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