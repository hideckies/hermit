#ifndef HERMIT_CORE_PROCS_HPP
#define HERMIT_CORE_PROCS_HPP

#include <winternl.h>
#include <windows.h>
#include <winhttp.h>
#include <string>

namespace Procs
{
    // NT Functions
    typedef NTSTATUS    (NTAPI*  LPPROC_NTOPENPROCESS)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
	typedef NTSTATUS    (NTAPI*  LPPROC_NTALLOCATEVIRTUALMEMORY)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
    typedef NTSTATUS    (NTAPI*  LPPROC_NTWRITEVIRTUALMEMORY)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);
    typedef NTSTATUS    (NTAPI*  LPPROC_NTCREATETHREADEX)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID lpBytesBuffer);
    typedef NTSTATUS    (NTAPI*  LPPROC_NTWAITFORSINGLEOBJECT)(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
	typedef NTSTATUS    (NTAPI*  LPPROC_NTCLOSE)(HANDLE Handle);
    // Runtime Library Functions
    typedef PVOID       (NTAPI*  LPPROC_RTLALLOCATEHEAP)(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
    // WinHTTP Functions
    typedef HINTERNET   (WINAPI* LPPROC_WINHTTPOPEN)(LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags);
    typedef HINTERNET   (WINAPI* LPPROC_WINHTTPCONNECT)(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved);
    typedef HINTERNET   (WINAPI* LPPROC_WINHTTPOPENREQUEST)(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR *ppwszAcceptTypes, DWORD dwFlags);
    typedef BOOL        (WINAPI* LPPROC_WINHTTPSETOPTION)(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength);
    typedef BOOL        (WINAPI* LPPROC_WINHTTPSENDREQUEST)(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext);
    typedef BOOL        (WINAPI* LPPROC_WINHTTPWRITEDATA)(HINTERNET hRequest, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten);
    typedef BOOL        (WINAPI* LPPROC_WINHTTPRECEIVERESPONSE)(HINTERNET hRequest, LPVOID lpReserved);
    typedef BOOL        (WINAPI* LPPROC_WINHTTPQUERYHEADERS)(HINTERNET hRequest, DWORD dwInfoLevel, LPCWSTR pwszName, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);
    typedef BOOL        (WINAPI* LPPROC_WINHTTPQUERYDATAAVAILABLE)(HINTERNET hRequest, LPDWORD lpdwNumberOfBytesAvailable);
    typedef BOOL        (WINAPI* LPPROC_WINHTTPREADDATA)(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesLength, LPDWORD lpdwNumberOfBytesRead);
    typedef BOOL        (WINAPI* LPPROC_WINHTTPCLOSEHANDLE)(HINTERNET hInternet);

    struct PROCS
    {
        // NT Functions
        LPPROC_NTOPENPROCESS              lpNtOpenProcess;
        LPPROC_NTALLOCATEVIRTUALMEMORY    lpNtAllocateVirtualMemory;
        LPPROC_NTWRITEVIRTUALMEMORY       lpNtWriteVirtualMemory;
        LPPROC_NTCREATETHREADEX           lpNtCreateThreadEx;
        LPPROC_NTWAITFORSINGLEOBJECT      lpNtWaitForSingleObject;
        LPPROC_NTCLOSE                    lpNtClose;
        // Runtime Library Functions
        LPPROC_RTLALLOCATEHEAP            lpRtlAllocateHeap;
        // WinHTTP Functions
        LPPROC_WINHTTPOPEN                lpWinHttpOpen;
        LPPROC_WINHTTPCONNECT             lpWinHttpConnect;
        LPPROC_WINHTTPOPENREQUEST         lpWinHttpOpenRequest;
        LPPROC_WINHTTPSETOPTION           lpWinHttpSetOption;
        LPPROC_WINHTTPSENDREQUEST         lpWinHttpSendRequest;
        LPPROC_WINHTTPWRITEDATA           lpWinHttpWriteData;
        LPPROC_WINHTTPRECEIVERESPONSE     lpWinHttpReceiveResponse;
        LPPROC_WINHTTPQUERYHEADERS        lpWinHttpQueryHeaders;
        LPPROC_WINHTTPQUERYDATAAVAILABLE  lpWinHttpQueryDataAvailable;
        LPPROC_WINHTTPREADDATA            lpWinHttpReadData;
        LPPROC_WINHTTPCLOSEHANDLE         lpWinHttpCloseHandle;
    };

    typedef PROCS* PPROCS;

    PPROCS  FindProcs(HMODULE hNTDLL, HMODULE hWinHTTPDLL);
}

#endif // HERMIT_CORE_PROCS_HPP