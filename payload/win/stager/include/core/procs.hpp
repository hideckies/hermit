#ifndef HERMIT_CORE_PROCS_HPP
#define HERMIT_CORE_PROCS_HPP

#include <windows.h>
#include <winhttp.h>
#include <string>

namespace Procs
{
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
        // WinHTTP
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

    PPROCS FindProcs(HMODULE hWinHTTPDLL);
}

#endif // HERMIT_CORE_PROCS_HPP