#ifndef HERMIT_CORE_PROCS_HPP
#define HERMIT_CORE_PROCS_HPP

#include "core/ntdll.hpp"
#include "core/syscalls.hpp"

#include <winternl.h>
#include <windows.h>
#include <winhttp.h>
#include <string>

typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

namespace Procs
{
    // **NATIVE APIs**
    // NtCreateProcessEx
    typedef NTSTATUS (NTAPI* LPPROC_NTCREATEPROCESSEX)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle, HANDLE DebugPort, HANDLE TokenHandle, ULONG Reserved);
    // NtOpenProcess
    typedef NTSTATUS (NTAPI* LPPROC_NTOPENPROCESS)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
    // NtOpenProcessToken
    typedef NTSTATUS (NTAPI* LPPROC_NTOPENPROCESSTOKEN)( HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle);
    // NtTerminateProcess
	typedef NTSTATUS (NTAPI* LPPROC_NTTERMINATEPROCESS)(HANDLE ProcessHandle, NTSTATUS ExitStatus);
    // NtQueryInformationProcess
    typedef NTSTATUS (NTAPI* LPPROC_NTQUERYINFORMATIONPROCESS)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
    // NtSetInformationProcess
    typedef NTSTATUS (NTAPI* LPPROC_NTSETINFORMATIONPROCESS)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);
    // NtCreateThreadEx
    typedef NTSTATUS (NTAPI* LPPROC_NTCREATETHREADEX)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, LPTHREAD_START_ROUTINE StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList);
    // NtOpenThread
    typedef NTSTATUS (NTAPI* LPPROC_NTOPENTHREAD)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
    // NtResumeThread
    typedef NTSTATUS (NTAPI* LPPROC_NTRESUMETHREAD)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
    // NtGetContextThread
    typedef NTSTATUS (NTAPI* LPPROC_NTGETCONTEXTTHREAD)(HANDLE ThreadHandle, PCONTEXT ThreadContext);
    // NtSetContextThread
    typedef NTSTATUS (NTAPI* LPPROC_NTSETCONTEXTTHREAD)(HANDLE ThreadHandle, PCONTEXT ThreadContext);
    // NtAllocateVirtualMemoryEx
    typedef NTSTATUS (NTAPI* LPPROC_NTALLOCATEVIRTUALMEMORY)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
    // NtReadVirtualMemory
    typedef NTSTATUS (NTAPI* LPPROC_NTREADVIRTUALMEMORY)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);
    // NtWriteVirtualMemory
    typedef NTSTATUS (NTAPI* LPPROC_NTWRITEVIRTUALMEMORY)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);
    // NtProtectVirtualMemory
    typedef NTSTATUS (NTAPI* LPPROC_NTPROTECTVIRTUALMEMORY)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
    // NtFreeVirtualMemory
    typedef NTSTATUS (NTAPI* LPPROC_NTFREEVIRTUALMEMORY)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
    // NtDuplicateObject
    typedef NTSTATUS (NTAPI* LPPROC_NTDUPLICATEOBJECT)(HANDLE SourceProcessHandle, PHANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, BOOLEAN InheritHandle, ULONG Options);
    // NtWaitForSingleObject
    typedef NTSTATUS (NTAPI* LPPROC_NTWAITFORSINGLEOBJECT)(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
    // NtClose
	typedef NTSTATUS (NTAPI* LPPROC_NTCLOSE)(HANDLE Handle);
    // NtCreateFile
    typedef NTSTATUS (NTAPI* LPPROC_NTCREATEFILE)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
    // NtReadFile
    typedef NTSTATUS (NTAPI* LPPROC_NTREADFILE)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
    // NtWriteFile
    typedef NTSTATUS (NTAPI* LPPROC_NTWRITEFILE)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
    // NtCreateNamedPipeFile
    typedef NTSTATUS (NTAPI* LPPROC_NTCREATENAMEDPIPEFILE)(PHANDLE FileHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, ULONG NamedPipeType, ULONG ReadMode, ULONG CompletionMode, ULONG MaximumInstances, ULONG InboundQuota, ULONG OutboundQuota, PLARGE_INTEGER DefaultTimeout);
    // NtQueryInformationFile
    typedef NTSTATUS (NTAPI* LPPROC_NTQUERYINFORMATIONFILE)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
    // NtSetInformationFile
    typedef NTSTATUS (NTAPI* LPPROC_NTSETINFORMATIONFILE)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
    // NtUnmapViewOfSection
    typedef NTSTATUS (NTAPI* LPPROC_NTUNMAPVIEWOFSECTION)(HANDLE ProcessHandle, PVOID BaseAddress);

    // **NATIVE APIs (Runtime Library)**
    // RtlAllocateHeap
    typedef PVOID (NTAPI* LPPROC_RTLALLOCATEHEAP)(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
    // RtlZeroMemory
    typedef VOID (NTAPI* LPPROC_RTLZEROMEMORY)(PVOID Destination, SIZE_T Length);
    // RtlInitUnicodeString
    typedef NTSTATUS (NTAPI* LPPROC_RTLINITUNICODESTRING)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
    // RtlStringCatW
    typedef NTSTATUS (NTAPI* LPPROC_RTLSTRINGCCHCATW)(LPWSTR pszDest, SIZE_T cchDest, LPCWSTR pszSrc);
    // RtlStringCchCopyW
    typedef NTSTATUS (NTAPI* LPPROC_RTLSTRINGCCHCOPYW)(LPWSTR pszDest, SIZE_T cchDest, LPCWSTR pszSrc);
    // RtlStringCchLengthW
    typedef NTSTATUS (NTAPI* LPPROC_RTLSTRINGCCHLENGTHW)(PCWSTR psz, SIZE_T cchMax, SIZE_T *pcchLength);
    // RtlQuerySystemInformation
    typedef NTSTATUS (NTAPI* LPPROC_RTLQUERYSYSTEMINFORMATION)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
    // RtlExpandEnvironmentStrings
    typedef NTSTATUS (NTAPI* LPPROC_RTLEXPANDENVIRONMENTSTRINGS)(PVOID Environment, PCWSTR Source, SIZE_T SourceLength, PWSTR Destination, SIZE_T DestinationLength, PSIZE_T ReturnLength);
    // RtlNtStatusToDosError
    typedef DWORD (NTAPI* LPPROC_RTLNTSTATUSTODOSERROR)(NTSTATUS Status);
    // RtlGetFullPathName_U
    typedef NTSTATUS (NTAPI* LPPROC_RTLGETFULLPATHNAME_U)(PCWSTR FileName, ULONG BufferLength, PWSTR Buffer, PWSTR *FilePart);

    // **WINAPIs**
    // WinHttpOpen
    typedef HINTERNET   (WINAPI* LPPROC_WINHTTPOPEN)(LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags);
    // WinHttpConnect
    typedef HINTERNET   (WINAPI* LPPROC_WINHTTPCONNECT)(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved);
    // WinHttpOpenRequest
    typedef HINTERNET   (WINAPI* LPPROC_WINHTTPOPENREQUEST)(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR *ppwszAcceptTypes, DWORD dwFlags);
    // WinHttpSetOption
    typedef BOOL        (WINAPI* LPPROC_WINHTTPSETOPTION)(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength);
    // WinHttpSendRequest
    typedef BOOL        (WINAPI* LPPROC_WINHTTPSENDREQUEST)(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext);
    // WinHttpWriteData
    typedef BOOL        (WINAPI* LPPROC_WINHTTPWRITEDATA)(HINTERNET hRequest, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten);
    // WinHttpReceiveResponse
    typedef BOOL        (WINAPI* LPPROC_WINHTTPRECEIVERESPONSE)(HINTERNET hRequest, LPVOID lpReserved);
    // WinHttpQueryHeaders
    typedef BOOL        (WINAPI* LPPROC_WINHTTPQUERYHEADERS)(HINTERNET hRequest, DWORD dwInfoLevel, LPCWSTR pwszName, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);
    // WinHttpQueryDataAvailable
    typedef BOOL        (WINAPI* LPPROC_WINHTTPQUERYDATAAVAILABLE)(HINTERNET hRequest, LPDWORD lpdwNumberOfBytesAvailable);
    // WinHttpReadData
    typedef BOOL        (WINAPI* LPPROC_WINHTTPREADDATA)(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesLength, LPDWORD lpdwNumberOfBytesRead);
    // WinHttpCloseHandle
    typedef BOOL        (WINAPI* LPPROC_WINHTTPCLOSEHANDLE)(HINTERNET hInternet);

    struct PROCS
    {
         // **NATIVE APIs**
        LPPROC_NTCREATEPROCESSEX            lpNtCreateProcessEx                 = nullptr;
        LPPROC_NTOPENPROCESS                lpNtOpenProcess                     = nullptr;
        LPPROC_NTOPENPROCESSTOKEN           lpNtOpenProcessToken                = nullptr;
        LPPROC_NTTERMINATEPROCESS           lpNtTerminateProcess                = nullptr;
        LPPROC_NTQUERYINFORMATIONPROCESS    lpNtQueryInformationProcess         = nullptr;
        LPPROC_NTSETINFORMATIONPROCESS      lpNtSetInformationProcess           = nullptr;
        LPPROC_NTCREATETHREADEX             lpNtCreateThreadEx                  = nullptr;
        LPPROC_NTOPENTHREAD                 lpNtOpenThread                      = nullptr;
        LPPROC_NTRESUMETHREAD               lpNtResumeThread                    = nullptr;
        LPPROC_NTGETCONTEXTTHREAD           lpNtGetContextThread                = nullptr;
        LPPROC_NTSETCONTEXTTHREAD           lpNtSetContextThread                = nullptr;
        LPPROC_NTALLOCATEVIRTUALMEMORY      lpNtAllocateVirtualMemory           = nullptr;
        LPPROC_NTREADVIRTUALMEMORY          lpNtReadVirtualMemory               = nullptr;
        LPPROC_NTWRITEVIRTUALMEMORY         lpNtWriteVirtualMemory              = nullptr;
        LPPROC_NTPROTECTVIRTUALMEMORY       lpNtProtectVirtualMemory            = nullptr;
        LPPROC_NTFREEVIRTUALMEMORY          lpNtFreeVirtualMemory               = nullptr;
        LPPROC_NTDUPLICATEOBJECT            lpNtDuplicateObject                 = nullptr;
        LPPROC_NTWAITFORSINGLEOBJECT        lpNtWaitForSingleObject             = nullptr;
        LPPROC_NTCLOSE                      lpNtClose                           = nullptr;
        LPPROC_NTCREATEFILE                 lpNtCreateFile                      = nullptr;
        LPPROC_NTREADFILE                   lpNtReadFile                        = nullptr;
        LPPROC_NTWRITEFILE                  lpNtWriteFile                       = nullptr;
        LPPROC_NTCREATENAMEDPIPEFILE        lpNtCreateNamedPipeFile             = nullptr;
        LPPROC_NTQUERYINFORMATIONFILE       lpNtQueryInformationFile            = nullptr;
        LPPROC_NTSETINFORMATIONFILE         lpNtSetInformationFile              = nullptr;
        LPPROC_NTUNMAPVIEWOFSECTION         lpNtUnmapViewOfSection              = nullptr;

        // **NATIVE APIs (RUNTIME LIBRARY)**
        LPPROC_RTLALLOCATEHEAP              lpRtlAllocateHeap                   = nullptr;
        LPPROC_RTLZEROMEMORY                lpRtlZeroMemory                     = nullptr;
        LPPROC_RTLINITUNICODESTRING         lpRtlInitUnicodeString              = nullptr;
        LPPROC_RTLSTRINGCCHCATW             lpRtlStringCchCatW                  = nullptr;
        LPPROC_RTLSTRINGCCHCOPYW            lpRtlStringCchCopyW                 = nullptr;
        LPPROC_RTLSTRINGCCHLENGTHW          lpRtlStringCchLengthW               = nullptr;
        LPPROC_RTLQUERYSYSTEMINFORMATION    lpRtlQuerySystemInformation         = nullptr;
        LPPROC_RTLEXPANDENVIRONMENTSTRINGS  lpRtlExpandEnvironmentStrings       = nullptr;
        LPPROC_RTLNTSTATUSTODOSERROR        lpRtlNtStatusToDosError             = nullptr;
        LPPROC_RTLGETFULLPATHNAME_U         lpRtlGetFullPathName_U              = nullptr;

        // **WINAPIs**
        LPPROC_WINHTTPOPEN                  lpWinHttpOpen                       = nullptr;
        LPPROC_WINHTTPCONNECT               lpWinHttpConnect                    = nullptr;
        LPPROC_WINHTTPOPENREQUEST           lpWinHttpOpenRequest                = nullptr;
        LPPROC_WINHTTPSETOPTION             lpWinHttpSetOption                  = nullptr;
        LPPROC_WINHTTPSENDREQUEST           lpWinHttpSendRequest                = nullptr;
        LPPROC_WINHTTPWRITEDATA             lpWinHttpWriteData                  = nullptr;
        LPPROC_WINHTTPRECEIVERESPONSE       lpWinHttpReceiveResponse            = nullptr;
        LPPROC_WINHTTPQUERYHEADERS          lpWinHttpQueryHeaders               = nullptr;
        LPPROC_WINHTTPQUERYDATAAVAILABLE    lpWinHttpQueryDataAvailable         = nullptr;
        LPPROC_WINHTTPREADDATA              lpWinHttpReadData                   = nullptr;
        LPPROC_WINHTTPCLOSEHANDLE           lpWinHttpCloseHandle                = nullptr;

        // **SYSCALLS**
        Syscalls::SYSCALL                   sysNtCreateProcessEx                = {0};
        Syscalls::SYSCALL                   sysNtOpenProcess                    = {0};
        Syscalls::SYSCALL                   sysNtOpenProcessToken               = {0};
        Syscalls::SYSCALL                   sysNtTerminateProcess               = {0};
        Syscalls::SYSCALL                   sysNtQueryInformationProcess        = {0};
        Syscalls::SYSCALL                   sysNtSetInformationProcess          = {0};
        Syscalls::SYSCALL                   sysNtCreateThreadEx                 = {0};
        Syscalls::SYSCALL                   sysNtOpenThread                     = {0};
        Syscalls::SYSCALL                   sysNtResumeThread                   = {0};
        Syscalls::SYSCALL                   sysNtGetContextThread               = {0};
        Syscalls::SYSCALL                   sysNtSetContextThread               = {0};
        Syscalls::SYSCALL                   sysNtAllocateVirtualMemory          = {0};
        Syscalls::SYSCALL                   sysNtReadVirtualMemory              = {0};
        Syscalls::SYSCALL                   sysNtWriteVirtualMemory             = {0};
        Syscalls::SYSCALL                   sysNtProtectVirtualMemory           = {0};
        Syscalls::SYSCALL                   sysNtFreeVirtualMemory              = {0};
        Syscalls::SYSCALL                   sysNtWaitForSingleObject            = {0};
        Syscalls::SYSCALL                   sysNtClose                          = {0};
        Syscalls::SYSCALL                   sysNtCreateFile                     = {0};
        Syscalls::SYSCALL                   sysNtReadFile                       = {0};
        Syscalls::SYSCALL                   sysNtWriteFile                      = {0};
        Syscalls::SYSCALL                   sysNtQueryInformationFile           = {0};
        Syscalls::SYSCALL                   sysNtUnmapViewOfSection             = {0};
        
        Syscalls::SYSCALL                   sysRtlInitUnicodeString             = {0};
        Syscalls::SYSCALL                   sysRtlGetFullPathName_U             = {0};
    };

    typedef PROCS* PPROCS;

    PPROCS FindProcs(HMODULE hNTDLL, HMODULE hWinHTTPDLL, BOOL bIndirectSyscalls);
}

#endif // HERMIT_CORE_PROCS_HPP