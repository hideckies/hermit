#ifndef HERMIT_CORE_PROCS_HPP
#define HERMIT_CORE_PROCS_HPP

#include "core/ntdll.hpp"
#include "core/stdout.hpp"
#include "core/syscalls.hpp"
#include "core/utils.hpp"

#include <winternl.h>
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <strsafe.h>

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

    // LdrLoadDll
    typedef NTSTATUS (NTAPI* LPPROC_LDRLOADDLL)(PWSTR DllPath, PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID *DllHandle);

    // NtFlushInstructionCache
    typedef NTSTATUS (NTAPI* LPPROC_NTFLUSHINSTRUCTIONCACHE)(HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T Length);
    // NtCreateProcessEx
    typedef NTSTATUS (NTAPI* LPPROC_NTCREATEPROCESSEX)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle, HANDLE DebugPort, HANDLE TokenHandle, ULONG Reserved);
    // NtOpenProcess
    typedef NTSTATUS (NTAPI* LPPROC_NTOPENPROCESS)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
    // NtOpenProcessToken
    typedef NTSTATUS (NTAPI* LPPROC_NTOPENPROCESSTOKEN)(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle);
    // NtTerminateProcess
	typedef NTSTATUS (NTAPI* LPPROC_NTTERMINATEPROCESS)(HANDLE ProcessHandle, NTSTATUS ExitStatus);
    // NtSetInformationProcess
    typedef NTSTATUS (NTAPI* LPPROC_NTSETINFORMATIONPROCESS)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);
    // NtCreateThreadEx
    typedef NTSTATUS (NTAPI* LPPROC_NTCREATETHREADEX)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, LPTHREAD_START_ROUTINE StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList);
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
    typedef NTSTATUS (NTAPI* LPPROC_NTPROTECTVIRTUALMEMORY)(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
    // NtFreeVirtualMemory
    typedef NTSTATUS (NTAPI* LPPROC_NTFREEVIRTUALMEMORY)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
    // NtDuplicateObject
    typedef NTSTATUS (NTAPI* LPPROC_NTDUPLICATEOBJECT)(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options);
    // NtWaitForSingleObject
    typedef NTSTATUS (NTAPI* LPPROC_NTWAITFORSINGLEOBJECT)(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
    // NtClose
	typedef NTSTATUS (NTAPI* LPPROC_NTCLOSE)(HANDLE Handle);
    // NtCreateFile
    typedef NTSTATUS (NTAPI* LPPROC_NTCREATEFILE)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
    // NtOpenFile
    typedef NTSTATUS (NTAPI* LPPROC_NTOPENFILE)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);
    // NtReadFile
    typedef NTSTATUS (NTAPI* LPPROC_NTREADFILE)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
    // NtWriteFile
    typedef NTSTATUS (NTAPI* LPPROC_NTWRITEFILE)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
    // NtDeleteFile
    typedef NTSTATUS (NTAPI* LPPROC_NTDELETEFILE)(POBJECT_ATTRIBUTES ObjectAttributes);
    // NtCreateNamedPipeFile
    typedef NTSTATUS (NTAPI* LPPROC_NTCREATENAMEDPIPEFILE)(PHANDLE FileHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, ULONG NamedPipeType, ULONG ReadMode, ULONG CompletionMode, ULONG MaximumInstances, ULONG InboundQuota, ULONG OutboundQuota, PLARGE_INTEGER DefaultTimeout);
    // NtQueryInformationProcess
    typedef NTSTATUS (NTAPI* LPPROC_NTQUERYINFORMATIONPROCESS)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
    // NtQueryInformationFile
    typedef NTSTATUS (NTAPI* LPPROC_NTQUERYINFORMATIONFILE)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
    // NtSetInformationFile
    typedef NTSTATUS (NTAPI* LPPROC_NTSETINFORMATIONFILE)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
    // NtQueryInformationToken
    typedef NTSTATUS (NTAPI* LPPROC_NTQUERYINFORMATIONTOKEN)(HANDLE HandleToken, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength, PULONG ReturnLength);
    // NtQuerySystemInformation
    typedef NTSTATUS (NTAPI* LPPROC_NTQUERYSYSTEMINFORMATION)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
    // NtSystemDebugControl
    typedef NTSTATUS (NTAPI* LPPROC_NTSYSTEMDEBUGCONTROL)(SYSDBG_COMMAND Command, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength);
    // NtPrivilegeCheck
    typedef NTSTATUS (NTAPI* LPPROC_NTPRIVILEGECHECK)(HANDLE ClientToken, PPRIVILEGE_SET RequiredPrivileges, PBOOLEAN Result);
    // NtAdjustPrivilegesToken
    typedef NTSTATUS (NTAPI* LPPROC_NTADJUSTPRIVILEGESTOKEN)(HANDLE TokenHandle, BOOLEAN DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, ULONG BufferLength, PTOKEN_PRIVILEGES PreviousState, PULONG ReturnLength);
    // NtOpenKeyEx
    typedef NTSTATUS (NTAPI* LPPROC_NTOPENKEYEX)(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG OpenOptions);
    // NtQueryKey
    typedef NTSTATUS (NTAPI* LPPROC_NTQUERYKEY)(HANDLE KeyHandle, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength);
    // NtEnumerateValueKey
    typedef NTSTATUS (NTAPI* LPPROC_NTENUMERATEVALUEKEY)(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);
    // NtUnmapViewOfSection
    typedef NTSTATUS (NTAPI* LPPROC_NTUNMAPVIEWOFSECTION)(HANDLE ProcessHandle, PVOID BaseAddress);

    // **NATIVE APIs (RUNTIME LIBRARY)**
    // RtlAllocateHeap
    typedef PVOID (NTAPI* LPPROC_RTLALLOCATEHEAP)(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
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
    // RtlGetCurrentDirectory_U
    typedef ULONG (NTAPI* LPPROC_RTLGETCURRENTDIRECTORY_U)(ULONG BufferLength, PWSTR Buffer);
    // RtlSetCurrentDirectory_U
    typedef NTSTATUS (NTAPI* LPPROC_RTLSETCURRENTDIRECTORY_U)(PUNICODE_STRING PathName);
    // RtlGetFullPathName_U
    typedef NTSTATUS (NTAPI* LPPROC_RTLGETFULLPATHNAME_U)(PCWSTR FileName, ULONG BufferLength, PWSTR Buffer, PWSTR *FilePart);
    
    // **WINAPIs**
    // LoadLibraryA
    typedef HMODULE (WINAPI* LPPROC_LOADLIBRARYA)(LPCSTR lpLibFileName);
    // LoadLibraryW
    typedef HMODULE (WINAPI* LPPROC_LOADLIBRARYW)(LPCWSTR lpLibFileName);
    // GetProcAddress
    typedef FARPROC (WINAPI* LPPROC_GETPROCADDRESS)(HMODULE hModule, LPCSTR lpProcName);
    // QueryFullProcessImageNameW
    typedef BOOL (WINAPI* LPPROC_QUERYFULLPROCESSIMAGENAMEW)(HANDLE hProcess, DWORD  dwFlags, LPWSTR lpExeName, PDWORD lpdwSize);
    // RtlAddFunctionTable
    typedef BOOL (WINAPI* LPPROC_RTLADDFUNCTIONTABLE)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
    // DllMain
    typedef BOOL (WINAPI* LPPROC_DLLMAIN)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
    // VirtualAlloc
    typedef LPVOID (WINAPI* LPPROC_VIRTUALALLOC)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    // VirtualProtect
    typedef BOOL (WINAPI* LPPROC_VIRTUALPROTECT)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
    // VirtualFree
    typedef BOOL (WINAPI* LPPROC_VIRTUALFREE)(LPVOID lpAddress, SIZE_T dwSize, DWORD  dwFreeType);
    // closeHandle
    typedef BOOL (WINAPI* LPPROC_CLOSEHANDLE)(HANDLE hObject);
    // SetFileInformationByHandle
    typedef BOOL (WINAPI* LPPROC_SETFILEINFORMATIONBYHANDLE)(HANDLE hFile, FILE_INFO_BY_HANDLE_CLASS FileInformationClass, LPVOID lpFileInformation, DWORD dwBufferSize);
    // MessageBoxA
    typedef int (WINAPI* LPPROC_MESSAGEBOXA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
    // WinHttpOpen
    typedef HINTERNET (WINAPI* LPPROC_WINHTTPOPEN)(LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags);
    // WinHttpConnect
    typedef HINTERNET (WINAPI* LPPROC_WINHTTPCONNECT)(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved);
    // WinHttpOpenRequest
    typedef HINTERNET (WINAPI* LPPROC_WINHTTPOPENREQUEST)(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR *ppwszAcceptTypes, DWORD dwFlags);
    // WinHttpSetOption
    typedef BOOL (WINAPI* LPPROC_WINHTTPSETOPTION)(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength);
    // WinHttpSendRequest
    typedef BOOL (WINAPI* LPPROC_WINHTTPSENDREQUEST)(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext);
    // WinHttpWriteData
    typedef BOOL (WINAPI* LPPROC_WINHTTPWRITEDATA)(HINTERNET hRequest, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten);
    // WinHttpReceiveResponse
    typedef BOOL (WINAPI* LPPROC_WINHTTPRECEIVERESPONSE)(HINTERNET hRequest, LPVOID lpReserved);
    // winHttpQueryHeaders
    typedef BOOL (WINAPI* LPPROC_WINHTTPQUERYHEADERS)(HINTERNET hRequest, DWORD dwInfoLevel, LPCWSTR pwszName, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);
    // WinHttpQueryDataAvailable
    typedef BOOL (WINAPI* LPPROC_WINHTTPQUERYDATAAVAILABLE)(HINTERNET hRequest, LPDWORD lpdwNumberOfBytesAvailable);
    // WinHttpReadData
    typedef BOOL (WINAPI* LPPROC_WINHTTPREADDATA)(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesLength, LPDWORD lpdwNumberOfBytesRead);
    // WinHttpCloseHandle
    typedef BOOL (WINAPI* LPPROC_WINHTTPCLOSEHANDLE)(HINTERNET hInternet);

    struct PROCS
    {
        // **NATIVE APIs**
        LPPROC_NTCREATEPROCESSEX            lpNtCreateProcessEx                 = nullptr;
        LPPROC_NTOPENPROCESS                lpNtOpenProcess                     = nullptr;
        LPPROC_NTOPENPROCESSTOKEN           lpNtOpenProcessToken                = nullptr;
        LPPROC_NTTERMINATEPROCESS           lpNtTerminateProcess                = nullptr;
        LPPROC_NTSETINFORMATIONPROCESS      lpNtSetInformationProcess           = nullptr;
        LPPROC_NTCREATETHREADEX             lpNtCreateThreadEx                  = nullptr;
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
        LPPROC_NTOPENFILE                   lpNtOpenFile                        = nullptr;
        LPPROC_NTREADFILE                   lpNtReadFile                        = nullptr;
        LPPROC_NTWRITEFILE                  lpNtWriteFile                       = nullptr;
        LPPROC_NTDELETEFILE                 lpNtDeleteFile                      = nullptr;
        LPPROC_NTCREATENAMEDPIPEFILE        lpNtCreateNamedPipeFile             = nullptr;
        LPPROC_NTQUERYINFORMATIONPROCESS    lpNtQueryInformationProcess         = nullptr;
        LPPROC_NTQUERYINFORMATIONFILE       lpNtQueryInformationFile            = nullptr;
        LPPROC_NTQUERYINFORMATIONTOKEN      lpNtQueryInformationToken           = nullptr;
        LPPROC_NTSETINFORMATIONFILE         lpNtSetInformationFile              = nullptr;
        LPPROC_NTQUERYSYSTEMINFORMATION     lpNtQuerySystemInformation          = nullptr;
        LPPROC_NTSYSTEMDEBUGCONTROL         lpNtSystemDebugControl              = nullptr;
        LPPROC_NTPRIVILEGECHECK             lpNtPrivilegeCheck                  = nullptr;
        LPPROC_NTADJUSTPRIVILEGESTOKEN      lpNtAdjustPrivilegesToken           = nullptr;
        LPPROC_NTOPENKEYEX                  lpNtOpenKeyEx                       = nullptr;
        LPPROC_NTQUERYKEY                   lpNtQueryKey                        = nullptr;
        LPPROC_NTENUMERATEVALUEKEY          lpNtEnumerateValueKey               = nullptr;
        LPPROC_NTUNMAPVIEWOFSECTION         lpNtUnmapViewOfSection              = nullptr;

        // **RUNTIME LIBRARY APIs**
        LPPROC_RTLALLOCATEHEAP              lpRtlAllocateHeap                   = nullptr;
        LPPROC_RTLINITUNICODESTRING         lpRtlInitUnicodeString              = nullptr;
        LPPROC_RTLSTRINGCCHCATW             lpRtlStringCchCatW                  = nullptr;
        LPPROC_RTLSTRINGCCHCOPYW            lpRtlStringCchCopyW                 = nullptr;
        LPPROC_RTLSTRINGCCHLENGTHW          lpRtlStringCchLengthW               = nullptr;
        LPPROC_RTLQUERYSYSTEMINFORMATION    lpRtlQuerySystemInformation         = nullptr;
        LPPROC_RTLEXPANDENVIRONMENTSTRINGS  lpRtlExpandEnvironmentStrings       = nullptr;
        LPPROC_RTLGETCURRENTDIRECTORY_U     lpRtlGetCurrentDirectory_U          = nullptr;
        LPPROC_RTLSETCURRENTDIRECTORY_U     lpRtlSetCurrentDirectory_U          = nullptr;
        LPPROC_RTLGETFULLPATHNAME_U         lpRtlGetFullPathName_U              = nullptr;

        // **WINAPIs**
        LPPROC_QUERYFULLPROCESSIMAGENAMEW   lpQueryFullProcessImageNameW        = nullptr;
        LPPROC_SETFILEINFORMATIONBYHANDLE   lpSetFileInformationByHandle        = nullptr;
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
        Syscalls::SYSCALL                   sysNtSetInformationProcess          = {0};
        Syscalls::SYSCALL                   sysNtCreateThreadEx                 = {0};
        Syscalls::SYSCALL                   sysNtResumeThread                   = {0};
        Syscalls::SYSCALL                   sysNtGetContextThread               = {0};
        Syscalls::SYSCALL                   sysNtSetContextThread               = {0};
        Syscalls::SYSCALL                   sysNtAllocateVirtualMemory          = {0};
        Syscalls::SYSCALL                   sysNtReadVirtualMemory              = {0};
        Syscalls::SYSCALL                   sysNtWriteVirtualMemory             = {0};
        Syscalls::SYSCALL                   sysNtProtectVirtualMemory           = {0};
        Syscalls::SYSCALL                   sysNtFreeVirtualMemory              = {0};
        Syscalls::SYSCALL                   sysNtDuplicateObject                = {0};
        Syscalls::SYSCALL                   sysNtWaitForSingleObject            = {0};
        Syscalls::SYSCALL                   sysNtClose                          = {0};
        Syscalls::SYSCALL                   sysNtOpenFile                       = {0};
        Syscalls::SYSCALL                   sysNtCreateFile                     = {0};
        Syscalls::SYSCALL                   sysNtReadFile                       = {0};
        Syscalls::SYSCALL                   sysNtWriteFile                      = {0};
        Syscalls::SYSCALL                   sysNtDeleteFile                     = {0};
        Syscalls::SYSCALL                   sysNtCreateNamedPipeFile            = {0};
        Syscalls::SYSCALL                   sysNtQueryInformationProcess        = {0};
        Syscalls::SYSCALL                   sysNtQueryInformationFile           = {0};
        Syscalls::SYSCALL                   sysNtSetInformationFile             = {0};
        Syscalls::SYSCALL                   sysNtQueryInformationToken          = {0};
        Syscalls::SYSCALL                   sysNtQuerySystemInformation         = {0};
        Syscalls::SYSCALL                   sysNtSystemDebugControl             = {0};
        Syscalls::SYSCALL                   sysNtPrivilegeCheck                 = {0};
        Syscalls::SYSCALL                   sysNtAdjustPrivilegesToken          = {0};
        Syscalls::SYSCALL                   sysNtOpenKeyEx                      = {0};
        Syscalls::SYSCALL                   sysNtQueryKey                       = {0};
        Syscalls::SYSCALL                   sysNtEnumerateValueKey              = {0};
        Syscalls::SYSCALL                   sysNtUnmapViewOfSection             = {0};

        Syscalls::SYSCALL                   sysRtlAllocateHeap                  = {0};
        Syscalls::SYSCALL                   sysRtlInitUnicodeString             = {0};
        Syscalls::SYSCALL                   sysRtlStringCchCatW                 = {0};
        Syscalls::SYSCALL                   sysRtlStringCchCopyW                = {0};
        Syscalls::SYSCALL                   sysRtlStringCchLengthW              = {0};
        Syscalls::SYSCALL                   sysRtlQuerySystemInformation        = {0};
        Syscalls::SYSCALL                   sysRtlExpandEnvironmentStrings      = {0};
        Syscalls::SYSCALL                   sysRtlGetCurrentDirectory_U         = {0};
        Syscalls::SYSCALL                   sysRtlSetCurrentDirectory_U         = {0};
        Syscalls::SYSCALL                   sysRtlGetFullPathName_U             = {0};
    };
    typedef PROCS* PPROCS;

    PPROCS FindProcs(
        HMODULE hNTDLL,
        HMODULE hKernel32DLL,
        HMODULE hWinHTTPDLL,
        BOOL bIndirectSyscalls
    );
}

#endif // HERMIT_CORE_PROCS_HPP
