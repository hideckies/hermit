// Reference:
// https://github.com/HavocFramework/Havoc/blob/ea3646e055eb1612dcc956130fd632029dbf0b86/payloads/Demon/include/core/SysNative.h

#ifndef HERMIT_CORE_SYSCALLS_HPP
#define HERMIT_CORE_SYSCALLS_HPP

#include <winternl.h>
#include <windows.h>

// #ifndef InitializeObjectAttributes
// #define InitializeObjectAttributes( p, n, a, r, s ) { \
// 	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
// 	(p)->RootDirectory = r;                           \
// 	(p)->Attributes = a;                              \
// 	(p)->ObjectName = n;                              \
// 	(p)->SecurityDescriptor = s;                      \
// 	(p)->SecurityQualityOfService = NULL;             \
// }
// #endif

typedef struct _PS_ATTRIBUTE
{
	ULONG  Attribute;
	SIZE_T Size;
	union
	{
		ULONG Value;
		PVOID ValuePtr;
	} u1;
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T       TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

// extern "C"
// {

	// Syscall Functions
	// NTSTATUS NtOpenProcess(
	// 	OUT    PHANDLE            ProcessHandle,
	// 	IN     ACCESS_MASK        DesiredAccess,
	// 	IN     POBJECT_ATTRIBUTES ObjectAttributes,
	// 	IN     PCLIENT_ID         ClientId OPTIONAL
	// );

	// NTSTATUS NtAllocateVirtualMemory(
	// 	IN     HANDLE             ProcessHandle,
	// 	IN OUT PVOID* BaseAddress,
	// 	IN     ULONG              ZeroBits,
	// 	IN OUT PSIZE_T            RegionSize,
	// 	IN     ULONG              AllocationType,
	// 	IN     ULONG              Protect
	// );

	// NTSTATUS NtWriteVirtualMemory(
	// 	IN     HANDLE             ProcessHandle,
	// 	IN     PVOID              BaseAddress,
	// 	IN     PVOID              Buffer,
	// 	IN     SIZE_T             NumberOfBytesToWrite,
	// 	OUT    PSIZE_T            NumberOfBytesWritten OPTIONAL
	// );

	// NTSTATUS NtCreateThreadEx(
	// 	OUT    PHANDLE            ThreadHandle,
	// 	IN     ACCESS_MASK        DesiredAccess,
	// 	IN     POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	// 	IN     HANDLE             ProcessHandle,
	// 	IN     PVOID              StartRoutine,
	// 	IN     PVOID              Argument OPTIONAL,
	// 	IN     ULONG              CreateFlags,
	// 	IN     SIZE_T             ZeroBits,
	// 	IN     SIZE_T             StackSize,
	// 	IN     SIZE_T             MaximumStackSize,
	// 	IN     PPS_ATTRIBUTE_LIST AttributeList OPTIONAL
	// );

	// NTSTATUS NtWaitForSingleObject(
	// 	IN     HANDLE             Handle,
	// 	IN     BOOLEAN            Alertable,
	// 	IN     PLARGE_INTEGER     Timeout
	// );

	// NTSTATUS NtClose(
	// 	IN     HANDLE             Handle
	// );
// }

namespace Syscalls
{
	struct SYSCALL
	{
		UINT_PTR	pAddr;
		DWORD		dwSSN;
	};
	typedef SYSCALL* PSYSCALL;

	struct SYSCALLS
	{
		SYSCALL sysNtOpenProcess;
		SYSCALL sysNtAllocateVirtualMemory;
		SYSCALL sysNtWriteVirtualMemory;
		SYSCALL sysNtCreateThreadEx;
		SYSCALL sysNtWaitForSingleObject;
		SYSCALL sysNtClose;
	};
	typedef SYSCALLS* PSYSCALLS;

	SYSCALL		FindSyscall(HMODULE hNTDLL, LPCSTR lpNtFunc);
	PSYSCALLS 	FindSyscalls(HMODULE hNTDLL);
}

#endif // HERMIT_CORE_SYSCALLS_HPP