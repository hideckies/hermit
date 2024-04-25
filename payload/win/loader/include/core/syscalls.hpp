#ifndef HERMIT_CORE_SYSCALLS_HPP
#define HERMIT_CORE_SYSCALLS_HPP

#include "core/utils.hpp"

#include <winternl.h>
#include <windows.h>

extern "C" DWORD 	SysSample(void*);
extern "C" VOID 	SysSet(void*);
extern "C" NTSTATUS SysInvoke(...);

extern "C" DWORD SysNumber;

template<typename FirstArg, typename SecondArg, typename... Args>
NTSTATUS CallSysInvoke(FirstArg pSyscall, SecondArg lpProc, Args... args)
{
	NTSTATUS status;

	if (pSyscall->dwSSN == 0)
	{
		status = lpProc(args...);
	}
	else
	{
		SysSet(pSyscall);
		status = SysInvoke(args...);
	}

	return status;
}

namespace Syscalls
{
	struct SYSCALL
	{
		UINT_PTR	pAddr;
		DWORD		dwSSN;
	};
	typedef SYSCALL* PSYSCALL;

	SYSCALL FindSyscall(HMODULE hNTDLL, LPCSTR lpNtFunc);
}

#endif // HERMIT_CORE_SYSCALLS_HPP