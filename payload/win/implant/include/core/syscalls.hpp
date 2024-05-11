// Reference:
// https://github.com/HavocFramework/Havoc/blob/ea3646e055eb1612dcc956130fd632029dbf0b86/payloads/Demon/include/core/SysNative.h

#ifndef HERMIT_CORE_SYSCALLS_HPP
#define HERMIT_CORE_SYSCALLS_HPP

#include "core/utils.hpp"

#include <windows.h>

extern "C" VOID 	SysSet(void*);
extern "C" NTSTATUS SysInvoke(...);

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

	SYSCALL FindSyscall(UINT_PTR pNtFuncAddr);
}

#endif // HERMIT_CORE_SYSCALLS_HPP