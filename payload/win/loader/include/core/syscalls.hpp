#ifndef HERMIT_CORE_SYSCALLS_HPP
#define HERMIT_CORE_SYSCALLS_HPP

#include "core/macros.hpp"
#include "core/stdout.hpp"
#include "core/utils.hpp"

#include <windows.h>

#define UP   -32
#define DOWN 32

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
	WORD FindSyscallFromImageBase(
        PVOID pModuleBase,
        PIMAGE_EXPORT_DIRECTORY pExportDir,
        DWORD dwSysFuncHash
    );
}

#endif // HERMIT_CORE_SYSCALLS_HPP