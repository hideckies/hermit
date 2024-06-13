#ifndef HERMIT_MODULES_HPP
#define HERMIT_MODULES_HPP

#include "nt.hpp"
#include "core/procs.hpp"

#include <windows.h>
#include <ntstatus.h>

#define HASH_MODULE_NTDLL       0x3cd7873f
#define HASH_MODULE_KERNEL32    0xf4796887

namespace Modules
{
    struct MODULES
    {

    };

    typedef MODULES *PMODULES;

    ULONG StringToHashModule(WCHAR* wStr, SIZE_T dwStrLen);
    PVOID GetModuleByHash(DWORD dwHash);
}

#endif // HERMIT_MODULES_HPP