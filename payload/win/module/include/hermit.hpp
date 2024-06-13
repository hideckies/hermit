#ifndef HERMIT_HERMIT_HPP
#define HERMIT_HERMIT_HPP

#include "core/macros.hpp"
#include "core/nt.hpp"
#include "core/modules.hpp"
#include "core/procs.hpp"

#include <windows.h>

#define DLL_QUERY_HMODULE 6

DWORD WINAPI RunWrapper(LPVOID lpParam);

namespace Hermit
{
    #if MODULE_TYPE == MODULE_TYPE_CALC
    VOID RunCalc();
    #elif MODULE_TYPE == MODULE_TYPE_MESSAGEBOX
    VOID RunMessageBox();
    #endif
    VOID Run();
}

#endif // HERMIT_HERMIT_HPP