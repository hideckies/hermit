#ifndef HERMIT_HPP
#define HERMIT_HPP

#include <windows.h>

#include "core/handler.hpp"
#include "core/procs.hpp"
#include "core/system.hpp"
#include "core/technique.hpp"
#include "core/utils.hpp"

namespace Hermit
{
    VOID DLLLoader();
    VOID ExecLoader();
    VOID ShellcodeLoader();

    VOID Free(
        HMODULE hWinHTTPDLL,
        Procs::PPROCS pProcs,
        HINTERNET hSession,
        HINTERNET hConnect,
        HINTERNET hRequest
    );
}

#endif // HERMIT_HPP