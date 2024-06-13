#ifndef HERMIT_HPP
#define HERMIT_HPP

#include <windows.h>
#include <winhttp.h>

#include "core/crypt.hpp"
#include "core/handler.hpp"
#include "core/macros.hpp"
#include "core/procs.hpp"
#include "core/state.hpp"
#include "core/system.hpp"
#include "core/technique.hpp"
#include "core/utils.hpp"

#define DLL_QUERY_HMODULE 6

// This is used for a DLL beacon.
DWORD WINAPI RunWrapper(LPVOID lpParam);

namespace Hermit
{
    State::PSTATE Init();
    std::vector<BYTE> Download(State::PSTATE pState);

    VOID DllLoader();
    VOID PeLoader();
    VOID ShellcodeLoader();
}

#endif // HERMIT_HPP