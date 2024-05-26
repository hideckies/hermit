#ifndef HERMIT_CORE_HANDLER_HPP
#define HERMIT_CORE_HANDLER_HPP

#include "core/macros.hpp"
#include "core/state.hpp"
#include "core/system.hpp"
#include "core/utils.hpp"

#include <windows.h>
#include <string>

namespace Handler
{
    VOID HTTPInit(State::PSTATE pState);
    std::wstring GetInitialInfoJSON(State::PSTATE pState);
}

#endif // HERMIT_CORE_HANDLER_HPP