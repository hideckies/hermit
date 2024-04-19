#ifndef HERMIT_CORE_HANDLER_HPP
#define HERMIT_CORE_HANDLER_HPP

#include <windows.h>
#include <string>
#include "core/macros.hpp"
#include "core/state.hpp"
#include "core/system.hpp"
#include "core/utils.hpp"

namespace Handler
{
    VOID HTTPInit(State::PSTATE pState);
    VOID GetInitialInfoJSON(State::PSTATE pState);
}

#endif // HERMIT_CORE_HANDLER_HPP