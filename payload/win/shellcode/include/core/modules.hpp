#ifndef HERMIT_MODULES_HPP
#define HERMIT_MODULES_HPP

#include "core/macros.hpp"
#include "core/nt.hpp"
#include "core/utils.hpp"

#include <windows.h>

namespace Modules
{
    HMODULE GetModuleByName(WCHAR* wModuleName);
}


#endif // HERMIT_MODULES_HPP