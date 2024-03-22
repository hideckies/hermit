#ifndef HERMIT_HPP
#define HERMIT_HPP

#include <windows.h>
#include <winhttp.h>
#include "core/handler.hpp"
#include "core/system.hpp"
#include "core/technique.hpp"
#include "core/utils.hpp"

namespace Hermit
{
    BOOL LoadDLL();
    BOOL LoadExecutable();
    BOOL LoadShellcode();
}

#endif // HERMIT_HPP