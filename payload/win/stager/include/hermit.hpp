#ifndef HERMIT_HERMIT_HPP
#define HERMIT_HERMIT_HPP

#include <windows.h>
#include <winhttp.h>
#include "inject.hpp"
#include "winhttp.hpp"
#include "winsystem.hpp"

BOOL LoadDLL();
BOOL LoadExecutable();
BOOL LoadShellcode();

#endif // HERMIT_HERMIT_HPP