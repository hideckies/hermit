#ifndef HERMIT_ENTRY_HPP
#define HERMIT_ENTRY_HPP

#include "core/macros.hpp"
#include "core/nt.hpp"
#include "core/procs.hpp"

#include <windows.h>

typedef ULONG_PTR (WINAPI * REFLECTIVEDLLLOADER)();

extern "C" VOID AlignRSP();
extern "C" VOID Entry();
extern "C" LPVOID  ReflectiveCaller();

#endif // HERMIT_ENTRY_HPP