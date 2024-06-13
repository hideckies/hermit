#ifndef HERMIT_MACROS_HPP
#define HERMIT_MACROS_HPP

// DLL
#define DLLEXPORT extern "C" __declspec(dllexport)

// PEB
#ifdef _WIN64
#define PPEB_PTR __readgsqword(0x60)
#else
#define PPEB_PTR __readfsqword(0x30)
#endif

// FUNCTIONS
#define MEMCPY  __builtin_memcpy

// MODULE TYPE
#define MODULE_TYPE_CALC        1
#define MODULE_TYPE_MESSAGEBOX  2

#endif // HERMIT_MACROS_HPP
