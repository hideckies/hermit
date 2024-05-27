#ifndef HERMIT_CORE_MACROS_HPP
#define HERMIT_CORE_MACROS_HPP

#include <windows.h>

// DLL
#define DLLEXPORT __declspec(dllexport)

// SHELLCODE
#define SHELLCODE(x) (ULONG_PTR)(GetIp() - ((ULONG_PTR) & GetIp - (ULONG_PTR)x))
#define SECTION(x) __attribute__((section(".text$" #x)))

// PEB
#ifdef _WIN64
#define PPEB_PTR __readgsqword(0x60)
#else
#define PPEB_PTR __readfsqword(0x30)
#endif

// VALUES
#define INFO_BUFFER_SIZE 32767

// FUNCTIONS
#define DEREF(name)     *(UINT_PTR*)(name)
#define DEREF_64(name)  *(DWORD64*)(name)
#define DEREF_32(name)  *(DWORD*)(name)
#define DEREF_16(name)  *(WORD*)(name)
#define DEREF_8(name)   *(BYTE*)(name)

#define MEMCPY __builtin_memcpy

#define SLEEP(n) Sleep(n * 1000)

#define WIDEN(x) WIDEN2(x)
#define WIDEN2(x) L##x

// PAYLOAD FLAGS
#ifdef PAYLOAD_TYPE
#define PAYLOAD_TYPE_W WIDEN(PAYLOAD_TYPE)
#endif

#ifdef PAYLOAD_TECHNIQUE
#define PAYLOAD_TECHNIQUE_W WIDEN(PAYLOAD_TECHNIQUE)
#endif

#ifdef PAYLOAD_PROCESS_TO_INJECT
#define PAYLOAD_PROCESS_TO_INJECT_W WIDEN(PAYLOAD_PROCESS_TO_INJECT)
#endif

#ifdef LISTENER_PROTOCOL
#define LISTENER_PROTOCOL_W WIDEN(LISTENER_PROTOCOL)
#endif

#ifdef LISTENER_HOST
#define LISTENER_HOST_W WIDEN(LISTENER_HOST)
#endif

#ifdef LISTENER_USER_AGENT
#define LISTENER_USER_AGENT_W WIDEN(LISTENER_USER_AGENT)
#endif

#ifdef REQUEST_PATH_DOWNLOAD
#define REQUEST_PATH_DOWNLOAD_W WIDEN(REQUEST_PATH_DOWNLOAD)
#endif

#ifdef AES_KEY_BASE64
#define AES_KEY_BASE64_W WIDEN(AES_KEY_BASE64)
#endif

#ifdef AES_IV_BASE64
#define AES_IV_BASE64_W WIDEN(AES_IV_BASE64)
#endif

#endif // HERMIT_CORE_MACROS_HPP