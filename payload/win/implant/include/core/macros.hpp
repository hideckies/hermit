#ifndef HERMIT_CORE_MACROS_HPP
#define HERMIT_CORE_MACROS_HPP

// DLL
#define DLLEXPORT extern "C" __declspec(dllexport)

// PEB
#ifdef _WIN64
#define PPEB_PTR __readgsqword(0x60)
#else
#define PPEB_PTR __readfsqword(0x30)
#endif

// VALUES
#define INFO_BUFFER_SIZE 32767

// FUNCTIONS
#define FREE(x)     HeapFree(GetProcessHeap(), 0, (x))
#define MALLOC(x)   HeapAlloc(GetProcessHeap(), 0, (x))

#define DEREF(name)     *(UINT_PTR*)(name)
#define DEREF_64(name)  *(DWORD64*)(name)
#define DEREF_32(name)  *(DWORD*)(name)
#define DEREF_16(name)  *(WORD*)(name)
#define DEREF_8(name)   *(BYTE*)(name)

#define HTONS16( x ) __builtin_bswap16( x )
#define HTONS32( x ) __builtin_bswap32( x )

#define MEMCPY  __builtin_memcpy

#ifndef TO_LOWERCASE
#define TO_LOWERCASE(c1, out) (out = (c1 <= 'Z' && c1 >= 'A') ? c1 = (c1 - 'A') + 'a': c1)
#endif

#define WIDEN(x) WIDEN2(x)
#define WIDEN2(x) L##x

// PAYLOAD FLAGS
#ifdef PAYLOAD_TYPE
#define PAYLOAD_TYPE_W WIDEN(PAYLOAD_TYPE)
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

#ifdef REQUEST_PATH_CHECKIN
#define REQUEST_PATH_CHECKIN_W WIDEN(REQUEST_PATH_CHECKIN)
#endif

#ifdef REQUEST_PATH_DOWNLOAD
#define REQUEST_PATH_DOWNLOAD_W WIDEN(REQUEST_PATH_DOWNLOAD)
#endif

#ifdef REQUEST_PATH_TASKGET
#define REQUEST_PATH_TASKGET_W WIDEN(REQUEST_PATH_TASKGET)
#endif

#ifdef REQUEST_PATH_TASKRESULT
#define REQUEST_PATH_TASKRESULT_W WIDEN(REQUEST_PATH_TASKRESULT)
#endif

#ifdef REQUEST_PATH_UPLOAD
#define REQUEST_PATH_UPLOAD_W WIDEN(REQUEST_PATH_UPLOAD)
#endif

#ifdef REQUEST_PATH_WEBSOCKET
#define REQUEST_PATH_WEBSOCKET_W WIDEN(REQUEST_PATH_WEBSOCKET)
#endif

#ifdef REQUEST_PATH_SOCKET_OPEN
#define REQUEST_PATH_SOCKET_OPEN_W WIDEN(REQUEST_PATH_SOCKET_OPEN)
#endif

#ifdef REQUEST_PATH_SOCKET_CLOSE
#define REQUEST_PATH_SOCKET_CLOSE_W WIDEN(REQUEST_PATH_SOCKET_CLOSE)
#endif

#ifdef AES_KEY_BASE64
#define AES_KEY_BASE64_W WIDEN(AES_KEY_BASE64)
#endif

#ifdef AES_IV_BASE64
#define AES_IV_BASE64_W WIDEN(AES_IV_BASE64)
#endif

#endif // HERMIT_CORE_MACROS_HPP