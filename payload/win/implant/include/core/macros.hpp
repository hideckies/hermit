#ifndef HERMIT_CORE_MACROS_HPP
#define HERMIT_CORE_MACROS_HPP

// DLL
#define DLLEXPORT __declspec(dllexport)

// COMMON
#define MAX_TRIES 3
#define MAX_BUFFER_SIZE 65536
#define INFO_BUFFER_SIZE 32767
#define BUFFER_SIZE 8192
#define WORKING_BUFFER_SIZE 15000
#define MAX_REG_KEY_LENGTH 255
#define MAX_REG_VALUE_NAME 16383
#define NUMHOOKS 7
#define IDS_APP_TITLE 1
#define IDC_GDICAPTURINGANIMAGE 1
#define IDI_GDICAPTURINGANIMAGE 2
#define IDI_SMALL 3
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
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

#endif // HERMIT_CORE_MACROS_HPP