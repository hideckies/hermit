#include "hermit.hpp"

namespace Hermit
{
    #if MODULE_TYPE == MODULE_TYPE_CALC
    VOID RunCalc()
    {
        STARTUPINFO si = { sizeof(si) };
        PROCESS_INFORMATION pi;

        if (CreateProcessW(
            L"C:\\Windows\\System32\\calc.exe",
            NULL,
            NULL,
            NULL,
            FALSE,
            0,
            NULL,
            NULL,
            &si,
            &pi
        )) {
            WaitForSingleObject(pi.hProcess, INFINITE);

            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
    #elif MODULE_TYPE == MODULE_TYPE_MESSAGEBOX
    VOID RunMessageBox()
    {
        MessageBoxA(NULL, "Hello World", "Hermit Module", MB_OK);
    }
    #endif

    VOID Run()
    {
        #if MODULE_TYPE == MODULE_TYPE_CALC
            RunCalc();
        #elif MODULE_TYPE == MODULE_TYPE_MESSAGEBOX
            RunMessageBox();
        #endif
    }
}
