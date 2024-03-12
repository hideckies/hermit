#include "inject.hpp"

BOOL DllInjection(DWORD dwPid, LPVOID lpDllPath, size_t dwDllPathSize)
{
    HANDLE hProcess;
    HANDLE hThread;
    PVOID remoteBuffer;
    BOOL bResults;

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
    if (!hProcess)
    {
        return FALSE;
    }
    
    remoteBuffer = VirtualAllocEx(
        hProcess,
        NULL,
        dwDllPathSize,
        MEM_COMMIT,
        PAGE_READWRITE
    );
    if (!remoteBuffer)
    {
        return FALSE;
    }

    bResults = WriteProcessMemory(
        hProcess,
        remoteBuffer,
        lpDllPath,
        dwDllPathSize,
        NULL
    );
    if (!bResults)
    {
        return FALSE;
    }

    PTHREAD_START_ROUTINE threadStartRoutineAddr = (PTHREAD_START_ROUTINE)GetProcAddress(
        GetModuleHandle(TEXT("kernel32")),
        "LoadLibraryW"
    );
    if (!threadStartRoutineAddr)
    {
        return FALSE;
    }

    hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        threadStartRoutineAddr,
        remoteBuffer,
        0,
        NULL
    );
    if (!hThread)
    {
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hProcess);
    CloseHandle(hThread);

    return TRUE;
}