#include "entry.hpp"

using DLLEntry = BOOL(WINAPI *)(HINSTANCE dll, DWORD reason, LPVOID reserved);

// For 64 bit shellcodes we will set this as the entrypoint
// void AlignRSP()
// {
//     // AT&T syntax
//     // asm("push %rsi\n"
//     //     "mov % rsp, % rsi\n"
//     //     "and $0x0FFFFFFFFFFFFFFF0, % rsp\n"
//     //     "sub $0x020, % rsp\n"
//     //     "call Entry\n"
//     //     "mov % rsi, % rsp\n"
//     //     "pop % rsi\n"
//     //     "ret\n");

//     // Intel syntax
//     asm("push rsi\n"
//         "mov rsi, rsp\n"
//         "and rsp, 0x0FFFFFFFFFFFFFFF0\n"
//         "sub rsp, 0x020\n"
//         "call Entry\n"
//         "mov rsp, rsi\n"
//         "pop rsi\n"
//         "ret\n");
// }

VOID ResolveIAT(
	LPVOID lpVirtualAddr,
	LPVOID lpIatDir,
	Procs::LPPROC_LOADLIBRARYA lpLoadLibraryA,
	Procs::LPPROC_GETPROCADDRESS lpGetProcAddress
) {
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = nullptr;

	for (pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)lpIatDir; pImportDescriptor->Name != 0; ++pImportDescriptor)
    {
		HMODULE hImportModule = lpLoadLibraryA(
			(LPCSTR)((ULONG_PTR)lpVirtualAddr + pImportDescriptor->Name)
		);

		PIMAGE_THUNK_DATA pOriginalTD = (PIMAGE_THUNK_DATA)((ULONG_PTR)lpVirtualAddr + pImportDescriptor->OriginalFirstThunk);
		PIMAGE_THUNK_DATA pFirstTD = (PIMAGE_THUNK_DATA)((ULONG_PTR)lpVirtualAddr + pImportDescriptor->FirstThunk);

		for (; pOriginalTD->u1.Ordinal != 0; ++pOriginalTD, ++pFirstTD)
        {
			if (IMAGE_SNAP_BY_ORDINAL(pOriginalTD->u1.Ordinal))
			{
				PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)hImportModule + ((PIMAGE_DOS_HEADER)hImportModule)->e_lfanew);
				PIMAGE_DATA_DIRECTORY pImageDir = (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
				PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)hImportModule + (ULONG_PTR)lpIatDir);

				ULONG_PTR uFuncAddresses = (ULONG_PTR)hImportModule + pExportDir->AddressOfFunctions;
				uFuncAddresses += ((IMAGE_ORDINAL(pOriginalTD->u1.Ordinal) - pExportDir->Base) * sizeof(DWORD));

				ULONGLONG lpFunc = (ULONGLONG)((ULONG_PTR)hImportModule + uFuncAddresses);
				if (lpFunc)
				{
					pFirstTD->u1.Function = lpFunc;
				}
			}
            else
			{
				PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)lpVirtualAddr + pOriginalTD->u1.AddressOfData);
				
				ULONGLONG lpFunc = (ULONGLONG)lpGetProcAddress(hImportModule, (LPCSTR)pImportByName->Name);
				if (lpFunc)
				{
					pFirstTD->u1.Function = lpFunc;
				}
			}
        }
    }
}

VOID ReallocateSections(
	LPVOID lpVirtualAddr,
	LPVOID lpImageBase,
	LPVOID lpBaseRelocDir,
	PIMAGE_NT_HEADERS pNtHeaders
) {
	ULONG_PTR uOffset = (ULONG_PTR)lpVirtualAddr - pNtHeaders->OptionalHeader.ImageBase;

	// and we itterate through all entries...
	while(((PIMAGE_BASE_RELOCATION)lpBaseRelocDir)->SizeOfBlock)
	{
		ULONG_PTR uBaseRelocRVA = ((ULONG_PTR)lpVirtualAddr + ((PIMAGE_BASE_RELOCATION)lpBaseRelocDir)->VirtualAddress);
		ULONG_PTR uRelocEntry = (ULONG_PTR)lpBaseRelocDir + sizeof(IMAGE_BASE_RELOCATION);

		// Number of entries in this relocation block
		DWORD dwNumOfEntries = (((PIMAGE_BASE_RELOCATION)lpBaseRelocDir)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(Nt::IMAGE_RELOC);
		while(dwNumOfEntries--)
		{
			if(((Nt::PIMAGE_RELOC)uRelocEntry)->type == IMAGE_REL_BASED_DIR64)
			{
				*(ULONG_PTR*)(uBaseRelocRVA + ((Nt::PIMAGE_RELOC)uRelocEntry)->offset) += uOffset;
			}
			else if(((Nt::PIMAGE_RELOC)uRelocEntry)->type == IMAGE_REL_BASED_HIGHLOW)
			{
				*(DWORD *)(uBaseRelocRVA + ((Nt::PIMAGE_RELOC)uRelocEntry)->offset) += (DWORD)uOffset;
			}
			else if(((Nt::PIMAGE_RELOC)uRelocEntry)->type == IMAGE_REL_BASED_HIGH)
			{
				*(WORD *)(uBaseRelocRVA + ((Nt::PIMAGE_RELOC)uRelocEntry)->offset) += HIWORD(uOffset);
			}
			else if( ((Nt::PIMAGE_RELOC)uRelocEntry)->type == IMAGE_REL_BASED_LOW)
			{
				*(WORD *)(uBaseRelocRVA + ((Nt::PIMAGE_RELOC)uRelocEntry)->offset) += LOWORD(uOffset);
			}

			uRelocEntry += sizeof(Nt::IMAGE_RELOC);
		}

		lpBaseRelocDir = lpBaseRelocDir + ((PIMAGE_BASE_RELOCATION)lpBaseRelocDir)->SizeOfBlock;
	}
}

SEC(text, B) VOID Entry()
{
    // Get this base address.
	// LPVOID lpBaseAddr = ReflectiveCaller();
	ULONG_PTR uBaseAddr = 0x00;

	Nt::PPEB pPeb = (Nt::PPEB)PPEB_PTR;

	// -----------------------------------------------------------------------------
	// Get modules and functions
	// -----------------------------------------------------------------------------
	
	HMODULE hNtdll = (HMODULE)Modules::GetModuleByHash(HASH_MODULE_NTDLL);
	if (!hNtdll)
	{
		return;
	}
	HMODULE hKernel32 = (HMODULE)Modules::GetModuleByHash(HASH_MODULE_KERNEL32);
	if (!hKernel32)
	{
		return;
	}

    // Get functions
    Procs::LPPROC_LDRLOADDLL lpLdrLoadDll = reinterpret_cast<Procs::LPPROC_LDRLOADDLL>(Procs::GetProcAddressByHash(hNtdll, HASH_FUNC_LDRLOADDLL));
	Procs::LPPROC_NTFLUSHINSTRUCTIONCACHE lpNtFlushInstructionCache = reinterpret_cast<Procs::LPPROC_NTFLUSHINSTRUCTIONCACHE>(Procs::GetProcAddressByHash(hNtdll, HASH_FUNC_NTFLUSHINSTRUCTIONCACHE));
    
    Procs::LPPROC_GETPROCADDRESS lpGetProcAddress = reinterpret_cast<Procs::LPPROC_GETPROCADDRESS>(Procs::GetProcAddressByHash(hKernel32, HASH_FUNC_GETPROCADDRESS));
    Procs::LPPROC_LOADLIBRARYA lpLoadLibraryA = reinterpret_cast<Procs::LPPROC_LOADLIBRARYA>(Procs::GetProcAddressByHash(hKernel32, HASH_FUNC_LOADLIBRARYA));
    Procs::LPPROC_LOADLIBRARYW lpLoadLibraryW = reinterpret_cast<Procs::LPPROC_LOADLIBRARYW>(Procs::GetProcAddressByHash(hKernel32, HASH_FUNC_LOADLIBRARYW));
    Procs::LPPROC_VIRTUALALLOC lpVirtualAlloc = reinterpret_cast<Procs::LPPROC_VIRTUALALLOC>(Procs::GetProcAddressByHash(hKernel32, HASH_FUNC_VIRTUALALLOC));
	Procs::LPPROC_VIRTUALPROTECT lpVirtualProtect = reinterpret_cast<Procs::LPPROC_VIRTUALPROTECT>(Procs::GetProcAddressByHash(hKernel32, HASH_FUNC_VIRTUALPROTECT));

    // -----------------------------------------------------------------------------
	// Get other modules and functions
	// -----------------------------------------------------------------------------

    WCHAR wUser32[] = L"user32.dll";
    HMODULE hUser32 = (HMODULE)Modules::LoadModule(lpLdrLoadDll, (LPWSTR)wUser32);

    // Get functions
	Procs::LPPROC_MESSAGEBOXA lpMessageBoxA = reinterpret_cast<Procs::LPPROC_MESSAGEBOXA>(Procs::GetProcAddressByHash(hUser32, HASH_FUNC_MESSAGEBOXA));
	
	lpMessageBoxA(NULL, "This is 'dll-loader'.", "Test", MB_OK);
	
	// -----------------------------------------------------------------------------
	// Allocate virtual memory
	// -----------------------------------------------------------------------------
	
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(uBaseAddr + ((PIMAGE_DOS_HEADER)uBaseAddr)->e_lfanew);
	
	LPVOID lpVirtualAddr = lpVirtualAlloc(
        NULL,
        pNtHeaders->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );
	if (!lpVirtualAddr)
	{
		return;
	}

	PIMAGE_SECTION_HEADER pSecHeader = IMAGE_FIRST_SECTION(pNtHeaders);

	for (DWORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		MEMCPY(
			(LPVOID)(lpVirtualAddr + pSecHeader[i].VirtualAddress),
			(LPVOID)(uBaseAddr + pSecHeader[i].PointerToRawData),
			pSecHeader[i].SizeOfRawData
		);
	}
	
	// -----------------------------------------------------------------------------
    // Resolve IAT (Import Address Table)
	// -----------------------------------------------------------------------------
	
	PIMAGE_DATA_DIRECTORY pImageDir =  (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];	
	if (!pImageDir->VirtualAddress)
	{
		return;
	}
	ResolveIAT(
		lpVirtualAddr,
		(LPVOID)(lpVirtualAddr + pImageDir->VirtualAddress),
		lpLoadLibraryA,
		lpGetProcAddress
	);

	// -----------------------------------------------------------------------------
    // Reallocate image
	// -----------------------------------------------------------------------------
	
	pImageDir = (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (!pImageDir)
	{
		return;
	}
	ReallocateSections(
		lpVirtualAddr,
		(LPVOID)pNtHeaders->OptionalHeader.ImageBase,
		(LPVOID)(lpVirtualAddr + pImageDir->VirtualAddress),
		pNtHeaders
	);

	// -----------------------------------------------------------------------------
    // Set protections for each section
	// Reference:
	//   https://github.com/Cracked5pider/KaynLdr/blob/01887b038fac5ebb459eb6200c522173fce57cf6/KaynLdr/src/KaynLdr.c#L70
	// -----------------------------------------------------------------------------

	LPVOID	lpSec			= nullptr;
	SIZE_T 	dwSecSize 		= 0;
	DWORD	dwProtect 		= 0;
	DWORD 	dwOldProtect 	= PAGE_READWRITE;

	for (DWORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		lpSec = (LPVOID)(lpVirtualAddr + pSecHeader[i].VirtualAddress);
		dwSecSize = pSecHeader[i].SizeOfRawData;

		if (pSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)
		{
			dwProtect = PAGE_WRITECOPY;
		}
		if (pSecHeader[i].Characteristics & IMAGE_SCN_MEM_READ)
		{
			dwProtect = PAGE_READONLY;
		}
		if ((pSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) &&
			(pSecHeader[i].Characteristics & IMAGE_SCN_MEM_READ)
		) {
			dwProtect = PAGE_READWRITE;
		}
		if (pSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			dwProtect = PAGE_EXECUTE;
		}
		if ((pSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
			(pSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)
		) {
			dwProtect = PAGE_EXECUTE_WRITECOPY;
		}
		if ((pSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
			(pSecHeader[i].Characteristics & IMAGE_SCN_MEM_READ)
		) {
			dwProtect = PAGE_EXECUTE_READ;
		}
		if ((pSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
			(pSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) &&
			(pSecHeader[i].Characteristics & IMAGE_SCN_MEM_READ)
		) {
			dwProtect = PAGE_EXECUTE_READWRITE;
		}

		lpVirtualProtect(lpSec, dwSecSize, dwProtect, &dwOldProtect);
	}

	// -----------------------------------------------------------------------------
    // Execute Shellcode
	// -----------------------------------------------------------------------------

	Procs::LPPROC_DLLMAIN lpDllMain = reinterpret_cast<Procs::LPPROC_DLLMAIN>((ULONG_PTR)lpVirtualAddr + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
	lpNtFlushInstructionCache((HANDLE)-1, NULL, 0);
    lpDllMain((HINSTANCE)lpVirtualAddr, DLL_PROCESS_ATTACH, NULL);
}
