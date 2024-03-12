#pragma warning(disable: 4996)

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void EnumExportedFunctions(char*, void (*callback)(char*));
int Rva2Offset(unsigned int);

typedef struct {
    unsigned char Name[8];
    unsigned int VirtualSize;
    unsigned int VirtualAddress;
    unsigned int SizeOfRawData;
    unsigned int PointerToRawData;
    unsigned int PointerToRelocations;
    unsigned int PointerToLineNumbers;
    unsigned short NumberOfRelocations;
    unsigned short NumberOfLineNumbers;
    unsigned int Characteristics;
} sectionHeader;

sectionHeader* sections;
unsigned int NumberOfSections = 0;

int Rva2Offset(unsigned int rva) {
    int i = 0;

    for (i = 0; i < NumberOfSections; i++) {
        unsigned int x = sections[i].VirtualAddress + sections[i].SizeOfRawData;

        if (x >= rva) {
            return sections[i].PointerToRawData + (rva + sections[i].SizeOfRawData) - x;
        }
    }

    return -1;
}

void EnumExportedFunctions(char* szFilename, void (*callback)(char*)) {
    FILE* hFile = fopen(szFilename, "rb");

    if (hFile != NULL) {
        if (fgetc(hFile) == 'M' && fgetc(hFile) == 'Z') {
            unsigned int e_lfanew = 0;
            unsigned int NumberOfRvaAndSizes = 0;
            unsigned int ExportVirtualAddress = 0;
            unsigned int ExportSize = 0;
            int i = 0;

            fseek(hFile, 0x3C, SEEK_SET);
            fread(&e_lfanew, 4, 1, hFile);
            fseek(hFile, e_lfanew + 6, SEEK_SET);
            fread(&NumberOfSections, 2, 1, hFile);
            fseek(hFile, 108, SEEK_CUR);
            fread(&NumberOfRvaAndSizes, 4, 1, hFile);

            if (NumberOfRvaAndSizes == 16) {
                fread(&ExportVirtualAddress, 4, 1, hFile);
                fread(&ExportSize, 4, 1, hFile);

                if (ExportVirtualAddress > 0 && ExportSize > 0) {
                    fseek(hFile, 120, SEEK_CUR);

                    if (NumberOfSections > 0) {
                        sections = (sectionHeader*)malloc(NumberOfSections * sizeof(sectionHeader));

                        for (i = 0; i < NumberOfSections; i++) {
                            fread(sections[i].Name, 8, 1, hFile);
                            fread(&sections[i].VirtualSize, 4, 1, hFile);
                            fread(&sections[i].VirtualAddress, 4, 1, hFile);
                            fread(&sections[i].SizeOfRawData, 4, 1, hFile);
                            fread(&sections[i].PointerToRawData, 4, 1, hFile);
                            fread(&sections[i].PointerToRelocations, 4, 1, hFile);
                            fread(&sections[i].PointerToLineNumbers, 4, 1, hFile);
                            fread(&sections[i].NumberOfRelocations, 2, 1, hFile);
                            fread(&sections[i].NumberOfLineNumbers, 2, 1, hFile);
                            fread(&sections[i].Characteristics, 4, 1, hFile);
                        }

                        unsigned int NumberOfNames = 0;
                        unsigned int AddressOfNames = 0;

                        int offset = Rva2Offset(ExportVirtualAddress);
                        fseek(hFile, offset + 24, SEEK_SET);
                        fread(&NumberOfNames, 4, 1, hFile);

                        fseek(hFile, 4, SEEK_CUR);
                        fread(&AddressOfNames, 4, 1, hFile);

                        unsigned int namesOffset = Rva2Offset(AddressOfNames), pos = 0;
                        fseek(hFile, namesOffset, SEEK_SET);

                        for (i = 0; i < NumberOfNames; i++) {
                            unsigned int y = 0;
                            fread(&y, 4, 1, hFile);
                            pos = ftell(hFile);
                            fseek(hFile, Rva2Offset(y), SEEK_SET);

                            char c = fgetc(hFile);
                            int szNameLen = 0;

                            while (c != '\0') {
                                c = fgetc(hFile);
                                szNameLen++;
                            }

                            fseek(hFile, (-szNameLen) - 1, SEEK_CUR);
                            char* szName = (char*)calloc(szNameLen + 1, 1);
                            fread(szName, szNameLen, 1, hFile);

                            callback(szName);

                            fseek(hFile, pos, SEEK_SET);
                        }
                    }
                }
            }
        }

        fclose(hFile);
    }
}

void calculate_hash(char* szName) {
    DWORD hash = 0;
    DWORD i = 0;
    for (i; i < strlen(szName); i++) {
        hash <<= 1;
        hash += szName[i];
    }
    printf("%s:0x%08x\n", szName, hash);

}

int main(int argc, char** argv) {
    printf("Loading %s\n", argv[1]);
    EnumExportedFunctions(argv[1], calculate_hash);
    return 0;
}