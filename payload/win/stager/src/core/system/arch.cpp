#include "core/system.hpp"

namespace System::Arch
{
    std::wstring GetName(WORD wProcessorArchitecture)
    {
        switch (wProcessorArchitecture) {
            case PROCESSOR_ARCHITECTURE_INTEL:
                return L"intel";
            case PROCESSOR_ARCHITECTURE_MIPS:
                return L"mips";
            case PROCESSOR_ARCHITECTURE_ALPHA:
                return L"alpha";
            case PROCESSOR_ARCHITECTURE_PPC:
                return L"ppc";
            case PROCESSOR_ARCHITECTURE_SHX:
                return L"shx";
            case PROCESSOR_ARCHITECTURE_ARM:
                return L"arm";
            case PROCESSOR_ARCHITECTURE_IA64:
                return L"ia64";
            case PROCESSOR_ARCHITECTURE_ALPHA64:
                return L"alpha64"; 
            case PROCESSOR_ARCHITECTURE_MSIL:
                return L"msil";
            case PROCESSOR_ARCHITECTURE_AMD64:
                return L"amd64";
            case PROCESSOR_ARCHITECTURE_IA32_ON_WIN64:
                return L"ia32_on_win64";
            case PROCESSOR_ARCHITECTURE_UNKNOWN:
                return L"unknown";
            default:
                return L"unknown";
            
        }
    }
}