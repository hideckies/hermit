#include "core/system.hpp"

namespace System::Env
{
    std::wstring GetStrings(Procs::PPROCS pProcs, const std::wstring& envVar)
    {
        wchar_t envStrings[INFO_BUFFER_SIZE];

        DWORD envStringsLen = pProcs->lpExpandEnvironmentStringsW(
            envVar.c_str(),
            envStrings,
            INFO_BUFFER_SIZE
        );

        return envStrings;
    }
}