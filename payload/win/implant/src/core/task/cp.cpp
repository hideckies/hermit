#include "core/task.hpp"

namespace Task
{
    std::wstring Cp(State::PSTATE pState, const std::wstring& wSrc, const std::wstring& wDest)
    {
        std::vector<BYTE> bytes = System::Fs::FileRead(pState->pProcs, wSrc);

        if (!System::Fs::FileWrite(pState->pProcs, wDest, bytes))
        {
            return L"Error: Failed to write file.";
        }

        return L"Success: File has been copied.";
    }
}