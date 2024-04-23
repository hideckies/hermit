#include "core/task.hpp"

namespace Task
{
    std::wstring Mv(State::PSTATE pState, const std::wstring& wSrc, const std::wstring& wDest)
    {
        if (!MoveFileW(wSrc.c_str(), wDest.c_str()))
        // if (!System::Fs::FileMove(pState->pProcs, wSrc, wDest)) // Bug: the 'FileMove' function forcefully terminates the program.
        {
            return L"Error: Could not move a file.";
        }

        return L"Success: File has been moved to the destination.";
    }
}