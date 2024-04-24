#include "core/task.hpp"

namespace Task
{
    std::wstring Rm(State::PSTATE pState, const std::wstring& wFile)
    {
        if (!System::Fs::FileDelete(pState->pProcs, wFile))
        {
            return L"Error: Could not delete a file.";
        }

        return L"Success: File has been deleted.";
    }
}