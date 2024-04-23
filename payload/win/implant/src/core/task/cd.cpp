#include "core/task.hpp"

namespace Task {
    std::wstring Cd(State::PSTATE pState, const std::wstring& wDestDir)
    {
        if (!System::Fs::DirectoryChangeCurrent(pState->pProcs, wDestDir))
        {
            return L"Error: Failed to change current directory.";
        }

        return L"Success: Current directory changed.";
    }
}