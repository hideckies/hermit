#include "core/task.hpp"

namespace Task
{
     std::wstring Mkdir(State::PSTATE pState, const std::wstring& wDir)
     {
        HANDLE hDir = System::Fs::DirectoryCreate(pState->pProcs, wDir);
        if (!hDir)
        {
            return L"Error: Failed to create a new directory.";
        }

        pState->pProcs->lpNtClose(hDir);

        return L"Success: New directory created.";
     }
}