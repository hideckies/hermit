#include "core/task.hpp"

namespace Task
{
    std::wstring Rm(State::PSTATE pState, const std::wstring& wPath, BOOL bRecursive)
    {
        if (bRecursive)
        {
            // Delete a directory recursively.
            // Maybe there isn't NTAPI to delete a directory...?
            if (!pState->pProcs->lpRemoveDirectoryW(wPath.c_str()))
            {
                return L"Error: Failed to delete a directory.";
            }
        }
        else
        {
            // Delete a file.
            if (!System::Fs::FileDelete(pState->pProcs, wPath))
            {
                return L"Error: Failed to delete a file.";
            }
        }

        return L"Success: File has been deleted successfully.";
    }
}
