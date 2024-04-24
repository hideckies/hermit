#include "core/task.hpp"

namespace Task
{
    std::wstring Rmdir(const std::wstring& wDir)
    {
        // Maybe there isn't NTAPI to delete a directory...?
        if (!RemoveDirectoryW(wDir.c_str()))
        {
            return L"Error: Could not delete a directory.";
        }

        return L"Success: Directory has been deleted.";
    }
}