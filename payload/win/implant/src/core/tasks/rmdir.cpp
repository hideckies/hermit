#include "core/task.hpp"

namespace Task
{
    std::wstring Rmdir(const std::wstring& wDir)
    {
        if (!RemoveDirectoryW(wDir.c_str()))
        {
            return L"Error: Could not delete a directory.";
        }

        return L"Success: Directory has been deleted.";
    }
}