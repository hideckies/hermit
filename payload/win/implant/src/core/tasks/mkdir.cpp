#include "core/task.hpp"

namespace Task
{
     std::wstring Mkdir(const std::wstring& wDir)
     {
        if (!CreateDirectoryW(wDir.c_str(), NULL))
        {
            return L"Error: Could not create a new directory.";
        }

        return L"Success: New directory has been created.";
     }
}