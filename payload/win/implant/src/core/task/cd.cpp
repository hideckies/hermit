#include "core/task.hpp"

namespace Task {
    std::wstring Cd(const std::wstring& wDestDir)
    {
        if (!SetCurrentDirectoryW(wDestDir.c_str()))
        {
            return L"Error: Could not change current directory.";
        }

        return L"Success: Current directory has been changed.";
    }
}