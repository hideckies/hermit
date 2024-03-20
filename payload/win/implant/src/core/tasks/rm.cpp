#include "core/task.hpp"

namespace Task
{
    std::wstring Rm(const std::wstring& wFile)
    {
         if (!DeleteFileW(wFile.c_str()))
        {
            return L"Error: Could not delete a file.";
        }

        return L"Success: File has been deleted.";
    }
}