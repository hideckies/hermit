#include "core/task.hpp"

namespace Task
{
    std::wstring Cp(const std::wstring& wSrc, const std::wstring& wDest)
    {
        if (!CopyFileW(wSrc.c_str(), wDest.c_str(), TRUE))
        {
            return L"Error: Could not copy the file.";
        }

        return L"Success: File has been copied.";
    }
}