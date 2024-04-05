#include "core/task.hpp"

namespace Task
{
    std::wstring Mv(const std::wstring& wSrc, const std::wstring& wDest)
    {
        if (!MoveFileW(wSrc.c_str(), wDest.c_str()))
        {
            return L"Error: Could not move a file.";
        }

        return L"Success: File has been moved to the destination.";
    }
}