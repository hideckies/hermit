#include "core/task.hpp"

namespace Task
{
    std::wstring Kill()
    {
        ExitProcess(EXIT_SUCCESS);
        return L"Success: Exit the process.";
    }
}