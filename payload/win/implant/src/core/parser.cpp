#include "core/parser.hpp"

namespace Parser
{
    json ParseTask(
        const std::vector<BYTE> task,
        BCRYPT_KEY_HANDLE hKey,
        std::vector<BYTE> iv
    ) {
        // Parse JSON
        json j = json::parse(std::string(task.begin(), task.end()));

        return j;
    }
}