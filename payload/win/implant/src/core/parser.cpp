#include "core/parser.hpp"

namespace Parser
{
    json ParseTask(const std::wstring& wTask)
    {
        // Decrypt
        std::vector<BYTE> bytes = Crypt::Decrypt(wTask);

        // Parse JSON
        json j = json::parse(std::string(bytes.begin(), bytes.end()));

        return j;
    }
}