#include "core/parser.hpp"

namespace Parser
{
    json ParseTask(const std::wstring& wTask)
    {
        // Decrypt
        std::wstring wDecTask = Crypt::Decrypt(wTask);

        // wstring -> string
        std::string sDecTask = Utils::Convert::UTF8Encode(wDecTask);

        // Parse JSON
        json j = json::parse(sDecTask);

        return j;
    }
}