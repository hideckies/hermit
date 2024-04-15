#include "core/task.hpp"

typedef std::map<std::wstring, std::wstring> env_t;

namespace Task
{
    std::wstring EnvLs()
    {        
        std::wstring result = L"";

        std::map<std::wstring, std::wstring> env = System::Env::GetAll();

        if (env.size() == 0)
        {
            return L"Error: Failed to retrieve envnrionment variables.";
        }

        auto iter = env.begin();
        while (iter != env.end())
        {
            std::wstring key = iter->first;
            std::wstring val = iter->second;

            result += key + L" = " + val + L"\n";

            ++iter;
        }

        return result;
    }
}