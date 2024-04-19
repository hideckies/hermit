#include "core/task.hpp"

namespace Task
{
    std::wstring Cat(State::PSTATE pState, const std::wstring& wFilePath)
    {
        std::vector<BYTE> bytes = System::Fs::ReadBytesFromFile(pState->pProcs, wFilePath);

        // Convert the data to wstring
        std::wstring wFileContent = Utils::Convert::UTF8Decode(std::string(bytes.begin(), bytes.end()));

        if (wFileContent == L"")
        {
            return L"Error: Failed to read a file.";
        }

        return wFileContent;
    }
}