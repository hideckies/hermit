#include "core/task.hpp"

namespace Task
{
    std::wstring Cat(const std::wstring& wFilePath)
    {
        std::vector<char> byteData = System::Fs::ReadBytesFromFile(wFilePath);

        // Convert to wstring
        std::string fileContent = Utils::Convert::VecCharToString(byteData);
        std::wstring wFileContent = Utils::Convert::UTF8Decode(fileContent);

        if (wFileContent == L"")
        {
            return L"Error: Failed to read a file.";
        }

        return wFileContent;
    }
}