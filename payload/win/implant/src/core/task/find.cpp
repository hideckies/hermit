#include "core/task.hpp"

namespace Task
{
    namespace Helper::Find
    {
        std::wstring FindFiles(
            State::PSTATE pState,
            const std::wstring& wPath,
            const std::wstring& wName
        ) {
            std::wstring wResult = L"";

            std::wstring wDirAbsPath = System::Fs::AbsolutePathGet(pState->pProcs, wPath, FALSE);
            std::wstring wDirAbsPathExtended = System::Fs::AbsolutePathGet(pState->pProcs, wPath, TRUE);
            if (wDirAbsPath == L"" || wDirAbsPathExtended == L"")
            {
                return L"";
            }

            // Remote "\" if it exists in the suffix.
            if (!wDirAbsPathExtended.empty() && wDirAbsPathExtended.back() == L'\\')
            {
                wDirAbsPathExtended.pop_back();
            }

            // Add "\\*" to the directory path
            wDirAbsPathExtended += L"\\*";

            // Find the first file in the directory.
            WIN32_FIND_DATAW ffd;
            HANDLE hFind = pState->pProcs->lpFindFirstFileW(wDirAbsPathExtended.c_str(), &ffd);
            if (hFind == INVALID_HANDLE_VALUE)
            {
                return L"";
            }

            // List all files in the directory
            do
            {
                if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                {
                    if (wcscmp(ffd.cFileName, L".") == 0 || wcscmp(ffd.cFileName, L"..") == 0)
                    {
                        continue;
                    }

                    // Find recursively
                    wResult += Helper::Find::FindFiles(pState, wPath + L"\\" + std::wstring(ffd.cFileName), wName);
                }
                else
                {
                    if (wName == L"")
                    {
                        continue;
                    }
                    if (std::wstring(ffd.cFileName).find(wName) == std::wstring::npos)
                    {
                        continue;
                    }

                    wResult += wPath + L"\\" + std::wstring(ffd.cFileName);
                    wResult += std::wstring(L"\n");
                }
            } while (pState->pProcs->lpFindNextFileW(hFind, &ffd) != 0);

            pState->pProcs->lpFindClose(hFind);
            return wResult;
        }
    }

    std::wstring Find(
        State::PSTATE pState,
        const std::wstring& wPath,
        const std::wstring& wName
    ) {
        return Helper::Find::FindFiles(pState, wPath, wName);
    }
}