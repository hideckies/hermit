#include "core/task.hpp"

namespace Task
{
    std::wstring Ls(State::PSTATE pState, const std::wstring& wDir)
    {
        std::wstring result;

        WIN32_FIND_DATAW ffd;
        LARGE_INTEGER filesize;
        std::wstring wFilesize;
        WCHAR wTargetDir[MAX_PATH];
        size_t dirLength;
        HANDLE hFind = INVALID_HANDLE_VALUE;

        std::wstring wDirAbsPath = System::Fs::AbsolutePathGet(pState->pProcs, wDir, FALSE);
        std::wstring wDirAbsPathExtended = System::Fs::AbsolutePathGet(pState->pProcs, wDir, TRUE);
        if (wDirAbsPath == L"" || wDirAbsPathExtended == L"")
        {
            return L"Error: Failed to get the absolute path for the directory.";
        }

        // Add "\\*" to the directory path
        wDirAbsPathExtended += L"\\*";

        // Find the first file in the directory.
        hFind = pState->pProcs->lpFindFirstFileW(wDirAbsPathExtended.c_str(), &ffd);
        if (hFind == INVALID_HANDLE_VALUE)
        {
            return L"Error: Could not find the first file in the directory.";
        }

        result += std::wstring(L"Directory: ");
        result += std::wstring(wDirAbsPath);
        result += std::wstring(L"\n\n");
        
        // List all files in the directory
        do
        {
            if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                result += std::wstring(L"<D> ");
                result += std::wstring(ffd.cFileName);
                result += std::wstring(L"\n");
            }
            else
            {
                filesize.LowPart = ffd.nFileSizeLow;
                filesize.HighPart = ffd.nFileSizeHigh;
                wFilesize = std::to_wstring(filesize.QuadPart);

                result += std::wstring(L"<F> ");
                result += std::wstring(ffd.cFileName);
                result += std::wstring(L", ");
                result += wFilesize;
                result += std::wstring(L" bytes\n");
            }
        } while (pState->pProcs->lpFindNextFileW(hFind, &ffd) != 0);

        pState->pProcs->lpFindClose(hFind);
        return result;
    }
}