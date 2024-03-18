#ifndef HERMIT_FS_HPP
#define HERMIT_FS_HPP

#include <windows.h>
#include <string>
#include <shlwapi.h>
#include <fstream>
#include <sstream>
#include <iterator>
#include <vector>
#include "common.hpp"
#include "convert.hpp"
#include "macros.hpp"

VOID CALLBACK FileIOCompletionRoutine(
  DWORD dwErrorCode,
  DWORD dwNumberOfBytesTransfered,
  LPOVERLAPPED lpOverlapped
);

struct MyFileData {
  LPVOID lpData;
  DWORD dwDataSize;
};

std::vector<char> ReadBytesFromFile(const std::wstring& wFilePath);
BOOL MyWriteFile(const std::wstring& wFile, LPCVOID lpData, DWORD dwDataSize);

#endif // HERMIT_FS_HPP