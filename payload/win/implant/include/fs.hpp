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
#include "constants.hpp"
#include "convert.hpp"

VOID CALLBACK FileIOCompletionRoutine(
  DWORD dwErrorCode,
  DWORD dwNumberOfBytesTransfered,
  LPOVERLAPPED lpOverlapped
);

struct MyFileData {
  LPVOID lpData;
  DWORD dwDataSize;
};

std::string MyReadFileA(const std::string& sFile);
std::wstring MyReadFileW(const std::wstring& wFile);
std::vector<BYTE> MyReadFileToByteArray(const std::string& sFilePath);
MyFileData MyReadFileExW(const std::wstring& wFile);
BOOL MyWriteFileW(const std::wstring& wFile, LPCVOID lpData, DWORD dwDataSize);
std::wstring MyDeleteFileW(const std::wstring& wFile);

#endif // HERMIT_FS_HPP