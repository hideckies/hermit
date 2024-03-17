#ifndef HERMIT_SCREENSHOT_HPP
#define HERMIT_SCREENSHOT_HPP

#include <windows.h>
#include <gdiplus.h>
#include <string>
#include "common.hpp"
#include "fs.hpp"
#include "winsystem.hpp"

#ifndef IDS_APP_TITLE
#define IDS_APP_TITLE 1
#endif

#ifndef IDC_GDICAPTURINGANIMAGE
#define IDC_GDICAPTURINGANIMAGE 1
#endif

#ifndef IDI_GDICAPTURINGANIMAGE
#define IDI_GDICAPTURINGANIMAGE 2
#endif

#ifndef IDI_SMALL
#define IDI_SMALL 3
#endif

BOOL InitInstance(HINSTANCE hInstance, INT nCmdShow);
// INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
INT GetEncoderClsid(const WCHAR* format, CLSID* pClsid);
BOOL BmpToPng();
BOOL DeleteBmp();
int CaptureAnImage(HWND hWnd);
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
ATOM MyRegisterClass(HINSTANCE hInstance);
std::wstring Screenshot(HINSTANCE hInstance, INT nCmdShow);

#endif // HERMIT_SCREENSHOT_HPP