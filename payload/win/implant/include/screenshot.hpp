#ifndef HERMIT_SCREENSHOT_HPP
#define HERMIT_SCREENSHOT_HPP

#include <windows.h>
#include <gdiplus.h>
#include <string>
#include "common.hpp"
#include "fs.hpp"
#include "macros.hpp"
#include "winsystem.hpp"

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