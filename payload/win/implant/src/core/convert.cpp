#include "convert.hpp"

// LPSTR (UTF-8) -> wchar_t* (UTF-16)
wchar_t* ConvertLPSTRToWCHAR_T(LPSTR lpStr)
{
    int wchars_num = MultiByteToWideChar(CP_UTF8, 0, lpStr, -1, NULL, 0);
    wchar_t* wstr = new wchar_t[wchars_num];
    MultiByteToWideChar(CP_UTF8, 0, lpStr, -1, wstr, wchars_num);
    return wstr;
}

// LPCWSTR (UTF-16) -> string (UTF-8)
std::string ConvertLPCWSTRToString(LPCWSTR lpcwStr)
{
    INT strLength = WideCharToMultiByte(CP_UTF8, 0, lpcwStr, -1, NULL, 0, NULL, NULL);
    std::string strData(strLength, 0);
    WideCharToMultiByte(CP_UTF8, 0, lpcwStr, -1, &strData[0], strLength, NULL, NULL);
    return strData;
}

// string -> LPCWSTR
LPCWSTR ConvertStringToLPCWSTR(const std::string& text)
{
    std::wstring wText = std::wstring(text.begin(), text.end());
    return wText.c_str();
}

// string -> wstring
std::wstring ConvertStringToWstring(const std::string& text)
{
    std::wstring wText;
    
    wchar_t* wcs = new wchar_t[text.length() + 1];
    mbstowcs(wcs, text.c_str(), text.length() + 1);

    wText = wcs;

    delete [] wcs;

    return wText;
}

// wstring -> string
std::string ConvertWstringToString(const std::wstring& wText)
{
    std::string text;

    char* mbs = new char[wText.length() * MB_CUR_MAX + 1];
    wcstombs(mbs, wText.c_str(), wText.length() * MB_CUR_MAX + 1);
    text = mbs;
    delete [] mbs;

    return text;
}

