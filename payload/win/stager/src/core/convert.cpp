#include "convert.hpp"

std::string VecCharToString(std::vector<char> chars)
{
    std::string s(chars.begin(), chars.end());
    return s;
}

std::string UTF8Encode(const std::wstring& wstr)
{
    if( wstr.empty() ) {
        return std::string();
    }

    int size_needed = WideCharToMultiByte(
        CP_UTF8,
        0,
        &wstr[0],
        (int)wstr.size(),
        NULL,
        0,
        NULL,
        NULL
    );

    std::string strTo( size_needed, 0 );

    WideCharToMultiByte(
        CP_UTF8,
        0,
        &wstr[0],
        (int)wstr.size(),
        &strTo[0],
        size_needed,
        NULL,
        NULL
    );

    return strTo;
}

std::wstring UTF8Decode(const std::string& str)
{
    if( str.empty() ) 
    {
        return std::wstring();
    }

    int size_needed = MultiByteToWideChar(
        CP_UTF8,
        0,
        &str[0],
        (int)str.size(),
        NULL,
        0
    );

    std::wstring wstrTo(size_needed, 0);

    MultiByteToWideChar(
        CP_UTF8,
        0,
        &str[0],
        (int)str.size(),
        &wstrTo[0],
        size_needed
    );

    return wstrTo;
}

// LPCWSTR (UTF-16) -> string (UTF-8)
std::string ConvertLPCWSTRToString(LPCWSTR lpcwStr)
{
    INT strLength = WideCharToMultiByte(CP_UTF8, 0, lpcwStr, -1, NULL, 0, NULL, NULL);
    std::string strData(strLength, 0);
    WideCharToMultiByte(CP_UTF8, 0, lpcwStr, -1, &strData[0], strLength, NULL, NULL);
    return strData;
}
