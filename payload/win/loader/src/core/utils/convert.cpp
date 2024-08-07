#include "core/utils.hpp"

namespace Utils::Convert
{
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

    // DWORD (unsigned long) -> wstring
    std::wstring DWORDToWstring(DWORD dwSrc)
    {
        std::string sSrc = std::to_string(dwSrc);
        std::wstring wDest = UTF8Decode(sSrc);
        return wDest;
    }

    // LPSTR (UTF-8) -> wchar_t* (UTF-16)
    wchar_t* LPSTRToWCHAR_T(LPSTR lpStr)
    {
        int wchars_num = MultiByteToWideChar(CP_UTF8, 0, lpStr, -1, NULL, 0);
        wchar_t* wstr = new wchar_t[wchars_num];
        MultiByteToWideChar(CP_UTF8, 0, lpStr, -1, wstr, wchars_num);
        return wstr;
    }

    // String (PCHAR) -> Hash (DWORD)
    DWORD StrToHashA(PCHAR pChar)
    {
        ULONG Hash = 5381;
        INT c;

        while (c = *pChar++)
            Hash = ((Hash << 5) + Hash) + c;

        return Hash;
    }
}

