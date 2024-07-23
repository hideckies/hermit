#include "core/utils.hpp"

namespace Utils::Convert
{
    std::string BytePointerToString(const BYTE* pByte)
    {
        size_t size = sizeof(pByte) / sizeof(pByte[0]);
        return std::string(reinterpret_cast<const char*>(pByte), size);
    }

    std::string VecByteToHexString(const std::vector<BYTE> bytes)
    {
        std::stringstream ss;
        ss << std::hex << std::uppercase << std::setfill('0');
        for (int i = 0; i < bytes.size(); ++i) {
            ss << std::setw(2) << static_cast<int>(bytes[i]) << " ";
        }
        return ss.str();
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

    // WORD (unsigned short) -> wstring
    std::wstring WORDToWstring(WORD wSrc)
    {
        std::string sSrc = std::to_string(wSrc);
        std::wstring wDest = UTF8Decode(sSrc);
        return wDest;
    }

    // wstring -> DWORD (unsigned long)
    DWORD WstringToDWORD(const std::wstring& wStr, int base)
    {
        std::string sStr = UTF8Encode(wStr);
        char* pEnds;
        DWORD dwStr = (DWORD)strtoul(sStr.c_str(), &pEnds, base);
        return dwStr;
    }

    // DWORD (unsigned long) -> wstring
    std::wstring DWORDToWstring(DWORD dwSrc)
    {
        std::string sSrc = std::to_string(dwSrc);
        std::wstring wDest = UTF8Decode(sSrc);
        return wDest;
    }

    // LPSTR (UTF-8) -> PWCHAR (UTF-16)
    PWCHAR LPSTRToPWCHAR(LPSTR lpStr)
    {
        int wchars_num = MultiByteToWideChar(CP_UTF8, 0, lpStr, -1, NULL, 0);
        wchar_t* wstr = new wchar_t[wchars_num];
        MultiByteToWideChar(CP_UTF8, 0, lpStr, -1, wstr, wchars_num);
        return wstr;
    }

    // IPv4(wstring) -> DWORD
    DWORD IPv4ToDWORD(const std::wstring& wIP)
    {
        DWORD dwResult = 0;
        int shift = 24;

        std::wstringstream ss(wIP);
        std::wstring section;
        while (std::getline(ss, section, L'.')) {
            DWORD value = std::stoul(section);
            dwResult |= (value << shift);
            shift -= 8;
        }

        return dwResult;
    }
}

