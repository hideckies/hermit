#include "core/task.hpp"

namespace Task::Helper::Rportfwd
{
    void HandleClient(SOCKET client, SOCKET remote)
    {
        char buffer[4096];
        int bytesRead, bytesSent;

        do {
            bytesRead = recv(remote, buffer, sizeof(buffer), 0);
            if (bytesRead > 0) {
                bytesSent = send(client, buffer, bytesRead, 0);
                if (bytesSent == SOCKET_ERROR) {
                    break;
                }
            }
            else if (bytesRead == 0) {
                break;
            }
            else {
                break;
            }

        } while (bytesRead > 0);

        closesocket(client);
        closesocket(remote);
    }
}

namespace Task
{
    std::wstring RportfwdAdd(
        State::StateManager& sm,
        const std::wstring& wLport,
        const std::wstring& wIP,
        const std::wstring& wPort
    ) {
        std::string sLhost = Utils::Convert::UTF8Encode(sm.GetListenerHost());
        std::string sLport = Utils::Convert::UTF8Encode(wLport);
        std::string sIP = Utils::Convert::UTF8Encode(wIP);
        std::string sPort = Utils::Convert::UTF8Encode(wPort);

        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        {
            return L"Error: WSAStartup failed.";
        }

        // Connect to SSH remote server
        SOCKET serverConn = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (serverConn == INVALID_SOCKET)
        {
            WSACleanup();
            return L"Error: Failed to initialize SSH socket.";
        }
        // Set remote SSH server params.
        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = inet_addr(sLhost.c_str());
        // serverAddr.sin_port = htons(sLport);
        serverAddr.sin_port = htons((unsigned short)strtoul(sLport.c_str(), NULL, 0));

        if (connect(serverConn, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
        {
            closesocket(serverConn);
            WSACleanup();
            return L"Error: Failed to connect to remote SSH server";
        }

        // Listen on remote SSH server port
        SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listener == INVALID_SOCKET)
        {
            closesocket(serverConn);
            WSACleanup();
            return L"Error: Failed to create listener socket.";
        }
        // Set listener params.
        sockaddr_in localAddr;
        localAddr.sin_family = AF_INET;
        localAddr.sin_addr.s_addr = INADDR_ANY;
        // localAddr.sin_port = htons(sLport);
        localAddr.sin_port = htons((unsigned short)strtoul(sLport.c_str(), NULL, 0));

        if (bind(listener, (sockaddr*)&localAddr, sizeof(localAddr)) == SOCKET_ERROR)
        {
            closesocket(listener);
            closesocket(serverConn);
            WSACleanup();
            return L"Error: Failed to bind listener.";
        }

        if (listen(listener, SOMAXCONN) == SOCKET_ERROR)
        {
            closesocket(listener);
            closesocket(serverConn);
            WSACleanup();
            return L"Error: Failed to start listener.";
        }

        // Handle incoming connections on reverse forwarded tunnel
        while (true) {
            SOCKET client = accept(listener, NULL, NULL);
            if (client == INVALID_SOCKET)
            {
                closesocket(listener);
                closesocket(serverConn);
                WSACleanup();
                return L"Error: Accept failed.";
            }

            // Connect to target local service.
            SOCKET local = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (local == INVALID_SOCKET)
            {
                closesocket(client);
                closesocket(listener);
                closesocket(serverConn);
                WSACleanup();
                return L"Error: Failed to create local socket.";
            }
            // Set target local service params.
            sockaddr_in localRemoteAddr;
            localRemoteAddr.sin_family = AF_INET;
            localRemoteAddr.sin_addr.s_addr = inet_addr(sIP.c_str());
            // localRemoteAddr.sin_port = htons(sPort);
            localRemoteAddr.sin_port = htons((unsigned short)strtoul(sPort.c_str(), NULL, 0));

            if (connect(local, (sockaddr*)&localRemoteAddr, sizeof(localRemoteAddr)) == SOCKET_ERROR)
            {
                closesocket(local);
                closesocket(client);
                closesocket(listener);
                closesocket(serverConn);
                WSACleanup();
                return L"Erorr: Failed to connect to target local service.";
            }

            // std::thread(Task::Helper::Rportfwd::HandleClient, client, local).detach();
            
            // TODO: Implement CreateThread
            // HANDLE hThread = CreateThread(
            //     NULL,
            //     0,
            //     Task::Helper::Rportfwd::HandleClient
            // )
        }

        closesocket(listener);
        closesocket(serverConn);
        WSACleanup();

        return L"Success: A connection has been established for reverse port forwarding.";
    }

    std::wstring RportfwdRm(
        const std::wstring& wIP,
        const std::wstring& wPort
    ) {
        return L"Warn: Not implemented yet.";
    }
}