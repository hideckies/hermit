#include "core/socket.hpp"

namespace Socket
{
    PSOCKET_DATA NewSocket(
        DWORD dwType,
        DWORD dwLIP,
        DWORD dwLPort,
        DWORD dwFwdIP,
        DWORD dwFwdPort,
        DWORD dwParentID
    ) {
        PSOCKET_DATA pSocket = NULL;
        u_long ulIOBlock = 1;

        if (dwType == SOCKET_TYPE_NONE)
        {
            return pSocket;
        }

        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        {
            return NULL;
        }

        SOCKET socket = WSASocket(
            AF_INET,
            SOCK_STREAM,
            IPPROTO_TCP,
            NULL,
            0,
            0
        );
        if (socket == INVALID_SOCKET)
        {
            WSACleanup();
            return NULL;
        }

        // Set bind address and port.
        sockaddr_in sockAddr;
        sockAddr.sin_family = AF_INET;
        sockAddr.sin_addr.s_addr = dwLIP;
        sockAddr.sin_port = HTONS16(dwLPort);

        if (dwType == SOCKET_TYPE_REVERSE_PORT_FORWARDING)
        {
            // Set socket to non blocking.
            if (ioctlsocket(socket, FIONBIO, &ulIOBlock) == SOCKET_ERROR)
            {
                closesocket(socket);
                WSACleanup();
            }

            // Bind the socket
            if (bind(socket, (sockaddr*)&sockAddr, sizeof(SOCKADDR_IN)) == SOCKET_ERROR)
            {
                closesocket(socket);
                WSACleanup();
            }

            // Listen
            if (listen(socket, 1) == SOCKET_ERROR)
            {
                closesocket(socket);
                WSACleanup();
                return NULL;
            }
        }

        // Allocate heap
        // pSocket = (procs.RtlAllocateHeap)(NtProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SOCKET_DATA));
        // pSocket->dwID = Utils::Random::RandomNumber32();
        // pSocket->dwParentID = dwParentID;
        // pSocket->socket = socket;
        // pSocket->dwType = dwType;
        // pSocket->bShouldRemove = FALSE;
        // pSocket->dwLIP = dwLIP;
        // // Socket->LIPv6 = IPv6;
        // pSocket->dwLPort = dwLPort;
        // pSocket->dwFwdAddr = dwFwdIP;
        // pSocket->dwFwdPort = dwFwdPort;
        // pSocket->next = sm.GetSocket();

        return pSocket;
    }
}
