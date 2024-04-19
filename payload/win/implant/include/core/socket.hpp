#ifndef HERMIT_CORE_SOCKET_HPP
#define HERMIT_CORE_SOCKET_HPP

#define SOCKET_TYPE_NONE 0x0
#define SOCKET_TYPE_REVERSE_PORT_FORWARDING 0x1
#define SOCKET_TYPE_CLIENT 0x2

#include "core/macros.hpp"

// #include <winsock2.h>

namespace Socket
{
    typedef struct _SOCKET_DATA
    {
        DWORD  dwID;
        DWORD  dwParentID;
        
        SOCKET socket;

        // Socket type
        DWORD dwType;

        BOOL bShouldRemove;

        // Bind ip and port
        DWORD dwLIP;
        // PBYTE LIPv6;
        DWORD dwLPort;

        // Forward ip and port
        DWORD dwFwdIP;
        DWORD dwFwdPort;

        // Pointer to the next Socket data
        struct _SOCKET_DATA* next;
    } SOCKET_DATA, *PSOCKET_DATA;

    PSOCKET_DATA NewSocket(
        DWORD dwType,
        DWORD dwLIP,
        DWORD dwLPort,
        DWORD dwFwdIP,
        DWORD dwFwdPort,
        DWORD dwParentID
    );
}

#endif // HERMIT_CORE_SOCKET_HPP