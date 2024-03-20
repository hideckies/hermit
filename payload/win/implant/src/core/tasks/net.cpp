#include "core/task.hpp"

namespace Task
{
    std::wstring Net()
    {
        std::wstring result = L"";

        PMIB_TCPTABLE pTcpTable;
        ULONG ulSize = 0;
        DWORD dwRetVal = 0;

        char szLocalAddr[128];
        char szRemoteAddr[128];

        struct in_addr IpAddr;

        int i;

        pTcpTable = (MIB_TCPTABLE*)MALLOC(sizeof(MIB_TCPTABLE));
        if (pTcpTable == NULL)
        {
            return L"Error: Could not allocate memory for TCP table.";
        }

        ulSize = sizeof(MIB_TCPTABLE);

        // Make an initial call to GetTcpTable to get the necessary size into the ulSize variable.
        if ((dwRetVal = GetTcpTable(pTcpTable, &ulSize, TRUE)) == ERROR_INSUFFICIENT_BUFFER)
        {
            FREE(pTcpTable);
            pTcpTable = (MIB_TCPTABLE*)MALLOC(ulSize);
            if (pTcpTable == NULL)
            {
                return L"Error: Could not allocate memory for TCP table.";
            }
        }

        if ((dwRetVal = GetTcpTable(pTcpTable, &ulSize, TRUE)) == NO_ERROR)
        {
            std::wstring labelLocalAddr = L"LocalAddress";
            std::wstring labelLocalPort = L"LocalPort";
            std::wstring labelRemoteAddr = L"RemoteAddress";
            std::wstring labelRemotePort = L"RemotePort";
            std::wstring labelState = L"State";

            result += labelLocalAddr + L"\t\t";
            result += labelLocalPort + L"\t";
            result += labelRemoteAddr + L"\t\t";
            result += labelRemotePort + L"\t";
            result += labelState + L"\n";

            result += std::wstring(wcslen(labelLocalAddr.c_str()), '-') + L"\t\t";
            result += std::wstring(wcslen(labelLocalPort.c_str()), '-') + L"\t";
            result += std::wstring(wcslen(labelRemoteAddr.c_str()), '-') + L"\t\t";
            result += std::wstring(wcslen(labelRemotePort.c_str()), '-') + L"\t";
            result += std::wstring(wcslen(labelState.c_str()), '-') + L"\n";

            for (i = 0; i < (int)pTcpTable->dwNumEntries; i++)
            {
                // LocalAddress
                IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwLocalAddr;
                strcpy_s(szLocalAddr, sizeof(szLocalAddr), inet_ntoa(IpAddr));
                std::string sLocalAddr(szLocalAddr);
                std::wstring wLocalAddr = Utils::Convert::UTF8Decode(sLocalAddr);
                result += wLocalAddr;
                if (wcslen(wLocalAddr.c_str()) <= 7)
                {
                    result += L"\t\t\t";
                }
                else
                {
                    result += L"\t\t";
                }

                // LocalPort
                u_short usLocalPort = ntohs((u_short)pTcpTable->table[i].dwLocalPort);
                char localBuffer[100];
                sprintf_s(localBuffer, sizeof(localBuffer), "%u", usLocalPort);
                std::string sLocalBuffer(localBuffer);
                std::wstring wLocalPort = Utils::Convert::UTF8Decode(sLocalBuffer);
                if (wLocalPort == L"")
                {
                    result += L"0\t\t";
                }
                else
                {
                    result += wLocalPort + L"\t\t";
                }

                // RemoteAddress
                IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwRemoteAddr;
                strcpy_s(szRemoteAddr, sizeof(szRemoteAddr), inet_ntoa(IpAddr));
                std::string sRemoteAddr(szRemoteAddr);
                std::wstring wRemoteAddr = Utils::Convert::UTF8Decode(sRemoteAddr);
                result += wRemoteAddr;
                if (wcslen(wRemoteAddr.c_str()) <= 7)
                {
                    result += L"\t\t\t";
                }
                else
                {
                    result += L"\t\t";
                }

                // RemotePort
                u_short usRemotePort = ntohs((u_short)pTcpTable->table[i].dwRemotePort);
                char remoteBuffer[100];
                sprintf_s(remoteBuffer, sizeof(remoteBuffer), "%u", usRemotePort);
                std::string sRemoteBuffer(remoteBuffer);
                std::wstring wRemotePort = Utils::Convert::UTF8Decode(remoteBuffer);
                if (wRemotePort == L"")
                {
                    result += L"0\t\t";
                }
                else
                {
                    result += wRemotePort + L"\t\t";
                }

                // Status
                switch (pTcpTable->table[i].dwState) {
                case MIB_TCP_STATE_CLOSED:
                    result += L"CLOSED\n";
                    break;
                case MIB_TCP_STATE_LISTEN:
                    result += L"LISTEN\n";
                    break;
                case MIB_TCP_STATE_SYN_SENT:
                    result += L"SYN-SENT\n";
                    break;
                case MIB_TCP_STATE_SYN_RCVD:
                    result += L"SYN-RECEIVED\n";
                    break;
                case MIB_TCP_STATE_ESTAB:
                    result += L"ESTABLISHED\n";
                    break;
                case MIB_TCP_STATE_FIN_WAIT1:
                    result += L"FIN-WAIT-1\n";
                    break;
                case MIB_TCP_STATE_FIN_WAIT2:
                    result += L"FIN-WAIT-2\n";
                    break;
                case MIB_TCP_STATE_CLOSE_WAIT:
                    result += L"CLOSE-WAIT\n";
                    break;
                case MIB_TCP_STATE_CLOSING:
                    result += L"CLOSING\n";
                    break;
                case MIB_TCP_STATE_LAST_ACK:
                    result += L"LAST-ACK\n";
                    break;
                case MIB_TCP_STATE_TIME_WAIT:
                    result += L"TIME-WAIT\n";
                    break;
                case MIB_TCP_STATE_DELETE_TCB:
                    result += L"DELETE-TCB\n";
                    break;
                default:
                    result += L"UNKNOWN\n";
                    break;
                }

                // result += L"PID: " + ConvertDWORDToWstring(pTcpTable->table[i].dwOwningPid);
                // result += L"Offload State: " + ConvertDWORDToWstring(pTcpTable->table[i].dwOffloadState);
                // switch (pTcpTable->table[i].dwOffloadState) {
                // case TcpConnectionOffloadStateInHost:
                //     result += L"Owned by the network stack and not offloaded\n";
                //     break;
                // case TcpConnectionOffloadStateOffloading:
                //     printf("In the process of being offloaded\n");
                //     break;
                // case TcpConnectionOffloadStateOffloaded:
                //     printf("Offloaded to the network interface control\n");
                //     break;
                // case TcpConnectionOffloadStateUploading:
                //     printf("In the process of being uploaded back to the network stack\n");
                //     break;
                // default:
                //     printf("UNKNOWN Offload state value\n");
                //     break;
                // }
            }
        }
        else
        {
            FREE(pTcpTable);
            return L"Error: GetTcpTable2 failed with " + Utils::Convert::DWORDToWstring(dwRetVal);
        }

        if (pTcpTable != NULL)
        {
            FREE(pTcpTable);
            pTcpTable = NULL;
        }

        return result;
    }
}
