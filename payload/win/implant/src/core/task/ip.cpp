#include "core/task.hpp"

namespace Task
{
    std::wstring Ip(State::PSTATE pState)
    {
        std::wstring result;
        
        DWORD dwRetVal = 0;
        unsigned int i = 0;

        ULONG flags = GAA_FLAG_INCLUDE_PREFIX;

        ULONG family = AF_UNSPEC;
        // ULONG family = AF_INET;
        // ULONG family = AF_INET6;

        LPVOID lpMsgBuf = NULL;
        Win32::PIP_ADAPTER_ADDRESSES_LH pAddresses = NULL;
        ULONG outBufLen = 0;
        ULONG Iterations = 0;

        Win32::PIP_ADAPTER_ADDRESSES_LH pCurrAddresses = NULL;
        Win32::PIP_ADAPTER_UNICAST_ADDRESS pUnicast = NULL;
        Win32::PIP_ADAPTER_ANYCAST_ADDRESS pAnycast = NULL;
        Win32::PIP_ADAPTER_MULTICAST_ADDRESS pMulticast = NULL;
        Win32::IP_ADAPTER_DNS_SERVER_ADDRESS* pDnsServer = NULL;
        Win32::PIP_ADAPTER_GATEWAY_ADDRESS_LH pGateway = NULL;
        Win32::IP_ADAPTER_PREFIX *pPrefix = NULL;

        // Allocate a 15KB buffer to start with.
        outBufLen = WORKING_BUFFER_SIZE;

        do {
            pAddresses = (Win32::IP_ADAPTER_ADDRESSES_LH*)MALLOC(outBufLen);
            if (pAddresses == NULL)
            {
                return L"Error: Could not allocate memory for addresses";
            }

            dwRetVal = pState->pProcs->lpGetAdaptersAddresses(
                family,
                flags,
                NULL,
                (Win32::PIP_ADAPTER_ADDRESSES)pAddresses,
                &outBufLen
            );
            if (dwRetVal == ERROR_BUFFER_OVERFLOW)
            {
                FREE(pAddresses);
                pAddresses = NULL;
            }
            else
            {
                break;
            }

            Iterations++;
        } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (Iterations < MAX_TRIES));

        if (dwRetVal == NO_ERROR)
        {
            pCurrAddresses = pAddresses;
            while (pCurrAddresses) {
                std::wstring wFriendlyName(pCurrAddresses->FriendlyName);
                result += wFriendlyName + L"\n";
                result += std::wstring(wcslen(wFriendlyName.c_str()), '-') + L"\n";

                result += L"Description: " + std::wstring(pCurrAddresses->Description) + L"\n";
                // result += L"DNS Suffix: " + std::wstring(pCurrAddresses->DnsSuffix) + L"\n";

                // result += L"IfIndex (IPv4 Interface): " + ConvertDWORDToWstring(pCurrAddresses->IfIndex) + L"\n";
                // result += L"Adapter Name: " + UTF8Decode(std::string(pCurrAddresses->AdapterName)) + L"\n";

                pUnicast = (Win32::PIP_ADAPTER_UNICAST_ADDRESS)pCurrAddresses->FirstUnicastAddress;
                if (pUnicast)
                {
                    result += L"IPv4 Addresses:\n";
                    for (i = 0; pUnicast != NULL; i++)
                    {
                        if (pUnicast->Address.lpSockaddr->sa_family == AF_INET)
                        {
                            sockaddr_in* pAddr = reinterpret_cast<sockaddr_in*>(pUnicast->Address.lpSockaddr);
                            const wchar_t ipAddress[INET_ADDRSTRLEN] = {};
                            char* cAddr = inet_ntoa(pAddr->sin_addr);
                            result += L"  " + Utils::Convert::UTF8Decode(std::string(cAddr)) + L"\n";
                        }
                        pUnicast = pUnicast->Next;
                    }
                }

                pAnycast = pCurrAddresses->FirstAnycastAddress;
                if (pAnycast)
                {
                    result += L"IPv6 Addresses:\n";
                    for (i = 0; pAnycast != NULL; i++)
                    {
                        if (pAnycast->Address.lpSockaddr->sa_family == AF_INET6)
                        {
                            sockaddr_in* pAddr = reinterpret_cast<sockaddr_in*>(pAnycast->Address.lpSockaddr);
                            const wchar_t ipAddress[INET_ADDRSTRLEN] = {};
                            char* cAddr = inet_ntoa(pAddr->sin_addr);
                            result += L"  " + Utils::Convert::UTF8Decode(std::string(cAddr)) + L"\n";
                        }
                        pAnycast = pAnycast->Next;
                    }
                }

                // pMulticast = pCurrAddresses->FirstMulticastAddress;
                // if (pMulticast)
                // {
                //     for (i = 0; pMulticast != NULL; i++)
                //     {
                //         pMulticast = pMulticast->Next;
                //     }
                // }

                pDnsServer = pCurrAddresses->FirstDnsServerAddress;
                if (pDnsServer)
                {
                    result += L"DNS Server Addresses:\n";
                    for (i = 0; pDnsServer != NULL; i++)
                    {
                        if (pDnsServer->Address.lpSockaddr->sa_family == AF_INET)
                        {
                            sockaddr_in* pAddr = reinterpret_cast<sockaddr_in*>(pDnsServer->Address.lpSockaddr);
                            const wchar_t ipAddress[INET_ADDRSTRLEN] = {};
                            char* cAddr = inet_ntoa(pAddr->sin_addr);
                            result += L"  " + Utils::Convert::UTF8Decode(std::string(cAddr)) + L"\n";
                        }
                        pDnsServer = pDnsServer->Next;
                    }
                }

                if (pCurrAddresses->PhysicalAddressLength != 0)
                {
                    result += L"Physical Address: ";
                    for (i = 0; i < (int)pCurrAddresses->PhysicalAddressLength; i++)
                    {
                        if (i == (pCurrAddresses->PhysicalAddressLength - 1))
                        {
                            result += std::to_wstring((int)pCurrAddresses->PhysicalAddress[i]) + L"\n";
                        }
                        else
                        {
                            result += std::to_wstring((int)pCurrAddresses->PhysicalAddress[i]) + L"-";
                        }
                    }
                }

                pGateway = pCurrAddresses->FirstGatewayAddress;
                if (pGateway)
                {
                    result += L"Gateway Addresseses:\n";
                    for (i = 0; pGateway != NULL; i++)
                    {
                        if (pGateway->Address.lpSockaddr->sa_family == AF_INET)
                        {
                            sockaddr_in* pAddr = reinterpret_cast<sockaddr_in*>(pGateway->Address.lpSockaddr);
                            const wchar_t ipAddress[INET_ADDRSTRLEN] = {};
                            char* cAddr = inet_ntoa(pAddr->sin_addr);
                            result += L"  " + Utils::Convert::UTF8Decode(std::string(cAddr)) + L"\n";
                        }
                        pGateway = pGateway->Next;
                    }
                }

                // PIP_ADAPTER_GATEWAY_ADDRESS_LH gatewayAddress = pCurrAddresses->FirstGatewayAddress;
                // SOCKET_ADDRESS gatewaySockAddr = gatewayAddress->Address;
                // result += L"Gateway Address: " + std::wstring(gatewaySockAddr->lpSockAddr) + L"\n";

                // result += L"Flags: " + ConvertDWORDToWstring(pCurrAddresses->Flags) + L"\n";
                // result += L"MTU: " + ConvertDWORDToWstring(pCurrAddresses->Mtu) + L"\n";
                // result += L"IfType: " + ConvertDWORDToWstring(pCurrAddresses->IfType) + L"\n";
                // result += L"OperStatus: " + pCurrAddresses->OperStatus + "\n";
                // result += L"Ipv6IfIndex (IPv6 Interface): " + ConvertDWORDToWstring(pCurrAddresses->Ipv6IfIndex) + L"\n";

                // result += L"ZoneIndices (hex): ";
                // for (i = 0; i < 16; i++)
                // {
                //     result += L" " + ConvertDWORDToWstring(pCurrAddresses->ZoneIndices[i]);
                // }
                // result += L"\n";

                // result += L"Transmit Link Speed: " + ConvertDWORDToWstring(pCurrAddresses->TransmitLinkSpeed) + L"\n";
                // result += L"Receive Link Speed: " + ConvertDWORDToWstring(pCurrAddresses->ReceiveLinkSpeed) + L"\n";

                // pPrefix = pCurrAddresses->FirstPrefix;
                // if (pPrefix)
                // {
                //     for (i = 0; pPrefix != NULL; i++)
                //     {
                //         pPrefix = pPrefix->Next;
                //     }
                //     result += L"Number of IP Adapter Prefix entries: " + ConvertDWORDToWstring(i) + L"\n";
                // }
                // else
                // {
                //     result += L"Number of IP Adapter Prefix entries: 0\n";
                // }

                result += L"\n";

                pCurrAddresses = pCurrAddresses->Next;
            }
        }
        else
        {
            result += L"Call to GetAdaptersAddresses failed with error: " + Utils::Convert::DWORDToWstring(dwRetVal) + L"\n";
            if (dwRetVal == ERROR_NO_DATA)
            {
                result += L"No addresses were found for the required parameters\n";
            }
            else
            {
                if (pState->pProcs->lpFormatMessageW(
                    FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                    NULL,
                    dwRetVal,
                    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                    // Default language
                    (LPTSTR) & lpMsgBuf,
                    0,
                    NULL
                )) {
                    wchar_t* wlpMsgBuf = reinterpret_cast<wchar_t*>(lpMsgBuf);
                    result += L"Error: ";
                    result += wlpMsgBuf;
                    result += L"\n";
                    pState->pProcs->lpLocalFree(lpMsgBuf);
                    if (pAddresses)
                    {
                        FREE(pAddresses);
                    }
                    return result;
                }
            }
        }

        if (pAddresses)
        {
            FREE(pAddresses);
        }

        return result;
    }
}