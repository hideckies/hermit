#ifndef HERMIT_IP_HPP
#define HERMIT_IP_HPP

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <string>
#include "convert.hpp"
#include "macros.hpp"

std::wstring GetIpAddresses();

#endif // HERMIT_IP_HPP