#ifndef HERMIT_NET_HPP
#define HERMIT_NET_HPP

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <string>
#include "common.hpp"
#include "convert.hpp"
#include "macros.hpp"

std::wstring GetNetTCPConnection();

#endif // HERMIT_NET_HPP