#ifndef HERMIT_CORE_WIN32_HPP
#define HERMIT_CORE_WIN32_HPP

namespace Win32
{

  #define MAX_DNS_SUFFIX_STRING_LENGTH    256
  #define MAX_ADAPTER_ADDRESS_LENGTH      8
  #define MAX_DHCPV6_DUID_LENGTH          130

  // ------------------------------------------------------------------
  // amsi.h
  // ------------------------------------------------------------------

  typedef HANDLE HAMSICONTEXT;
  typedef HANDLE HAMSISESSION;

  typedef enum {
    AMSI_RESULT_CLEAN,
    AMSI_RESULT_NOT_DETECTED,
    AMSI_RESULT_BLOCKED_BY_ADMIN_START,
    AMSI_RESULT_BLOCKED_BY_ADMIN_END,
    AMSI_RESULT_DETECTED
  } AMSI_RESULT;

  // ------------------------------------------------------------------
  // ifdef.h
  // ------------------------------------------------------------------

  typedef DWORD       NET_API_STATUS;
  typedef ULONG       NET_IFINDEX;
  typedef NET_IFINDEX IF_INDEX;
  typedef ULONG       IFTYPE;
  typedef UINT32      NET_IF_COMPARTMENT_ID;

  typedef enum {
    IfOperStatusUp = 1,
    IfOperStatusDown,
    IfOperStatusTesting,
    IfOperStatusUnknown,
    IfOperStatusDormant,
    IfOperStatusNotPresent,
    IfOperStatusLowerLayerDown
  } IF_OPER_STATUS;

  typedef enum _NET_IF_CONNECTION_TYPE {
    NET_IF_CONNECTION_DEDICATED = 1,
    NET_IF_CONNECTION_PASSIVE = 2,
    NET_IF_CONNECTION_DEMAND = 3,
    NET_IF_CONNECTION_MAXIMUM = 4
  } NET_IF_CONNECTION_TYPE, *PNET_IF_CONNECTION_TYPE;

  // ------------------------------------------------------------------
  // iphlpapi.h
  // ------------------------------------------------------------------

  #define GAA_FLAG_INCLUDE_PREFIX 0x0010

  typedef union _NET_LUID_LH {
      ULONG64 Value;
      struct {
          ULONG64 Reserved : 24;
          ULONG64 NetLuidIndex : 24;
          ULONG64 IfType : 16;
      } Info;
  } NET_LUID_LH, *PNET_LUID_LH;
  typedef union _NET_LUID_LH NET_LUID_LH;
  typedef NET_LUID_LH NET_LUID;
  typedef NET_LUID    IF_LUID;

  typedef enum {
    IpPrefixOriginOther = 0, 
    IpPrefixOriginManual, 
    IpPrefixOriginWellKnown, 
    IpPrefixOriginDhcp, 
    IpPrefixOriginRouterAdvertisement
  } IP_PREFIX_ORIGIN;

  typedef enum {
    NlsoOther = 0,
    NlsoManual,
    NlsoWellKnown,
    NlsoDhcp,
    NlsoLinkLayerAddress,
    NlsoRandom,
    IpSuffixOriginOther = 0,
    IpSuffixOriginManual,
    IpSuffixOriginWellKnown,
    IpSuffixOriginDhcp,
    IpSuffixOriginLinkLayerAddress,
    IpSuffixOriginRandom,
    IpSuffixOriginUnchanged = 1 << 4
  } NL_SUFFIX_ORIGIN;

  typedef enum {
    NldsInvalid,
    NldsTentative,
    NldsDuplicate,
    NldsDeprecated,
    NldsPreferred,
    IpDadStateInvalid = 0,
    IpDadStateTentative,
    IpDadStateDuplicate,
    IpDadStateDeprecated,
    IpDadStatePreferred,
  } NL_DAD_STATE;

  typedef enum {
    TUNNEL_TYPE_NONE = 0,
    TUNNEL_TYPE_OTHER = 1,
    TUNNEL_TYPE_DIRECT = 2,
    TUNNEL_TYPE_6TO4 = 11,
    TUNNEL_TYPE_ISATAP = 13,
    TUNNEL_TYPE_TEREDO = 14,
    TUNNEL_TYPE_IPHTTPS = 15
  } TUNNEL_TYPE, *PTUNNEL_TYPE;

  typedef NL_SUFFIX_ORIGIN    IP_SUFFIX_ORIGIN;
  typedef NL_DAD_STATE        IP_DAD_STATE;

  // typedef struct _GUID {
  //   unsigned long  Data1;
  //   unsigned short Data2;
  //   unsigned short Data3;
  //   unsigned char  Data4[8];
  // } GUID;

  typedef GUID NET_IF_NETWORK_GUID;

  typedef struct _MY_SOCKET_ADDRESS {
    LPSOCKADDR lpSockaddr;
    INT        iSockaddrLength;
  } MY_SOCKET_ADDRESS, *PMY_SOCKET_ADDRESS, *LPMY_SOCKET_ADDRESS;

  typedef struct _IP_ADAPTER_UNICAST_ADDRESS_LH {
    union {
      ULONGLONG Alignment;
      struct {
        ULONG Length;
        DWORD Flags;
      };
    };
    struct _IP_ADAPTER_UNICAST_ADDRESS_LH *Next;
    MY_SOCKET_ADDRESS                        Address;
    IP_PREFIX_ORIGIN                      PrefixOrigin;
    IP_SUFFIX_ORIGIN                      SuffixOrigin;
    IP_DAD_STATE                          DadState;
    ULONG                                 ValidLifetime;
    ULONG                                 PreferredLifetime;
    ULONG                                 LeaseLifetime;
    UINT8                                 OnLinkPrefixLength;
  } IP_ADAPTER_UNICAST_ADDRESS_LH, *PIP_ADAPTER_UNICAST_ADDRESS_LH;

  typedef IP_ADAPTER_UNICAST_ADDRESS_LH IP_ADAPTER_UNICAST_ADDRESS;
  typedef IP_ADAPTER_UNICAST_ADDRESS_LH *PIP_ADAPTER_UNICAST_ADDRESS;

  typedef struct _IP_ADAPTER_ANYCAST_ADDRESS_XP {
    union {
      ULONGLONG Alignment;
      struct {
        ULONG Length;
        DWORD Flags;
      };
    };
    struct _IP_ADAPTER_ANYCAST_ADDRESS_XP *Next;
    MY_SOCKET_ADDRESS                        Address;
  } IP_ADAPTER_ANYCAST_ADDRESS_XP, *PIP_ADAPTER_ANYCAST_ADDRESS_XP;

  typedef IP_ADAPTER_ANYCAST_ADDRESS_XP IP_ADAPTER_ANYCAST_ADDRESS;
  typedef IP_ADAPTER_ANYCAST_ADDRESS_XP *PIP_ADAPTER_ANYCAST_ADDRESS;

  typedef struct _IP_ADAPTER_MULTICAST_ADDRESS_XP {
    union {
      ULONGLONG Alignment;
      struct {
        ULONG Length;
        DWORD Flags;
      };
    };
    struct _IP_ADAPTER_MULTICAST_ADDRESS_XP *Next;
    MY_SOCKET_ADDRESS                          Address;
  } IP_ADAPTER_MULTICAST_ADDRESS_XP, *PIP_ADAPTER_MULTICAST_ADDRESS_XP;

  typedef IP_ADAPTER_MULTICAST_ADDRESS_XP IP_ADAPTER_MULTICAST_ADDRESS;
  typedef IP_ADAPTER_MULTICAST_ADDRESS_XP *PIP_ADAPTER_MULTICAST_ADDRESS;

  typedef struct _IP_ADAPTER_DNS_SERVER_ADDRESS_XP {
    union {
      ULONGLONG Alignment;
      struct {
        ULONG Length;
        DWORD Reserved;
      };
    };
    struct _IP_ADAPTER_DNS_SERVER_ADDRESS_XP *Next;
    MY_SOCKET_ADDRESS                           Address;
  } IP_ADAPTER_DNS_SERVER_ADDRESS_XP, *PIP_ADAPTER_DNS_SERVER_ADDRESS_XP;

  typedef IP_ADAPTER_DNS_SERVER_ADDRESS_XP IP_ADAPTER_DNS_SERVER_ADDRESS;
  typedef IP_ADAPTER_DNS_SERVER_ADDRESS_XP *PIP_ADAPTER_DNS_SERVER_ADDRESS;

  typedef struct _IP_ADAPTER_PREFIX_XP {
    union {
      ULONGLONG Alignment;
      struct {
        ULONG Length;
        DWORD Flags;
      };
    };
    struct _IP_ADAPTER_PREFIX_XP *Next;
    MY_SOCKET_ADDRESS               Address;
    ULONG                        PrefixLength;
  } IP_ADAPTER_PREFIX_XP, *PIP_ADAPTER_PREFIX_XP;

  typedef IP_ADAPTER_PREFIX_XP IP_ADAPTER_PREFIX;
  typedef IP_ADAPTER_PREFIX_XP *PIP_ADAPTER_PREFIX;

  typedef struct _IP_ADAPTER_WINS_SERVER_ADDRESS_LH {
    union {
      ULONGLONG Alignment;
      struct {
        ULONG Length;
        DWORD Reserved;
      };
    };
    struct _IP_ADAPTER_WINS_SERVER_ADDRESS_LH *Next;
    MY_SOCKET_ADDRESS                            Address;
  } IP_ADAPTER_WINS_SERVER_ADDRESS_LH, *PIP_ADAPTER_WINS_SERVER_ADDRESS_LH;

  typedef struct _IP_ADAPTER_GATEWAY_ADDRESS_LH {
    union {
      ULONGLONG Alignment;
      struct {
        ULONG Length;
        DWORD Reserved;
      };
    };
    struct _IP_ADAPTER_GATEWAY_ADDRESS_LH *Next;
    MY_SOCKET_ADDRESS                        Address;
  } IP_ADAPTER_GATEWAY_ADDRESS_LH, *PIP_ADAPTER_GATEWAY_ADDRESS_LH;

  typedef struct _IP_ADAPTER_DNS_SUFFIX {
    struct _IP_ADAPTER_DNS_SUFFIX *Next;
    WCHAR                         String[MAX_DNS_SUFFIX_STRING_LENGTH];
  } IP_ADAPTER_DNS_SUFFIX, *PIP_ADAPTER_DNS_SUFFIX;

  typedef struct _IP_ADAPTER_ADDRESSES_LH {
    union {
      ULONGLONG Alignment;
      struct {
        ULONG    Length;
        IF_INDEX IfIndex;
      };
    };
    struct _IP_ADAPTER_ADDRESSES_LH    *Next;
    PCHAR                              AdapterName;
    PIP_ADAPTER_UNICAST_ADDRESS_LH     FirstUnicastAddress;
    PIP_ADAPTER_ANYCAST_ADDRESS_XP     FirstAnycastAddress;
    PIP_ADAPTER_MULTICAST_ADDRESS_XP   FirstMulticastAddress;
    PIP_ADAPTER_DNS_SERVER_ADDRESS_XP  FirstDnsServerAddress;
    PWCHAR                             DnsSuffix;
    PWCHAR                             Description;
    PWCHAR                             FriendlyName;
    BYTE                               PhysicalAddress[MAX_ADAPTER_ADDRESS_LENGTH];
    ULONG                              PhysicalAddressLength;
    union {
      ULONG Flags;
      struct {
        ULONG DdnsEnabled : 1;
        ULONG RegisterAdapterSuffix : 1;
        ULONG Dhcpv4Enabled : 1;
        ULONG ReceiveOnly : 1;
        ULONG NoMulticast : 1;
        ULONG Ipv6OtherStatefulConfig : 1;
        ULONG NetbiosOverTcpipEnabled : 1;
        ULONG Ipv4Enabled : 1;
        ULONG Ipv6Enabled : 1;
        ULONG Ipv6ManagedAddressConfigurationSupported : 1;
      };
    };
    ULONG                              Mtu;
    IFTYPE                             IfType;
    IF_OPER_STATUS                     OperStatus;
    IF_INDEX                           Ipv6IfIndex;
    ULONG                              ZoneIndices[16];
    PIP_ADAPTER_PREFIX_XP              FirstPrefix;
    ULONG64                            TransmitLinkSpeed;
    ULONG64                            ReceiveLinkSpeed;
    PIP_ADAPTER_WINS_SERVER_ADDRESS_LH FirstWinsServerAddress;
    PIP_ADAPTER_GATEWAY_ADDRESS_LH     FirstGatewayAddress;
    ULONG                              Ipv4Metric;
    ULONG                              Ipv6Metric;
    IF_LUID                            Luid;
    MY_SOCKET_ADDRESS                     Dhcpv4Server;
    NET_IF_COMPARTMENT_ID              CompartmentId;
    NET_IF_NETWORK_GUID                NetworkGuid;
    NET_IF_CONNECTION_TYPE             ConnectionType;
    TUNNEL_TYPE                        TunnelType;
    MY_SOCKET_ADDRESS                     Dhcpv6Server;
    BYTE                               Dhcpv6ClientDuid[MAX_DHCPV6_DUID_LENGTH];
    ULONG                              Dhcpv6ClientDuidLength;
    ULONG                              Dhcpv6Iaid;
    PIP_ADAPTER_DNS_SUFFIX             FirstDnsSuffix;
  } IP_ADAPTER_ADDRESSES_LH, *PIP_ADAPTER_ADDRESSES_LH;

  typedef IP_ADAPTER_ADDRESSES_LH IP_ADAPTER_ADDRESSES;
  typedef IP_ADAPTER_ADDRESSES_LH *PIP_ADAPTER_ADDRESSES;

  // ------------------------------------------------------------------
  // tcpmib.h
  // ------------------------------------------------------------------

  #define ANY_SIZE   1

  typedef enum 
  {
      MIB_TCP_STATE_CLOSED = 1,
      MIB_TCP_STATE_LISTEN = 2,
      MIB_TCP_STATE_SYN_SENT = 3,
      MIB_TCP_STATE_SYN_RCVD = 4,
      MIB_TCP_STATE_ESTAB = 5,
      MIB_TCP_STATE_FIN_WAIT1 = 6,
      MIB_TCP_STATE_FIN_WAIT2 = 7,
      MIB_TCP_STATE_CLOSE_WAIT = 8,
      MIB_TCP_STATE_CLOSING = 9,
      MIB_TCP_STATE_LAST_ACK = 10,
      MIB_TCP_STATE_TIME_WAIT = 11,
      MIB_TCP_STATE_DELETE_TCB = 12,
  } MIB_TCP_STATE;

  typedef struct _MIB_TCPROW {
      union {
          DWORD dwState;
          MIB_TCP_STATE State;
      };
      DWORD dwLocalAddr;
      DWORD dwLocalPort;
      DWORD dwRemoteAddr;
      DWORD dwRemotePort;
  } MIB_TCPROW, *PMIB_TCPROW;

  typedef struct _MIB_TCPTABLE {
      DWORD      dwNumEntries;
      MIB_TCPROW table[ANY_SIZE];
  } MIB_TCPTABLE, *PMIB_TCPTABLE;
}


#endif // HERMIT_CORE_WIN32_HPP
