package meta

import (
	"fmt"
	"net"
)

func IsIpAddr(addr string) bool {
	if parsed := net.ParseIP(addr); parsed != nil {
		return true
	}
	return false
}

func InterfaceExists(interfaceName string) (bool, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false, err
	}

	for _, iface := range ifaces {
		if iface.Name == interfaceName {
			return true, nil
		}
	}
	return false, nil
}

func GetInterfaceIpv4Addr(interfaceName string) (string, error) {
	var ipv4Addr net.IP

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return "", err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}

	for _, addr := range addrs {
		if ipv4Addr = addr.(*net.IPNet).IP.To4(); ipv4Addr != nil {
			break
		}
	}
	if ipv4Addr == nil {
		return "", fmt.Errorf("IPv4 address not found on the interface: %s", interfaceName)
	}
	return ipv4Addr.String(), nil
}

func GetSpecificHost(host string) string {
	if host == "0.0.0.0" || host == "::" {
		// If the specific bind address is not set, get the Ipv4 address of the `eth0` interface.
		ipv4Addr, err := GetInterfaceIpv4Addr("eth0")
		if err != nil {
			return "localhost"
		}
		return ipv4Addr
	} else if host == "127.0.0.1" || host == "::1" {
		return "localhost"
	} else {
		return host
	}
}
