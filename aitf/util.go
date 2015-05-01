package aitf

import (
	"fmt"
	"net"
)

/*LocalIP returns the IP address of this machine.*/
func LocalIP() net.IP {
	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		ip := addr.(*net.IPNet).IP

		/*The first address that isn't loopback (i.e. not 127.0.0.1) is probably
		the one we care about.*/
		if ip.To4() != nil && !ip.IsLoopback() {
			return ip
		}
	}

	return nil
}

/*Hostname returns the hostname of the given IP address if available, or the
IP address otherwise. If the hostname is found, the IP address is also appended
in parentheses.*/
func Hostname(ip net.IP) string {
	names, err := net.LookupAddr(ip.String())
	if err != nil || len(names) == 0 {
		return ip.String()
	}

	return fmt.Sprintf("%s (%s)", names[0], ip.String())
}
