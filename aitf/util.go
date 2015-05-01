package aitf

import "net"

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
