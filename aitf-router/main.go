package main

import (
	"log"
	"net"

	"code.google.com/p/gopacket/layers"

	"github.com/ThomasJClark/cs4404project/aitf/routerecord"
	"github.com/ThomasJClark/cs4404project/pkg/go-netfilter-queue"
)

const (
	/*IPProtocolAITFRouteRecord is an IPv4 protocol number that indicates the
	presence of of a route record.*/
	IPProtocolAITFRouteRecord layers.IPProtocol = 253
)

/*Get the local IP address of this router by choosing the first interface
address that is IPv4 and is not a loopback address.*/
func localIP() net.IP {
	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		ip := addr.(*net.IPNet).IP

		if ip.To4() != nil && !ip.IsLoopback() {
			return ip
		}
	}

	return nil
}

func main() {
	localIP := localIP()
	log.Println("My IP address is", localIP)

	/*sudo iptables -I FORWARD -j NFQUEUE --queue-num 0*/
	nfq, err := netfilter.NewNFQueue(0, 100000, 0xffff)
	if err != nil {
		log.Fatal(err)
	}

	defer nfq.Close()

	/*Listen for any packets being forwarded by this router and create/update the
	route record shim layer in each of them.*/
	for packet := range nfq.GetPackets() {
		if layer := packet.Packet.Layer(layers.LayerTypeIPv4); layer != nil {
			ipLayer := layer.(*layers.IPv4)

			/*Any local loopback packets can be accepted with modification, as they
			do not actually go through the network. This is most likely to happen
			while testing using an iptables rule that may include loopback traffice.*/
			if ipLayer.SrcIP.IsLoopback() {
				packet.SetVerdict(netfilter.NF_ACCEPT)
				continue
			}

			if routerecord.Shimmed(ipLayer) {
				log.Println("Got AITF shimmed packet from", ipLayer.SrcIP)

				b := routerecord.Unshim(ipLayer)
				packet.SetResult(netfilter.NF_ACCEPT, b)
			} else {
				log.Println("Got", ipLayer.Protocol, "packet from", ipLayer.SrcIP)

				b := routerecord.Shim(ipLayer, routerecord.NewRouter(localIP, ipLayer.DstIP))
				packet.SetResult(netfilter.NF_REPEAT, b)
			}
		}
	}
}
