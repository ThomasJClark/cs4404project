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
		log.Println(packet.Packet)
		var ipLayer *layers.IPv4

		/* Get the IPv4 layer, or ignore it if it doesn't exist. */
		if layer := packet.Packet.Layer(layers.LayerTypeIPv4); layer != nil {
			ipLayer = layer.(*layers.IPv4)
		} else {
			packet.SetVerdict(netfilter.NF_ACCEPT)
			continue
		}

		/*Any local loopback packets can be accepted with modification, as they
		do not actually go through the network. This is most likely to happen
		while testing using an iptables rule that may include loopback traffic.*/
		if ipLayer.SrcIP.IsLoopback() {
			packet.SetVerdict(netfilter.NF_ACCEPT)
			continue
		}

		if routerecord.Shimmed(ipLayer) {
			log.Println("Got AITF shimmed packet from", ipLayer.SrcIP, "for", ipLayer.DstIP)
		} else {
			log.Println("Got", ipLayer.Protocol, "packet from", ipLayer.SrcIP, "for", ipLayer.DstIP)
		}

		/*Shim up the packet. One of the assumptions made is that each route knows
		which hosts support AITF. All hosts in the test scenerios do, so there's
		never a need for a router to remove the shim layer.*/
		routerecord.Shim(ipLayer, routerecord.NewRouter(localIP, ipLayer.DstIP))

		/*Serialize the IP packet. Assuming this is successful, accept it.*/
		b, err := routerecord.Serialize(ipLayer)
		if err != nil {
			log.Println(err)
			packet.SetVerdict(netfilter.NF_DROP)
		} else {
			packet.SetResult(netfilter.NF_ACCEPT, b)
		}
	}
}
