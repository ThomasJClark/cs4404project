package main

import (
	"log"

	"code.google.com/p/gopacket/layers"

	"github.com/ThomasJClark/cs4404project/aitf/routerecord"
	"github.com/ThomasJClark/cs4404project/pkg/go-netfilter-queue"
)

func main() {
	/*sudo iptables -I INPUT -j NFQUEUE --queue-num 0*/
	nfq, err := netfilter.NewNFQueue(0, 100000, 0xffff)
	if err != nil {
		log.Fatal(err)
	}

	defer nfq.Close()

	/*Listen for any packets arriving at this host.  If any of them have AITF
	route records, remove them before letting the kernel send them to the
	application layer.*/
	for packet := range nfq.GetPackets() {
		var ipLayer *layers.IPv4

		/* Get the IPv4 layer, or ignore it if it doesn't exist. */
		if layer := packet.Packet.Layer(layers.LayerTypeIPv4); layer != nil {
			ipLayer = layer.(*layers.IPv4)
		} else {
			packet.SetVerdict(netfilter.NF_ACCEPT)
			continue
		}

		if routerecord.Shimmed(ipLayer) {
			/*If the IP layer has a shim, remove it.*/
			log.Println("Got AITF shimmed packet from", ipLayer.SrcIP)
			routerecord.Unshim(ipLayer)

			/*Serialize the IP packet. Assuming this is successful, accept it.*/
			b, err := routerecord.Serialize(ipLayer)
			if err != nil {
				log.Println(err)
				packet.SetVerdict(netfilter.NF_DROP)
			} else {
				packet.SetResult(netfilter.NF_ACCEPT, b)
			}
		} else {
			/*Any packets without a shim can be accepted as-is.*/
			log.Println("Got", ipLayer.Protocol, "packet from", ipLayer.SrcIP)
			packet.SetVerdict(netfilter.NF_ACCEPT)
		}
	}
}
