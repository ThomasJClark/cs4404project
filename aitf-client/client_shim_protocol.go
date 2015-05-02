package main

import (
	"log"
	"net"

	"code.google.com/p/gopacket/layers"
	"github.com/ThomasJClark/cs4404project/aitf"
	"github.com/ThomasJClark/cs4404project/aitf/filter"
	"github.com/ThomasJClark/cs4404project/aitf/routerecord"
	"github.com/ThomasJClark/cs4404project/pkg/go-netfilter-queue"
)

/*listenForRouteRecords intercepts all incoming packets to this host and
removes their route records before letting the operating system process them.

If listenForRouteRecords is true, it also sends filter requests whenever an
ICMP packet from 10.4.32.4 arrives.
*/
func listenForRouteRecords(sendFilterRequests bool) {
	nfq, err := netfilter.NewNFQueue(0, 100000, 0xffff)
	if err != nil {
		log.Fatal(err)
	}

	defer nfq.Close()

	for packet := range nfq.GetPackets() {
		var ipLayer *layers.IPv4

		if layer := packet.Packet.Layer(layers.LayerTypeIPv4); layer != nil {
			ipLayer = layer.(*layers.IPv4)
		} else {
			packet.SetVerdict(netfilter.NF_ACCEPT)
			continue
		}

		if routerecord.Shimmed(ipLayer) {
			/*If the IP layer has a shim, remove it.*/
			log.Println("Got AITF shimmed packet from", aitf.Hostname(ipLayer.SrcIP))
			rr := routerecord.Unshim(ipLayer)

			if sendFilterRequests {
				/*If this is a malicious packet, construct a filter request to stop any
				future undesired traffic from this flow. The policy module simply
				considers any ICMP traffic from the attacker to be "malicous".*/
				if ipLayer.Protocol == layers.IPProtocolICMPv4 && ipLayer.SrcIP.Equal(net.ParseIP("10.4.32.4")) {
					log.Println("Malicious packet detected from", aitf.Hostname(ipLayer.SrcIP))

					req := filter.Request{
						Type:  filter.FilterReq,
						SrcIP: ipLayer.SrcIP,
						DstIP: ipLayer.DstIP,
						Flow:  *rr,
					}
					req.Send(rr.Path[len(rr.Path)-1].IP)
				}
			}

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
			log.Println("Got", ipLayer.Protocol, "packet from", aitf.Hostname(ipLayer.SrcIP))
			packet.SetVerdict(netfilter.NF_ACCEPT)
		}
	}
}
