package main

import (
	"bytes"
	"log"
	"net"

	"code.google.com/p/gopacket/layers"

	"github.com/ThomasJClark/cs4404project/aitf"
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

	/*sudo iptables -I FORWARD -j NFQUEUE --queue-num 0*/
	nfq, err := netfilter.NewNFQueue(0, 100000, 0xffff)
	if err != nil {
		log.Fatal(err)
	}

	defer nfq.Close()

	/*Listen for any packets being forwarded by this router and create/update the
	route record shim layer in each of them.*/
	for packet := range nfq.GetPackets() {
		if ipLayer := packet.Packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ipHeader := ipLayer.(*layers.IPv4)
			ipPayload := bytes.NewBuffer(ipLayer.LayerPayload())
			var b bytes.Buffer
			var rr aitf.RouteRecord

			/*Any local loopback packets can be accepted with modification, as they
			do not actually go through the network. This is most likely to happen
			while testing using an iptables rule that may include loopback traffice.*/
			if ipHeader.SrcIP.IsLoopback() {
				packet.SetVerdict(netfilter.NF_ACCEPT)
				continue
			}

			if ipHeader.Protocol != IPProtocolAITFRouteRecord {
				/*If the packet does not already have a route record, create one.*/
				rr = aitf.NewRouteRecord()
				rr.Protocol = uint8(ipHeader.Protocol)

				log.Println("Got", ipHeader.Protocol, "packet from", ipHeader.SrcIP, "WITHOUT route record")
			} else {
				/*Otherwise, read the existing route record from the packet.*/
				rr.ReadFrom(ipPayload)

				log.Println("Got", layers.IPProtocol(rr.Protocol), "packet from", ipHeader.SrcIP, "WITH route record")
			}

			/*This router is appended to the end of the route record to indicated
			that is is part of the path that the packet was transmitted along.*/
			rr.AddRouter(aitf.NewRouter(localIP, ipHeader.DstIP))

			/*The total length field of the IP header must be updated to incorporate
			the new length of the route record, and we must make sure that the
			protocol number is set to indicate a route record. Because of these
			changes, the IP checksum must also be recomputed.*/
			totalLength := len(ipLayer.LayerContents()) + rr.Len() + ipPayload.Len()
			ipLayer.LayerContents()[2] = byte(totalLength >> 8)
			ipLayer.LayerContents()[3] = byte(totalLength & 0xff)
			ipLayer.LayerContents()[9] = byte(IPProtocolAITFRouteRecord)
			ipLayer.LayerContents()[10] = 0
			ipLayer.LayerContents()[11] = 0

			/*Put the modified shim layer back into the packet, right after the IP
			header, and accept the packet.*/
			b.Write(ipLayer.LayerContents())
			rr.WriteTo(&b)
			b.Write(ipPayload.Bytes())
			packet.SetResult(netfilter.NF_ACCEPT, b.Bytes())

			log.Println("Sent", layers.IPProtocol(rr.Protocol), "packet to", ipHeader.DstIP, "WITH route record")
		}
	}
}
