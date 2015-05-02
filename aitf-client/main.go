package main

import (
	"flag"
	"log"
	"net"

	"code.google.com/p/gopacket/layers"

	"github.com/ThomasJClark/cs4404project/aitf"
	"github.com/ThomasJClark/cs4404project/aitf/filter"
	"github.com/ThomasJClark/cs4404project/aitf/routerecord"
	"github.com/ThomasJClark/cs4404project/pkg/go-netfilter-queue"
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	/*Read in the command-line options.*/
	modeStr := flag.String("mode", "comply", "What to do after receiving a filter request (comply, ignore, or lie)")
	sendRequests := flag.Bool("sendRequests", false, "Enable the dummy policy module to send filter request. (true or false)")
	flag.Parse()

	switch *modeStr {
	case "comply":
		log.Println("Complying with filtering requests.")
		go listenForFilterRequest(comply)
	case "ignore":
		log.Println("Ignoring filtering requests.")
		go listenForFilterRequest(ignore)
	case "lie":
		log.Println("Pretending to comply with filtering requests.")
		go listenForFilterRequest(lie)
	}

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
			log.Println("Got AITF shimmed packet from", aitf.Hostname(ipLayer.SrcIP))
			rr := routerecord.Unshim(ipLayer)

			if *sendRequests {
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
