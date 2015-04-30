package main

import (
	"bytes"
	"fmt"
	"log"
	"net"

	"github.com/ThomasJClark/cs4404project/aitf/filter"
)

/*sendRequest constructs and sends a request for the given flow to stop. It
should escalate the request if necessary.*/
func sendRequest(req filter.Request) {
	attackerRouter := req.Flow.Path[0]
	log.Println("Contacting", attackerRouter.Address, "to deal with this nonsense.")

	/*Contact the router closest to the attacker with the filter request.*/
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:54321", attackerRouter.Address))
	if err != nil {
		log.Println(err)
		return
	}

	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		log.Println(err)
		return
	}

	var b bytes.Buffer
	req.WriteTo(&b)
	b.WriteTo(udpConn)

	log.Println("Okay, nonsense dealt with.")
}
