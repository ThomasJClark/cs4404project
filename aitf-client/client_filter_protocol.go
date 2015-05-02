package main

import (
	"bytes"
	"log"
	"net"

	"github.com/ThomasJClark/cs4404project/aitf"
	"github.com/ThomasJClark/cs4404project/aitf/filter"
)

type complianceMode int

const (
	comply complianceMode = iota
	ignore
	lie
)

/*
listenForFilterRequest waits for a filter request from a router to come.  Then,
it verifies the authenticity of the request and takes some action.

If action is comply, it filters the attack.

If action is ignore, it logs the request but does nothing about it.comply

If action is lie, it complies with the request but doesn't actually add a filter.
*/
func listenForFilterRequest(mode complianceMode) {
	/*Open up a UDP server on the filter request port and handle any messages
	that arrive.*/
	serverAddr, err := net.ResolveUDPAddr("udp", ":54321")
	if err != nil {
		log.Fatal(err)
	}

	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		log.Fatal(err)
	}

	defer serverConn.Close()

	buf := make([]byte, 5000)
	for {
		n, addr, _ := serverConn.ReadFromUDP(buf)

		/*Read a request from the UDP connection*/
		var req filter.Request
		_, err := req.ReadFrom(bytes.NewBuffer(buf[:n]))
		if err != nil {
			log.Println(err)
			continue
		}

		log.Println("Got", req.Type, "from", aitf.Hostname(addr.IP))
		if req.Type == filter.FilterReq {
			switch mode {
			case comply:
				log.Println("Complying with filter request...")

				/*If this host is okay with filter requests, add a firewall rule to
				block the requested flow and respond with an acknowledgement.*/
				filter.InstallFilter(req, filter.LongFilterTime, false)
				req.Type = filter.FilterAck
				req.Send(addr.IP)

			case ignore:
				log.Println("Ignoring filter request...")

			case lie:
				log.Println("Pretending to comply with filter request...")

				/*If this host is a lier, send an acknowledgement without actually
				installing a filter rule.*/
				req.Type = filter.FilterAck
				req.Send(addr.IP)
			}
		} else {
			/*Hosts shouldn't get any of the other message types.*/
			log.Println("Unexpected filter request:", req)
		}
	}
}
