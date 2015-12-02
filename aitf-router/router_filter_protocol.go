package main

import (
	"bytes"
	"log"
	"math/rand"
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

var handshakes map[uint64](*filter.Request)
var shadowFilters []filter.Request

/*
listenForFilterRequest waits for a filter request from a client to come.  Then,
it verifies the authenticity of the request and takes the appropriate action
based on the AITF filter request protocol.
*/
func listenForFilterRequest(mode complianceMode) {
	if handshakes == nil {
		handshakes = make(map[uint64](*filter.Request))
	}

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

		/*Throw the request away if it is not authentic.*/
		if !req.Authentic() {
			log.Println("Received a forged filter request!")
			continue
		}

		log.Println("Got", req.Type, "from", aitf.Hostname(addr.IP))

		switch req.Type {
		case filter.FilterReq:
			/*When we receive a filter request, install a temporary filter and begin
			a counter-connection with the attacker's router. Also let the victim know
			that the attack should have stopped with a filter ACK. The filter is
			installed for the full filter time instead of the temporary time, but is
			automatically removed when we get a filter ACK.*/
			filter.InstallFilter(req, filter.LongFilterTime, true)
			req.Type = filter.FilterAck
			req.Send(addr.IP)

			/*If we've blocked this filter before and it's still happening, escalate
			the filter and just block it here.*/
			for _, req2 := range shadowFilters {
				if req2.SrcIP.Equal(req.SrcIP) && req2.DstIP.Equal(req.DstIP) {
					log.Println("Escalating request.")
					return
				}
			}

			req.Type = filter.CounterConnectionSyn
			req.Send(req.Flow.Path[0].IP)

		case filter.CounterConnectionSyn:
			if mode == comply || mode == lie {
				/*When we get a counter-connection SYN, continue the three-way handshake
				with a SYN-ACK. We don't install a filter until we get an ACK back with
				the right nonce.*/
				req.Type = filter.CounterConnectionSynAck
				req.Nonce = uint64(rand.Int63())
				handshakes[req.Nonce] = &req
				req.Send(addr.IP)
			}

		case filter.CounterConnectionSynAck:
			if mode == comply || mode == lie {
				/*When we receive a response to a counter-connection, complete the
				three-way handshake.*/
				req.Type = filter.CounterConnectionAck
				req.Send(addr.IP)
			}

		case filter.CounterConnectionAck:
			if mode == comply || mode == lie {
				/*When we receive a counter-connection ACK, make sure we're actually
				waiting for a response to that handshake, then install a temporary
				filter.*/
				originalReq := handshakes[req.Nonce]
				if originalReq == nil {
					log.Println("Received a forged three-way handshake:", req)
					continue
				} else {
					delete(handshakes, req.Nonce)
				}
			}

			if mode == comply {
				/*The filter is installed for the full filter time instead of the
				temporary time, but is automatically removed when we get a filter ACK.*/
				filter.InstallFilter(req, filter.LongFilterTime, true)

				/*The attacker should be informed of its wrongdoing, and the victim's
				router should be informed that this router is complying with the
				request.*/
				req.Type = filter.FilterReq
				req.Send(req.SrcIP)
				req.Type = filter.FilterAck
				req.Send(addr.IP)
			}

		case filter.FilterAck:
			if mode == comply {
				/*When we get acknowledgement of compliance with a filter, we can remove
				our temporary filter. Nobody lies on the internet.*/
				filter.UninstallFilter(req, true)

				shadowFilters = append(shadowFilters, req)
			}
		}
	}
}
