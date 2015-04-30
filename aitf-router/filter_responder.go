package main

import (
	"bytes"
	"log"
	"net"
	"time"

	"github.com/ThomasJClark/cs4404project/aitf/filter"
)

const ()

/*
listenForRequest waits for a filter request from a client to come.  Then, if
verifies the authenticity of the request and takes the appropriate action based
on the AITF filter request protocol.
*/
func listenForRequest() {
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
		log.Println("Listening for filter request...")
		n, _, _ := serverConn.ReadFromUDP(buf)
		log.Println(buf[:n])

		/*Read a filter request from the UDP connection*/
		var req filter.Request
		_, err := req.ReadFrom(bytes.NewBuffer(buf[:n]))
		if err != nil {
			log.Println(err)
			continue
		}

		/*If the request can be verified as authentic through the nonce value in it,
		install the requested filter.*/
		if req.Authentic() {
			log.Println("Received an authentic request!")
			log.Println(req)
			filter.InstallFilter(req, time.Second*5)
		} else {
			log.Println("Received a forged request!")
		}
	}
}
