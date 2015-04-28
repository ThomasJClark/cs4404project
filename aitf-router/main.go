package main

import (
	"log"
	"net"
	"time"

	"github.com/ThomasJClark/cs4404project/aitf"
)

var (
	victim   = net.ParseIP("130.215.247.95")
	attacker = net.ParseIP("208.80.154.224")
	router1  = net.ParseIP("1.2.3.4")
	router2  = net.ParseIP("5.6.7.8")
	router3  = net.ParseIP("9.10.11.12")
)

func main() {
	rr := aitf.NewRouteRecord()
	rr.Protocol = 0x06
	rr.AddRouter(aitf.NewRouter(router1, victim))
	rr.AddRouter(aitf.NewRouter(router2, victim))
	rr.AddRouter(aitf.NewRouter(router3, victim))

	req := aitf.FilterRequest{Type: aitf.FilterReq, Source: attacker, Dest: victim, Flow: rr}

	err := aitf.InstallFilter(req, time.Second*2)
	if err != nil {
		log.Fatal(err)
	}

	time.Sleep(5 * time.Minute)
}
