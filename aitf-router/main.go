package main

import (
	"bytes"
	"fmt"
	"net"

	"github.com/ThomasJClark/cs4404project/aitf"
)

var (
	victim   = net.ParseIP("8.8.8.8")
	attacker = net.ParseIP("9.9.9.9")
	router1  = net.ParseIP("1.2.3.4")
	router2  = net.ParseIP("5.6.7.8")
	router3  = net.ParseIP("9.10.11.12")
)

func main() {
	// Sample route record
	rr := aitf.NewRouteRecord()
	rr.Protocol = 0x06
	rr.AddRouter(aitf.NewRouter(router1, victim))
	rr.AddRouter(aitf.NewRouter(router2, victim))
	rr.AddRouter(aitf.NewRouter(router3, victim))

	// Print the route record, encode it, decode it, then print the decoded one
	fmt.Println("rr =", rr)

	b := new(bytes.Buffer)
	rr.WriteTo(b)

	fmt.Printf("bytes = % x\n", b.Bytes())

	rr2 := aitf.NewRouteRecord()
	rr2.ReadFrom(b)
	fmt.Println("rr2 =", rr2)

	fmt.Println("==========")

	// Now the same for FilterRequest
	req := aitf.FilterRequest{Type: aitf.FilterReq, Source: attacker, Dest: victim, Flow: rr}
	fmt.Println("req =", req)

	req.WriteTo(b)
	fmt.Printf("bytes = % x\n", b.Bytes())

	req2 := aitf.FilterRequest{}
	req2.ReadFrom(b)

	if cc := req2.ReadCounterConnection(b); cc != nil {
		fmt.Println("cc =", cc)
	} else {
		fmt.Println("req2 =", req2)
	}

	fmt.Println("==========")

	// And CounterConnection
	cc := aitf.CounterConnection{Req: req, Nonce: 0xc6f5bec12a9e668b}
	cc.Req.Type = aitf.CounterConnectionSyn
	fmt.Println("cc =", cc)

	cc.WriteTo(b)
	fmt.Printf("bytes = % x\n", b.Bytes())

	req3 := aitf.FilterRequest{}
	req3.ReadFrom(b)

	if cc := req3.ReadCounterConnection(b); cc != nil {
		fmt.Println("cc2 =", cc)
	} else {
		fmt.Println("req3 =", req3)
	}
}
