package main

import (
	"bytes"
	"fmt"
	"log"
	"net"

	"github.com/ThomasJClark/cs4404project/aitf"
)

func main() {
	// Sample route record
	rr := aitf.NewRouteRecord()
	rr.Protocol = 0x06
	rr.AddRouter(aitf.NewRouter(net.IPv4(1, 2, 3, 4), net.IPv4(8, 8, 8, 8)))
	rr.AddRouter(aitf.NewRouter(net.IPv4(5, 6, 7, 8), net.IPv4(8, 8, 8, 8)))
	rr.AddRouter(aitf.NewRouter(net.IPv4(9, 10, 11, 12), net.IPv4(8, 8, 8, 8)))

	// Print the route record, encode it, decode it, then print the decoded one
	fmt.Println("rr =", rr)

	b := new(bytes.Buffer)
	if _, err := rr.WriteTo(b); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("bytes = % x\n", b.Bytes())

	rr2 := aitf.NewRouteRecord()
	if _, err := rr2.ReadFrom(b); err != nil {
		log.Fatal(err)
	}

	fmt.Println("rr2 =", rr2)
}
