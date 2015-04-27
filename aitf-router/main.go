package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"net"

	"github.com/ThomasJClark/cs4404project/aitf"
)

func main() {
	rr := aitf.NewRouteRecord()
	rr.Protocol = 0x06
	rr.AddRouter(aitf.NewRouter(net.IPv4(1, 2, 3, 4), net.IPv4(8, 8, 8, 8)))
	rr.AddRouter(aitf.NewRouter(net.IPv4(5, 6, 7, 8), net.IPv4(8, 8, 8, 8)))
	rr.AddRouter(aitf.NewRouter(net.IPv4(9, 10, 11, 12), net.IPv4(8, 8, 8, 8)))

	for _, router := range rr.Path {
		fmt.Println(router)
		fmt.Println(router.Authentic(net.IPv4(8, 8, 8, 8)))
		fmt.Println(router.Authentic(net.IPv4(9, 9, 9, 9)))
	}

	b := new(bytes.Buffer)
	_, err := rr.WriteTo(b)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("bytes =", b.Bytes())
	fmt.Println(hex.EncodeToString(b.Bytes()))
}
