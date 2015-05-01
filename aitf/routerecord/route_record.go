package routerecord

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"net"
)

var (
	key     = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	macFunc = hmac.New(sha1.New, key)
)

/*64-bit nonce calculated using a keyed hash function with the current key*/
func nonce(data []byte) [8]byte {
	const Size = 8

	// Get the last 8 bytes of the the HMAC-SHA1 of the data
	macFunc.Reset()
	macFunc.Write(data)
	sum := macFunc.Sum([]byte{})[macFunc.Size()-Size : macFunc.Size()]

	var sumArray [Size]byte
	copy(sumArray[:], sum)

	return sumArray
}

/*
Router stores the record of a single router that forwarded a packet.
The address of the router is stored, as well as a nonce that is used by the
router to verify that the record is genuine.
*/
type Router struct {
	IP    net.IP
	Nonce [8]byte
}

/*
NewRouter creates and returns a new aitf.Router with a properly calculated
nonce.  The nonce is determined from the destination address of the packet.

routerIP must by an IPv4 address.
*/
func NewRouter(routerIP net.IP, destinationIP net.IP) Router {
	return Router{IP: routerIP, Nonce: nonce(destinationIP)}
}

/*
Authentic checks if the given router record is an authentic record generated
from this router.  This is accomplished by checking the keyed hash.

destinationIP is the address of the packet is the address of packet that
sent this route record.  This function is used to verify that this router
actually forwarded a packet to that address.
*/
func (router *Router) Authentic(destinationIP net.IP) bool {
	expectedNonce := nonce(destinationIP)
	return hmac.Equal(router.Nonce[:], expectedNonce[:])
}

/*
RouteRecord contains a list of all of the routers that have forwarded a packet
along a path, as well as the protocol number of the packet.  The protocol
number is stored because packets with route records are identified by a special
protocol number that replaces the original one.
*/
type RouteRecord struct {
	Protocol uint8
	Path     []Router
}

/*
NewRouteRecord creates and returns a new, empty aitf.RouteRecord
*/
func NewRouteRecord() RouteRecord {
	return RouteRecord{Protocol: 0, Path: []Router{}}
}

/*
AddRouter adds a new entry to a RouterRecord's path
*/
func (record *RouteRecord) AddRouter(router Router) {
	record.Path = append(record.Path, router)
}

/*
Authentic checks if the given route record is an authentic record of the path
of a packet that was transmitted by the calling router.  In other words, at
least one router along the path in the route record must have a valid nonce.

destinationIP is the address of the packet is the address of packet that
sent this route record.  This function is used to verify that this router
actually forwarded a packet to that address.
*/
func (record *RouteRecord) Authentic(destinationIP net.IP) bool {
	for _, router := range record.Path {
		if router.Authentic(destinationIP) {
			return true
		}
	}

	return false
}

/*
Len returns the number of bytes on the wire that the route record takes up,
without actually writing it to anything. This is used for adjusting the length
of an IP payload.
*/
func (record *RouteRecord) Len() int {
	//The protocol number and path length take up one byte each, and each router
	//takes up 12 bytes (4 byte IPv4 address plus an 8 byte nonce).
	return 2 + 12*len(record.Path)
}

/*
WriteTo writes the entire route record in its raw binary header format into w
*/
func (record *RouteRecord) WriteTo(w io.Writer) (n int64, err error) {
	binary.Write(w, binary.BigEndian, record.Protocol)
	binary.Write(w, binary.BigEndian, uint8(len(record.Path)))
	for _, router := range record.Path {
		binary.Write(w, binary.BigEndian, router.IP.To4())
		binary.Write(w, binary.BigEndian, router.Nonce)
	}
	return 0, nil
}

/*
ReadFrom reads a round record from a stream of bytes provided by r
*/
func (record *RouteRecord) ReadFrom(r io.Reader) (n int64, err error) {
	n = 0

	// The first byte in the RR header is the protocol number
	if err = binary.Read(r, binary.BigEndian, &record.Protocol); err != nil {
		return
	}

	// Read the next byte, which is the number of routers in the path, then read
	// in that many routers.
	var pathLen uint8
	if err = binary.Read(r, binary.BigEndian, &pathLen); err != nil {
		return
	}

	record.Path = make([]Router, pathLen)
	for i := range record.Path {
		var routerIP [4]byte
		if err = binary.Read(r, binary.BigEndian, &routerIP); err != nil {
			return
		}

		record.Path[i].IP = net.IP(routerIP[:])

		if err = binary.Read(r, binary.BigEndian, &record.Path[i].Nonce); err != nil {
			return
		}
	}

	return
}
