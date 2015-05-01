package filter

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/ThomasJClark/cs4404project/aitf"
	"github.com/ThomasJClark/cs4404project/aitf/routerecord"
)

/*
MessageType specifies which of the five messages involved in the filter
request process this is.
*/
type MessageType uint8

const (
	/*FilterReq is sent by a "victim" host to the nearest router to initiate a
	filter request, and later to an "attacker" host.*/
	FilterReq MessageType = iota

	/*CounterConnectionSyn is sent by the victim's router to another router to
	request a filter*/
	CounterConnectionSyn

	/*CounterConnectionSynAck is sent by the other router to the victim's router
	to acknowledge a filter request*/
	CounterConnectionSynAck

	/*CounterConnectionAck is sent by the vicitm's router to the other router to
	confirm the origin of the filter request.*/
	CounterConnectionAck

	/*FilterAck is sent by an "Attacker" host to a nearby gateway router to
	signify the host's compliance with a filter request.*/
	FilterAck
)

func (t MessageType) String() string {
	switch t {
	case FilterReq:
		return "Filter Request"
	case CounterConnectionSyn:
		return "Counter-connection SYN"
	case CounterConnectionSynAck:
		return "Counter-connection SYN+ACK"
	case CounterConnectionAck:
		return "Counter-connection ACK"
	case FilterAck:
		return "Filter acknowledgement"
	}

	return "Unrecognized"
}

/*Request contains the information passed around by a victim, routers,
and an attacker during the process of a filter request.*/
type Request struct {
	Type  MessageType
	SrcIP net.IP /*The alleged attacker*/
	DstIP net.IP /*The alleged victim*/
	Nonce uint64 /*Used in the three-way handshake between routers*/
	Flow  routerecord.RouteRecord
}

/*Authentic checks if a filter request was made by a host that legitimately
received traffice through this router.

This is verified by checking each router in the path until a matching one with
an authentic nonce is found.  If no such router can be found in the path, the
filter request is assumed to be mmalicious.*/
func (req *Request) Authentic() bool {
	for _, router := range req.Flow.Path {
		if router.Authentic(req.DstIP) {
			return true
		}
	}

	return false
}

/*
WriteTo writes a filter request in its binary format into w
*/
func (req *Request) WriteTo(w io.Writer) (n int64, err error) {
	binary.Write(w, binary.BigEndian, req.Type)
	binary.Write(w, binary.BigEndian, req.SrcIP.To4())
	binary.Write(w, binary.BigEndian, req.DstIP.To4())
	binary.Write(w, binary.BigEndian, req.Nonce)
	req.Flow.WriteTo(w)

	return 0, nil
}

/*
ReadFrom reads a filter request from its binary encoding in r
*/
func (req *Request) ReadFrom(r io.Reader) (n int64, err error) {
	n = 0

	if err = binary.Read(r, binary.BigEndian, &req.Type); err != nil {
		return
	}

	var addresses [8]byte
	if err = binary.Read(r, binary.BigEndian, &addresses); err != nil {
		return
	}

	req.SrcIP = net.IP(addresses[:4])
	req.DstIP = net.IP(addresses[4:])

	if err = binary.Read(r, binary.BigEndian, &req.Nonce); err != nil {
		return
	}

	return req.Flow.ReadFrom(r)
}

/*
Send sends the given filter.Request over UDP port 54321 to the given
IP address.
*/
func (req Request) Send(to net.IP) error {
	log.Println("Sending", req.Type, "to", aitf.Hostname(to))

	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:54321", to))
	if err != nil {
		return err
	}

	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return err
	}

	var b bytes.Buffer
	req.WriteTo(&b)
	b.WriteTo(udpConn)
	return nil
}
