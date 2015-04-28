package aitf

import (
	"encoding/binary"
	"io"
	"net"
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

/*FilterRequest contains the information passed around by a victim, routers,
and an attacker during the process of a filter request.*/
type FilterRequest struct {
	Type   MessageType
	Source net.IP /*The alleged attacker*/
	Dest   net.IP /*The alleged victim*/
	Flow   RouteRecord
}

/*Authentic checks if a filter request was made by a host that legitimately
received traffice through this router.

This is verified by checking each router in the path until a matching one with
an authentic nonce is found.  If no such router can be found in the path, the
filter request is assumed to be mmalicious.*/
func (req *FilterRequest) Authentic() bool {
	for _, router := range req.Flow.Path {
		if router.Authentic(req.Dest) {
			return true
		}
	}

	return false
}

/*
WriteTo writes a filter request in its binary format into w
*/
func (req *FilterRequest) WriteTo(w io.Writer) (n int64, err error) {
	binary.Write(w, binary.BigEndian, req.Type)
	binary.Write(w, binary.BigEndian, req.Source.To4())
	binary.Write(w, binary.BigEndian, req.Dest.To4())
	req.Flow.WriteTo(w)

	return 0, nil
}

/*
ReadFrom reads a filter request from its binary encoding in r
*/
func (req *FilterRequest) ReadFrom(r io.Reader) (n int64, err error) {
	n = 0

	if err = binary.Read(r, binary.BigEndian, &req.Type); err != nil {
		return
	}

	var addresses [8]byte
	if err = binary.Read(r, binary.BigEndian, &addresses); err != nil {
		return
	}

	req.Source = net.IP(addresses[:4])
	req.Dest = net.IP(addresses[4:])

	return req.Flow.ReadFrom(r)
}

/*
ReadCounterConnection checks weather a filter request is part of a
counter-connection handshake, and reads and returns a full CounterConnection
struct if it is.

Otherwise, ReadCounterConnection returns nil.
*/
func (req *FilterRequest) ReadCounterConnection(r io.Reader) *CounterConnection {
	switch req.Type {
	case CounterConnectionSyn, CounterConnectionSynAck, CounterConnectionAck:
		cc := new(CounterConnection)
		cc.Req = *req
		binary.Read(r, binary.BigEndian, cc.Nonce)
		return cc
	default:
		return nil
	}
}

/*A CounterConnection contains an entire filter request as well as a nonce.
This is used in part of a three-way handshake between two routers to confirm
the address of the router forwarding a filter request.*/
type CounterConnection struct {
	Req   FilterRequest
	Nonce uint64
}

/*
WriteTo writes a CounterConnection message in its raw binary format to w.  This
is the same as writing a filter request, but with a message type indicating
that it is a counter-connection, and an additional nonce at the end.
*/
func (cc *CounterConnection) WriteTo(w io.Writer) (n int64, err error) {
	cc.Req.WriteTo(w)
	binary.Write(w, binary.BigEndian, cc.Nonce)

	return 0, nil
}
