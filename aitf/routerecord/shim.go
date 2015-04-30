package routerecord

import (
	"bytes"

	"code.google.com/p/gopacket/layers"
)

/*IPProtocolAITFRouteRecord is an IPv4 protocol number that indicates the
presence of of a route record.*/
const IPProtocolAITFRouteRecord layers.IPProtocol = 253

/*Shimmed returns true if a given IP Layer already has a shim layer with a
route record in it.*/
func Shimmed(ipLayer *layers.IPv4) bool {
	return ipLayer.Protocol == IPProtocolAITFRouteRecord
}

/*Shim inserts the given router into the shim layer route record of the given
IPv4 packet, creating a new route record if it's not already present. The
resulting shimmed packet is returned as a byte slice.*/
func Shim(ipLayer *layers.IPv4, r Router) []byte {
	ipHeader := bytes.NewBuffer(ipLayer.LayerContents())
	ipPayload := bytes.NewBuffer(ipLayer.LayerPayload())

	var rr RouteRecord

	if Shimmed(ipLayer) {
		/*Read the existing route record from the packet, if there is one,
		and add the router to it.*/
		rr.ReadFrom(ipPayload)
	} else {
		/*Otherwise, create a new route record.*/
		rr.Protocol = uint8(ipLayer.Protocol)
	}

	/*Add the router to the route record and put the route record into a shim
	layer in the packet.*/
	rr.AddRouter(r)
	return enocdeShimmedPacket(ipHeader, ipPayload, rr)
}

/*Unshim removes the shim layer from an IPv4 packet, if it's present. Either
way, the resulting normal non-shimmed packet data is returned as a byte slice.*/
func Unshim(ipLayer *layers.IPv4) []byte {
	ipHeader := bytes.NewBuffer(ipLayer.LayerContents())
	ipPayload := bytes.NewBuffer(ipLayer.LayerPayload())

	/*If the packet has shim layer, read it into a temporary variable to remove
	it.*/
	if Shimmed(ipLayer) {
		var rr RouteRecord
		rr.ReadFrom(ipPayload)

		totalLength := ipHeader.Len() + ipPayload.Len()
		ipHeader.Bytes()[2] = byte(totalLength >> 8)
		ipHeader.Bytes()[3] = byte(totalLength & 0xff)
		ipHeader.Bytes()[9] = rr.Protocol
		ipHeader.Bytes()[10] = 0
		ipHeader.Bytes()[11] = 0
	}

	var b bytes.Buffer
	ipHeader.WriteTo(&b)
	ipPayload.WriteTo(&b)
	return b.Bytes()
}

func enocdeShimmedPacket(ipHeader, ipPayload *bytes.Buffer, rr RouteRecord) []byte {
	/*The total length field of the IP header must be updated to incorporate
	the new length of the route record, and we must make sure that the
	protocol number is set to indicate a route record. Because of these
	changes, the IP checksum must also be recomputed.*/
	totalLength := ipHeader.Len() + rr.Len() + ipPayload.Len()
	ipHeader.Bytes()[2] = byte(totalLength >> 8)
	ipHeader.Bytes()[3] = byte(totalLength & 0xff)
	ipHeader.Bytes()[9] = byte(IPProtocolAITFRouteRecord)
	ipHeader.Bytes()[10] = 0
	ipHeader.Bytes()[11] = 0

	/*Put the shim layer into the middle of the packet, right after the IP header.*/
	var b bytes.Buffer
	ipHeader.WriteTo(&b)
	rr.WriteTo(&b)
	ipPayload.WriteTo(&b)
	return b.Bytes()
}
