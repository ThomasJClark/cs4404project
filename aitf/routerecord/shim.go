package routerecord

import (
	"bytes"

	"code.google.com/p/gopacket"
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
IPv4 packet, creating a new route record if it's not already present.*/
func Shim(ipLayer *layers.IPv4, r Router) {
	ipPayload := bytes.NewBuffer(ipLayer.LayerPayload())
	var modifiedIPPayload bytes.Buffer

	var rr RouteRecord

	if Shimmed(ipLayer) {
		rr.ReadFrom(ipPayload)
		ipLayer.Length -= uint16(rr.Len())
	} else {
		rr.Protocol = uint8(ipLayer.Protocol)
	}

	/*Add the specified router to the route record and put the record at the
	beginning of the payload.*/
	rr.AddRouter(r)
	rr.WriteTo(&modifiedIPPayload)
	ipPayload.WriteTo(&modifiedIPPayload)

	ipLayer.Length += uint16(rr.Len())
	ipLayer.Protocol = layers.IPProtocol(IPProtocolAITFRouteRecord)
	ipLayer.Checksum = 0
	ipLayer.Payload = modifiedIPPayload.Bytes()
}

/*Unshim removes the shim layer from an IPv4 packet, if it's present.*/
func Unshim(ipLayer *layers.IPv4) *RouteRecord {
	if Shimmed(ipLayer) {
		/*Remove the route record from the payload*/
		ipPayload := bytes.NewBuffer(ipLayer.LayerPayload())
		var rr RouteRecord
		rr.ReadFrom(ipPayload)

		ipLayer.Length -= uint16(rr.Len())
		ipLayer.Protocol = layers.IPProtocol(rr.Protocol)
		ipLayer.Checksum = 0
		ipLayer.Payload = ipPayload.Bytes()

		return &rr
	}

	return nil
}

/*Serialize helps to serialize an IPv4 packet that has been tampered with.
The IP checksum is recomputed, and the whole packet is concatenated together
into a byte slice that can be passed to netfilter.*/
func Serialize(ipLayer *layers.IPv4) ([]byte, error) {
	/*Write the IPv4 header into a gopacket buffer*/
	buf := gopacket.NewSerializeBuffer()
	err := ipLayer.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: false, ComputeChecksums: true})
	if err != nil {
		return nil, err
	}

	/*Write the gopacket buffer and the payload into a byte buffer, concatenating
	the entire packet together.*/
	var buf2 bytes.Buffer
	buf2.Write(buf.Bytes())
	buf2.Write(ipLayer.Payload)

	return buf2.Bytes(), nil
}
