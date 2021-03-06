/*
   Copyright 2014 Krishna Raman <kraman@gmail.com>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

/*
Go bindings for libnetfilter_queue

This library provides access to packets in the IPTables netfilter queue (NFQUEUE).
The libnetfilter_queue library is part of the http://netfilter.org/projects/libnetfilter_queue/ project.
*/
package netfilter

/*
#cgo pkg-config: libnetfilter_queue
#cgo CFLAGS: -Wall -Werror -I/usr/include
#cgo LDFLAGS: -L/usr/lib64/

#include "netfilter.h"
*/
import "C"

import (
	"fmt"
	"unsafe"

	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
)

type NFPacket struct {
	Packet        gopacket.Packet
	resultChannel chan C.struct_NFResult
}

//Set the verdict for the packet
func (p *NFPacket) SetVerdict(v Verdict) {
	p.SetResult(v, nil)
}

//Set both the verdict for the packet and a data buffer containing the packet
//data
func (p *NFPacket) SetResult(v Verdict, data []byte) {
	if data == nil {
		p.resultChannel <- C.struct_NFResult{Verdict: C.uint(v), Data: nil, Len: 0}
	} else {
		p.resultChannel <- C.struct_NFResult{Verdict: C.uint(v), Data: (*C.uint8_t)(&data[0]), Len: (C.int)(len(data))}
	}
}

type NFQueue struct {
	h       *C.struct_nfq_handle
	qh      *C.struct_nfq_q_handle
	fd      C.int
	packets chan NFPacket
}

//Verdict for a packet
type Verdict C.uint32_t

const (
	AF_INET = 2

	NF_DROP   Verdict = 0
	NF_ACCEPT Verdict = 1
	NF_STOLEN Verdict = 2
	NF_QUEUE  Verdict = 3
	NF_REPEAT Verdict = 4
	NF_STOP   Verdict = 5

	NF_DEFAULT_PACKET_SIZE uint32 = 0xffff
)

//Create and bind to queue specified by queueId
func NewNFQueue(queueId uint16, maxPacketsInQueue uint32, packetSize uint32) (*NFQueue, error) {
	var nfq = NFQueue{}
	var err error
	var ret C.int

	if nfq.h, err = C.nfq_open(); err != nil {
		return nil, fmt.Errorf("Error opening NFQueue handle: %v\n", err)
	}

	if ret, err = C.nfq_unbind_pf(nfq.h, AF_INET); err != nil || ret < 0 {
		return nil, fmt.Errorf("Error unbinding existing NFQ handler from AF_INET protocol family: %v\n", err)
	}

	if ret, err := C.nfq_bind_pf(nfq.h, AF_INET); err != nil || ret < 0 {
		return nil, fmt.Errorf("Error binding to AF_INET protocol family: %v\n", err)
	}

	nfq.packets = make(chan NFPacket)
	if nfq.qh, err = C.CreateQueue(nfq.h, C.u_int16_t(queueId), unsafe.Pointer(&nfq.packets)); err != nil || nfq.qh == nil {
		C.nfq_close(nfq.h)
		return nil, fmt.Errorf("Error binding to queue: %v\n", err)
	}

	if ret, err = C.nfq_set_queue_maxlen(nfq.qh, C.u_int32_t(maxPacketsInQueue)); err != nil || ret < 0 {
		C.nfq_destroy_queue(nfq.qh)
		C.nfq_close(nfq.h)
		return nil, fmt.Errorf("Unable to set max packets in queue: %v\n", err)
	}

	if C.nfq_set_mode(nfq.qh, C.u_int8_t(2), C.uint(packetSize)) < 0 {
		C.nfq_destroy_queue(nfq.qh)
		C.nfq_close(nfq.h)
		return nil, fmt.Errorf("Unable to set packets copy mode: %v\n", err)
	}

	if nfq.fd, err = C.nfq_fd(nfq.h); err != nil {
		C.nfq_destroy_queue(nfq.qh)
		C.nfq_close(nfq.h)
		return nil, fmt.Errorf("Unable to get queue file-descriptor. %v", err)
	}

	go nfq.run()

	return &nfq, nil
}

//Unbind and close the queue
func (nfq *NFQueue) Close() {
	C.nfq_destroy_queue(nfq.qh)
	C.nfq_close(nfq.h)
}

//Get the channel for packets
func (nfq *NFQueue) GetPackets() <-chan NFPacket {
	return nfq.packets
}

func (nfq *NFQueue) run() {
	C.Run(nfq.h, nfq.fd)
}

//export go_callback
func go_callback(queueId C.int, data *C.uchar, len C.int, cb *chan NFPacket) C.struct_NFResult {
	xdata := C.GoBytes(unsafe.Pointer(data), len)
	packet := gopacket.NewPacket(xdata, layers.LayerTypeIPv4, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	p := NFPacket{resultChannel: make(chan C.struct_NFResult), Packet: packet}
	select {
	case (*cb) <- p:
		r := <-p.resultChannel
		return r
	default:
		return C.struct_NFResult{Verdict: C.uint(NF_DROP), Data: nil, Len: 0}
	}
}
