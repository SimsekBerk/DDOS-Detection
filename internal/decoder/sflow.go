package decoder

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/SimsekBerk/DDOS-Detection/internal/flow"
)

// sFlow v5 (https://sflow.org/sflow_version_5.txt)
const (
	sflowFlowSample            = 1
	sflowCounterSample         = 2
	sflowFlowSampleExpanded    = 3
	sflowCounterSampleExpanded = 4

	sflowRecRawHeader   = 1
	sflowRecSampledIPv4 = 3
	sflowRecSampledIPv6 = 4
	sflowRecExtGateway  = 1003

	sflowHeaderEthernet = 1
	sflowHeaderIPv4     = 11
	sflowHeaderIPv6     = 12
)

type xdr struct {
	b   []byte
	err error
}

func (x *xdr) u32() uint32 {
	if x.err != nil {
		return 0
	}
	if len(x.b) < 4 {
		x.err = ErrShort
		return 0
	}
	v := binary.BigEndian.Uint32(x.b[0:4])
	x.b = x.b[4:]
	return v
}

func (x *xdr) bytes(n int) []byte {
	if x.err != nil {
		return nil
	}
	if n < 0 || len(x.b) < n {
		x.err = ErrShort
		return nil
	}
	v := x.b[:n]
	x.b = x.b[n:]
	return v
}

// opaque reads XDR opaque data padded to 4 bytes.
func (x *xdr) opaque(n int) []byte {
	v := x.bytes(n)
	if pad := (4 - n%4) % 4; pad > 0 {
		x.bytes(pad)
	}
	return v
}

func (x *xdr) addr() netip.Addr {
	switch x.u32() {
	case 1:
		return addrFrom(x.bytes(4))
	case 2:
		return addrFrom(x.bytes(16))
	}
	return netip.Addr{}
}

func decodeSFlow(exporter netip.Addr, data []byte, now int64) (Result, error) {
	x := &xdr{b: data}
	if v := x.u32(); v != 5 {
		return Result{}, fmt.Errorf("%w: sflow version %d", ErrUnsupported, v)
	}
	x.addr() // agent address (we key exporters on the UDP source)
	subAgent := x.u32()
	seq := x.u32()
	x.u32() // uptime
	n := int(x.u32())
	if x.err != nil {
		return Result{}, x.err
	}
	res := Result{Source: flow.SourceSFlow, SeqKey: uint64(subAgent), Seq: seq, SeqNext: seq + 1}

	for i := 0; i < n && x.err == nil; i++ {
		format := x.u32()
		length := int(x.u32())
		body := x.opaque(length)
		if x.err != nil {
			break
		}
		if format>>12 != 0 { // enterprise-specific sample
			continue
		}
		switch format & 0xFFF {
		case sflowFlowSample, sflowFlowSampleExpanded:
			decodeSFlowFlowSample(&res, exporter, body, format&0xFFF == sflowFlowSampleExpanded, now)
		case sflowCounterSample, sflowCounterSampleExpanded:
			res.OptionRecords++
		}
	}
	return res, nil
}

func decodeSFlowFlowSample(res *Result, exporter netip.Addr, body []byte, expanded bool, now int64) {
	x := &xdr{b: body}
	x.u32() // sequence
	var inIf, outIf uint32
	if expanded {
		x.u32() // source id type
		x.u32() // source id index
	} else {
		x.u32() // source id
	}
	rate := x.u32()
	x.u32() // sample pool
	x.u32() // drops
	if expanded {
		x.u32()
		inIf = x.u32()
		x.u32()
		outIf = x.u32()
	} else {
		inIf = x.u32() & 0x3FFFFFFF
		outIf = x.u32() & 0x3FFFFFFF
	}
	n := int(x.u32())
	if x.err != nil {
		return
	}

	r := flow.Record{
		ReceivedUnix: now,
		Exporter:     exporter,
		Source:       flow.SourceSFlow,
		SamplingRate: rate,
		InIf:         inIf,
		OutIf:        outIf,
		Packets:      1,
	}
	have := false
	for i := 0; i < n && x.err == nil; i++ {
		format := x.u32()
		length := int(x.u32())
		rec := x.opaque(length)
		if x.err != nil || format>>12 != 0 {
			continue
		}
		rx := &xdr{b: rec}
		switch format & 0xFFF {
		case sflowRecRawHeader:
			proto := rx.u32()
			frameLen := rx.u32()
			rx.u32() // stripped
			hlen := int(rx.u32())
			hdr := rx.bytes(hlen)
			if rx.err != nil {
				continue
			}
			r.Bytes = uint64(frameLen)
			if parsePacket(&r, proto, hdr) {
				have = true
			}
		case sflowRecSampledIPv4:
			r.Bytes = uint64(rx.u32())
			r.Protocol = uint8(rx.u32())
			r.Src = addrFrom(rx.bytes(4))
			r.Dst = addrFrom(rx.bytes(4))
			r.SrcPort = uint16(rx.u32())
			r.DstPort = uint16(rx.u32())
			r.TCPFlags = uint8(rx.u32())
			r.TOS = uint8(rx.u32())
			have = rx.err == nil
		case sflowRecSampledIPv6:
			r.Bytes = uint64(rx.u32())
			r.Protocol = uint8(rx.u32())
			r.Src = addrFrom(rx.bytes(16))
			r.Dst = addrFrom(rx.bytes(16))
			r.SrcPort = uint16(rx.u32())
			r.DstPort = uint16(rx.u32())
			r.TCPFlags = uint8(rx.u32())
			rx.u32() // priority
			have = rx.err == nil
		case sflowRecExtGateway:
			rx.addr() // next hop
			rx.u32()  // router AS
			r.SrcAS = rx.u32()
		}
	}
	if have && r.Src.IsValid() && r.Dst.IsValid() {
		res.Records = append(res.Records, r)
	}
}

// ParseEthernet decodes a captured Ethernet frame (VLAN/MPLS/IPv4/IPv6 and
// the L4 header) into r. Packets and Bytes are left to the caller.
func ParseEthernet(r *flow.Record, frame []byte) bool {
	return parsePacket(r, sflowHeaderEthernet, frame)
}

// parsePacket decodes Ethernet/VLAN/MPLS/IPv4/IPv6 + L4 headers into r.
func parsePacket(r *flow.Record, proto uint32, b []byte) bool {
	var etype uint16
	switch proto {
	case sflowHeaderEthernet:
		if len(b) < 14 {
			return false
		}
		etype = binary.BigEndian.Uint16(b[12:14])
		b = b[14:]
		for etype == 0x8100 || etype == 0x88A8 || etype == 0x9100 {
			if len(b) < 4 {
				return false
			}
			etype = binary.BigEndian.Uint16(b[2:4])
			b = b[4:]
		}
		if etype == 0x8847 || etype == 0x8848 { // MPLS: skip labels until bottom of stack
			for {
				if len(b) < 4 {
					return false
				}
				bos := b[2]&0x01 != 0
				b = b[4:]
				if bos {
					break
				}
			}
			if len(b) < 1 {
				return false
			}
			switch b[0] >> 4 {
			case 4:
				etype = 0x0800
			case 6:
				etype = 0x86DD
			default:
				return false
			}
		}
	case sflowHeaderIPv4:
		etype = 0x0800
	case sflowHeaderIPv6:
		etype = 0x86DD
	default:
		return false
	}

	var l4 []byte
	switch etype {
	case 0x0800:
		if len(b) < 20 {
			return false
		}
		ihl := int(b[0]&0x0F) * 4
		if ihl < 20 || len(b) < ihl {
			return false
		}
		r.TOS = b[1]
		flagsFrag := binary.BigEndian.Uint16(b[6:8])
		mf := flagsFrag&0x2000 != 0
		offset := flagsFrag & 0x1FFF
		r.Protocol = b[9]
		r.Src = netip.AddrFrom4([4]byte(b[12:16]))
		r.Dst = netip.AddrFrom4([4]byte(b[16:20]))
		if mf || offset != 0 {
			r.Fragment = true
		}
		if offset != 0 {
			return true // no L4 header in non-initial fragments
		}
		l4 = b[ihl:]
	case 0x86DD:
		if len(b) < 40 {
			return false
		}
		r.TOS = uint8(binary.BigEndian.Uint16(b[0:2]) >> 4)
		next := b[6]
		r.Src = netip.AddrFrom16([16]byte(b[8:24]))
		r.Dst = netip.AddrFrom16([16]byte(b[24:40]))
		b = b[40:]
		for i := 0; i < 8; i++ { // walk extension headers
			switch next {
			case 0, 43, 60: // hop-by-hop, routing, destination options
				if len(b) < 2 {
					r.Protocol = next
					return true
				}
				l := (int(b[1]) + 1) * 8
				next = b[0]
				if len(b) < l {
					r.Protocol = next
					return true
				}
				b = b[l:]
				continue
			case 44: // fragment
				if len(b) < 8 {
					r.Protocol = next
					return true
				}
				r.Fragment = true
				offset := binary.BigEndian.Uint16(b[2:4]) >> 3
				next = b[0]
				b = b[8:]
				if offset != 0 {
					r.Protocol = next
					return true
				}
				continue
			}
			break
		}
		r.Protocol = next
		l4 = b
	default:
		return false
	}

	switch r.Protocol {
	case flow.ProtoTCP:
		if len(l4) >= 14 {
			r.SrcPort = binary.BigEndian.Uint16(l4[0:2])
			r.DstPort = binary.BigEndian.Uint16(l4[2:4])
			r.TCPFlags = l4[13]
		}
	case flow.ProtoUDP, flow.ProtoSCTP:
		if len(l4) >= 4 {
			r.SrcPort = binary.BigEndian.Uint16(l4[0:2])
			r.DstPort = binary.BigEndian.Uint16(l4[2:4])
		}
	case flow.ProtoICMP, flow.ProtoICMPv6:
		if len(l4) >= 2 {
			r.ICMPType, r.ICMPCode = l4[0], l4[1]
		}
	}
	return true
}
