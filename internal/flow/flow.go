// Package flow defines the normalized flow record shared by decoders, the
// detection engine and the flow store.
package flow

import (
	"fmt"
	"net/netip"
)

// Source identifies the telemetry protocol a record was decoded from.
type Source uint8

const (
	SourceUnknown Source = iota
	SourceNetFlow5
	SourceNetFlow9
	SourceIPFIX
	SourceSFlow
)

func (s Source) String() string {
	switch s {
	case SourceNetFlow5:
		return "netflow5"
	case SourceNetFlow9:
		return "netflow9"
	case SourceIPFIX:
		return "ipfix"
	case SourceSFlow:
		return "sflow"
	}
	return "unknown"
}

// Direction of a record relative to the protected address space.
type Direction uint8

const (
	DirOther    Direction = iota // neither side protected (transit)
	DirInbound                   // destination is protected
	DirOutbound                  // source is protected, destination is not
)

func (d Direction) String() string {
	switch d {
	case DirInbound:
		return "inbound"
	case DirOutbound:
		return "outbound"
	}
	return "other"
}

// IP protocol numbers used across the code base.
const (
	ProtoICMP   uint8 = 1
	ProtoIGMP   uint8 = 2
	ProtoIPIP   uint8 = 4
	ProtoTCP    uint8 = 6
	ProtoUDP    uint8 = 17
	ProtoGRE    uint8 = 47
	ProtoESP    uint8 = 50
	ProtoAH     uint8 = 51
	ProtoICMPv6 uint8 = 58
	ProtoSCTP   uint8 = 132
)

// TCP flag bits as carried in NetFlow/IPFIX tcpControlBits and the TCP header.
const (
	TCPFin uint8 = 0x01
	TCPSyn uint8 = 0x02
	TCPRst uint8 = 0x04
	TCPPsh uint8 = 0x08
	TCPAck uint8 = 0x10
	TCPUrg uint8 = 0x20
	TCPEce uint8 = 0x40
	TCPCwr uint8 = 0x80
)

// Record is a single normalized flow (or sFlow packet sample).
//
// Bytes and Packets are the values as exported (i.e. *sampled*); multiply by
// SamplingRate to estimate real traffic. DurationMs is 0 for packet samples.
type Record struct {
	ReceivedUnix int64 // collector receive time, unix seconds
	Exporter     netip.Addr
	Source       Source
	SamplingRate uint32

	Src, Dst         netip.Addr
	SrcPort, DstPort uint16
	Protocol         uint8
	TCPFlags         uint8
	TOS              uint8
	ICMPType         uint8
	ICMPCode         uint8
	Fragment         bool // non-initial fragment or MF set

	Bytes      uint64
	Packets    uint64
	DurationMs uint32

	InIf, OutIf  uint32
	SrcAS, DstAS uint32

	// Filled in by the engine during normalization.
	Direction Direction
	ObjectID  int32 // index of protected object, -1 if none
}

// ScaledBytes returns estimated real bytes (sampling applied).
func (r *Record) ScaledBytes() float64 { return float64(r.Bytes) * float64(r.rate()) }

// ScaledPackets returns estimated real packets (sampling applied).
func (r *Record) ScaledPackets() float64 { return float64(r.Packets) * float64(r.rate()) }

func (r *Record) rate() uint32 {
	if r.SamplingRate == 0 {
		return 1
	}
	return r.SamplingRate
}

// AvgPacketSize returns bytes/packets of the record (0 if no packets).
func (r *Record) AvgPacketSize() float64 {
	if r.Packets == 0 {
		return 0
	}
	return float64(r.Bytes) / float64(r.Packets)
}

// ProtoName returns a short protocol name.
func ProtoName(p uint8) string {
	switch p {
	case ProtoICMP:
		return "icmp"
	case ProtoIGMP:
		return "igmp"
	case ProtoIPIP:
		return "ipip"
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoGRE:
		return "gre"
	case ProtoESP:
		return "esp"
	case ProtoAH:
		return "ah"
	case ProtoICMPv6:
		return "icmpv6"
	case ProtoSCTP:
		return "sctp"
	}
	return fmt.Sprintf("ip-%d", p)
}

// ProtoNumber parses a protocol name (or number) used in rule files.
func ProtoNumber(s string) (uint8, bool) {
	switch s {
	case "icmp":
		return ProtoICMP, true
	case "igmp":
		return ProtoIGMP, true
	case "ipip":
		return ProtoIPIP, true
	case "tcp":
		return ProtoTCP, true
	case "udp":
		return ProtoUDP, true
	case "gre":
		return ProtoGRE, true
	case "esp":
		return ProtoESP, true
	case "ah":
		return ProtoAH, true
	case "icmpv6":
		return ProtoICMPv6, true
	case "sctp":
		return ProtoSCTP, true
	}
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err == nil && n >= 0 && n <= 255 {
		return uint8(n), true
	}
	return 0, false
}

// TCPFlagsString renders flags like "SYN|ACK".
func TCPFlagsString(f uint8) string {
	if f == 0 {
		return "-"
	}
	names := []struct {
		b uint8
		n string
	}{{TCPSyn, "SYN"}, {TCPAck, "ACK"}, {TCPFin, "FIN"}, {TCPRst, "RST"}, {TCPPsh, "PSH"}, {TCPUrg, "URG"}, {TCPEce, "ECE"}, {TCPCwr, "CWR"}}
	out := ""
	for _, n := range names {
		if f&n.b != 0 {
			if out != "" {
				out += "|"
			}
			out += n.n
		}
	}
	return out
}

// TCPFlagBit parses a flag name used in rule files.
func TCPFlagBit(s string) (uint8, bool) {
	switch s {
	case "fin", "FIN":
		return TCPFin, true
	case "syn", "SYN":
		return TCPSyn, true
	case "rst", "RST":
		return TCPRst, true
	case "psh", "PSH":
		return TCPPsh, true
	case "ack", "ACK":
		return TCPAck, true
	case "urg", "URG":
		return TCPUrg, true
	case "ece", "ECE":
		return TCPEce, true
	case "cwr", "CWR":
		return TCPCwr, true
	}
	return 0, false
}
