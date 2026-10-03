// Package decoder parses NetFlow v5/v9, IPFIX and sFlow v5 datagrams into
// normalized flow records. Template state (NetFlow v9 / IPFIX) is kept per
// exporter and observation domain.
package decoder

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"github.com/SimsekBerk/DDOS-Detection/internal/flow"
)

var (
	ErrShort       = errors.New("datagram too short")
	ErrUnsupported = errors.New("unsupported datagram version")
)

// Result is the outcome of decoding a single datagram.
type Result struct {
	Source  flow.Source
	Records []flow.Record

	// Sequence tracking (for loss detection). SeqKey distinguishes
	// independent sequence spaces of one exporter (source id / domain / sub-agent).
	SeqKey  uint64
	Seq     uint32
	SeqNext uint32 // expected sequence of the next datagram in this space

	TemplatesLearned int
	MissingTemplate  int // data sets skipped because the template is unknown
	OptionRecords    int
}

type tmplKey struct {
	exporter netip.Addr
	domain   uint32
	id       uint16
}

type fieldSpec struct {
	id         uint16
	length     uint16 // 0xFFFF = variable length (IPFIX)
	enterprise uint32
}

type template struct {
	fields     []fieldSpec
	scopeCount int // options templates: number of scope fields
	options    bool
}

type samplingKey struct {
	exporter netip.Addr
	domain   uint32
}

// MaxTemplatesPerExporter bounds template state so a misbehaving or spoofed
// exporter cannot exhaust memory.
const MaxTemplatesPerExporter = 1024

// Decoder is safe for concurrent use.
type Decoder struct {
	mu       sync.Mutex
	nf9      map[tmplKey]*template
	ipfix    map[tmplKey]*template
	sampling map[samplingKey]uint32
	perExp   map[netip.Addr]int
	Rejected uint64 // templates rejected by the per-exporter limit
}

// storeTemplate saves a template unless the exporter is over its limit.
// Caller must hold d.mu.
func (d *Decoder) storeTemplate(m map[tmplKey]*template, k tmplKey, t *template) bool {
	if _, exists := m[k]; !exists {
		if d.perExp[k.exporter] >= MaxTemplatesPerExporter {
			d.Rejected++
			return false
		}
		d.perExp[k.exporter]++
	}
	m[k] = t
	return true
}

func New() *Decoder {
	return &Decoder{
		nf9:      make(map[tmplKey]*template),
		ipfix:    make(map[tmplKey]*template),
		sampling: make(map[samplingKey]uint32),
		perExp:   make(map[netip.Addr]int),
	}
}

// TemplateCount returns the number of cached templates for an exporter.
func (d *Decoder) TemplateCount(exporter netip.Addr) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for k := range d.nf9 {
		if k.exporter == exporter {
			n++
		}
	}
	for k := range d.ipfix {
		if k.exporter == exporter {
			n++
		}
	}
	return n
}

// LearnedSampling returns the sampling rate learned from options data (0 if none).
func (d *Decoder) LearnedSampling(exporter netip.Addr) uint32 {
	d.mu.Lock()
	defer d.mu.Unlock()
	var r uint32
	for k, v := range d.sampling {
		if k.exporter == exporter && v > r {
			r = v
		}
	}
	return r
}

// Decode detects the datagram format and decodes it.
func (d *Decoder) Decode(exporter netip.Addr, data []byte, now int64) (Result, error) {
	if len(data) < 4 {
		return Result{}, ErrShort
	}
	// sFlow v5 starts with a 32-bit version field.
	if binary.BigEndian.Uint32(data[0:4]) == 5 {
		return decodeSFlow(exporter, data, now)
	}
	switch binary.BigEndian.Uint16(data[0:2]) {
	case 5:
		return decodeNetFlow5(exporter, data, now)
	case 9:
		return d.decodeNetFlow9(exporter, data, now)
	case 10:
		return d.decodeIPFIX(exporter, data, now)
	}
	return Result{}, fmt.Errorf("%w: first bytes %x", ErrUnsupported, data[:4])
}

// beUint reads a big-endian unsigned integer of 1..8 bytes.
func beUint(b []byte) uint64 {
	if len(b) > 8 {
		b = b[len(b)-8:]
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

func addrFrom(b []byte) netip.Addr {
	switch len(b) {
	case 4:
		return netip.AddrFrom4([4]byte(b))
	case 16:
		a := netip.AddrFrom16([16]byte(b))
		return a.Unmap()
	}
	return netip.Addr{}
}

// recordState collects auxiliary values while walking template fields.
type recordState struct {
	firstRel, lastRel  uint64 // sysUptime-relative ms
	hasRel             bool
	startAbs, endAbs   uint64 // absolute ms
	hasAbs             bool
	startSec, endSec   uint64
	hasSec             bool
	sampling           uint64
	samplingInterval   uint64
	samplingSpace      uint64
	samplingPopulation uint64
	samplingSize       uint64
	icmpTypeCode       uint64
	hasICMPTypeCode    bool
	icmpType, icmpCode uint64
	hasICMPSplit       bool
	fragOffset         uint64
	fragFlags          uint64
	outBytes, outPkts  uint64
	inBytesSet         bool
	inPktsSet          bool
	totalBytes         uint64
	totalPkts          uint64
}

// applyField maps an IANA IPFIX / NetFlow v9 information element to the record.
func applyField(r *flow.Record, st *recordState, id uint16, b []byte) {
	switch id {
	case 1: // octetDeltaCount / IN_BYTES
		r.Bytes = beUint(b)
		st.inBytesSet = true
	case 2: // packetDeltaCount / IN_PKTS
		r.Packets = beUint(b)
		st.inPktsSet = true
	case 4: // protocolIdentifier
		r.Protocol = uint8(beUint(b))
	case 5: // ipClassOfService
		r.TOS = uint8(beUint(b))
	case 6: // tcpControlBits (may be 2 bytes in IPFIX)
		r.TCPFlags = uint8(beUint(b))
	case 7: // sourceTransportPort
		r.SrcPort = uint16(beUint(b))
	case 8, 27: // sourceIPv4Address / sourceIPv6Address
		r.Src = addrFrom(b)
	case 10: // ingressInterface
		r.InIf = uint32(beUint(b))
	case 11: // destinationTransportPort
		r.DstPort = uint16(beUint(b))
	case 12, 28: // destinationIPv4Address / destinationIPv6Address
		r.Dst = addrFrom(b)
	case 14: // egressInterface
		r.OutIf = uint32(beUint(b))
	case 16: // bgpSourceAsNumber
		r.SrcAS = uint32(beUint(b))
	case 17: // bgpDestinationAsNumber
		r.DstAS = uint32(beUint(b))
	case 21: // flowEndSysUpTime / LAST_SWITCHED
		st.lastRel = beUint(b)
		st.hasRel = true
	case 22: // flowStartSysUpTime / FIRST_SWITCHED
		st.firstRel = beUint(b)
		st.hasRel = true
	case 23: // postOctetDeltaCount / OUT_BYTES
		st.outBytes = beUint(b)
	case 24: // postPacketDeltaCount / OUT_PKTS
		st.outPkts = beUint(b)
	case 32, 139: // icmpTypeCodeIPv4 / icmpTypeCodeIPv6
		st.icmpTypeCode = beUint(b)
		st.hasICMPTypeCode = true
	case 34: // samplingInterval
		st.sampling = beUint(b)
	case 50: // samplerRandomInterval
		st.sampling = beUint(b)
	case 85: // octetTotalCount
		st.totalBytes = beUint(b)
	case 86: // packetTotalCount
		st.totalPkts = beUint(b)
	case 88: // fragmentOffset
		st.fragOffset = beUint(b)
	case 150: // flowStartSeconds
		st.startSec = beUint(b)
		st.hasSec = true
	case 151: // flowEndSeconds
		st.endSec = beUint(b)
		st.hasSec = true
	case 152: // flowStartMilliseconds
		st.startAbs = beUint(b)
		st.hasAbs = true
	case 153: // flowEndMilliseconds
		st.endAbs = beUint(b)
		st.hasAbs = true
	case 176, 178: // icmpTypeIPv4 / icmpTypeIPv6
		st.icmpType = beUint(b)
		st.hasICMPSplit = true
	case 177, 179: // icmpCodeIPv4 / icmpCodeIPv6
		st.icmpCode = beUint(b)
		st.hasICMPSplit = true
	case 197: // fragmentFlags
		st.fragFlags = beUint(b)
	case 305: // samplingPacketInterval
		st.samplingInterval = beUint(b)
	case 306: // samplingPacketSpace
		st.samplingSpace = beUint(b)
	case 309: // samplingSize
		st.samplingSize = beUint(b)
	case 310: // samplingPopulation
		st.samplingPopulation = beUint(b)
	}
}

// samplingFromState derives a sampling rate (0 = unknown).
func samplingFromState(st *recordState) uint32 {
	switch {
	case st.sampling > 0:
		return uint32(st.sampling)
	case st.samplingInterval > 0:
		return uint32((st.samplingInterval + st.samplingSpace) / st.samplingInterval)
	case st.samplingSize > 0 && st.samplingPopulation > 0:
		return uint32(st.samplingPopulation / st.samplingSize)
	}
	return 0
}

// finish fills derived fields (duration, ICMP, fragments, counters).
func finish(r *flow.Record, st *recordState) {
	if !st.inBytesSet {
		if st.totalBytes > 0 {
			r.Bytes = st.totalBytes
		} else {
			r.Bytes = st.outBytes
		}
	}
	if !st.inPktsSet {
		if st.totalPkts > 0 {
			r.Packets = st.totalPkts
		} else {
			r.Packets = st.outPkts
		}
	}
	switch {
	case st.hasAbs && st.endAbs >= st.startAbs:
		r.DurationMs = clampDuration(st.endAbs - st.startAbs)
	case st.hasRel && st.lastRel >= st.firstRel:
		r.DurationMs = clampDuration(st.lastRel - st.firstRel)
	case st.hasSec && st.endSec >= st.startSec:
		r.DurationMs = clampDuration((st.endSec - st.startSec) * 1000)
	}
	if r.Protocol == flow.ProtoICMP || r.Protocol == flow.ProtoICMPv6 {
		switch {
		case st.hasICMPTypeCode:
			r.ICMPType, r.ICMPCode = uint8(st.icmpTypeCode>>8), uint8(st.icmpTypeCode)
		case st.hasICMPSplit:
			r.ICMPType, r.ICMPCode = uint8(st.icmpType), uint8(st.icmpCode)
		default:
			// Many NetFlow exporters encode type/code into the destination port.
			r.ICMPType, r.ICMPCode = uint8(r.DstPort>>8), uint8(r.DstPort)
		}
	}
	// fragmentFlags bit 0x20 = More Fragments (IPFIX encodes the IPv4 flags in the high bits).
	if st.fragOffset > 0 || st.fragFlags&0x20 != 0 {
		r.Fragment = true
	}
	markPortlessFragment(r)
}

// markPortlessFragment applies the common heuristic: non-initial fragments carry
// no L4 header, so exporters report TCP/UDP with both ports zero.
func markPortlessFragment(r *flow.Record) {
	if (r.Protocol == flow.ProtoUDP || r.Protocol == flow.ProtoTCP) && r.SrcPort == 0 && r.DstPort == 0 {
		r.Fragment = true
	}
}

func clampDuration(ms uint64) uint32 {
	const max = 10 * 60 * 1000
	if ms > max {
		return max
	}
	return uint32(ms)
}
