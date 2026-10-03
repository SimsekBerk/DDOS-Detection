// Package sim generates synthetic traffic and attack scenarios and encodes
// them as real NetFlow v5/v9, IPFIX or sFlow v5 datagrams, so the full
// collector → decoder → engine path is exercised.
package sim

import (
	"encoding/binary"
	"math/rand/v2"
	"net/netip"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/flow"
)

// Spec describes traffic for one second between one source and destination.
type Spec struct {
	Src, Dst         netip.Addr
	SrcPort, DstPort uint16
	Proto            uint8
	TCPFlags         uint8
	ICMPType         uint8
	ICMPCode         uint8
	Packets          uint64 // real (unsampled) packets in this second
	PktSize          uint16 // average packet size in bytes
	Fragment         bool
	// DurationMs is the flow duration reported by NetFlow/IPFIX encoders
	// (0 = 1000 ms). Used to emulate exporter active/inactive timeouts.
	DurationMs uint32
}

func (s Spec) duration() uint32 {
	if s.DurationMs == 0 {
		return 1000
	}
	return s.DurationMs
}

// Encoder turns specs into datagrams.
type Encoder interface {
	Encode(specs []Spec, now time.Time) [][]byte
	Name() string
}

// NewEncoder returns an encoder for "netflow5", "netflow9", "ipfix" or "sflow".
// samplingRate is applied by the encoder (sFlow samples packets, NetFlow/IPFIX
// export scaled-down counters together with the sampling rate).
func NewEncoder(kind string, samplingRate uint32) Encoder {
	if samplingRate == 0 {
		samplingRate = 1
	}
	switch kind {
	case "netflow5":
		return &nf5Encoder{rate: samplingRate, boot: time.Now().Add(-time.Hour)}
	case "ipfix":
		return &ipfixEncoder{rate: samplingRate, domain: 1}
	case "sflow":
		return &sflowEncoder{rate: samplingRate, boot: time.Now().Add(-time.Hour), agent: netip.MustParseAddr("192.0.2.254")}
	default:
		return &nf9Encoder{rate: samplingRate, boot: time.Now().Add(-time.Hour), sourceID: 1}
	}
}

// sampledCount converts real packets to exported (sampled) packets with
// probabilistic rounding so low rates are still represented on average.
func sampledCount(real uint64, rate uint32) uint64 {
	if rate <= 1 {
		return real
	}
	q := real / uint64(rate)
	if rand.Uint64N(uint64(rate)) < real%uint64(rate) {
		q++
	}
	return q
}

const maxDatagram = 1400

// ---------------------------------------------------------------- NetFlow v5

type nf5Encoder struct {
	rate uint32
	boot time.Time
	seq  uint32
}

func (e *nf5Encoder) Name() string { return "netflow5" }

func (e *nf5Encoder) Encode(specs []Spec, now time.Time) [][]byte {
	var out [][]byte
	var recs [][]byte
	uptime := uint32(now.Sub(e.boot).Milliseconds())
	for _, s := range specs {
		if !s.Src.Is4() || !s.Dst.Is4() {
			continue
		}
		p := sampledCount(s.Packets, e.rate)
		if p == 0 {
			continue
		}
		r := make([]byte, 48)
		copy(r[0:4], s.Src.AsSlice())
		copy(r[4:8], s.Dst.AsSlice())
		binary.BigEndian.PutUint16(r[12:14], 1)
		binary.BigEndian.PutUint16(r[14:16], 2)
		binary.BigEndian.PutUint32(r[16:20], uint32(p))
		binary.BigEndian.PutUint32(r[20:24], uint32(p*uint64(s.PktSize)))
		binary.BigEndian.PutUint32(r[24:28], uptime-s.duration())
		binary.BigEndian.PutUint32(r[28:32], uptime)
		sp, dp := ports(s)
		binary.BigEndian.PutUint16(r[32:34], sp)
		binary.BigEndian.PutUint16(r[34:36], dp)
		r[37] = s.TCPFlags
		r[38] = s.Proto
		recs = append(recs, r)
	}
	for len(recs) > 0 {
		n := min(len(recs), 30)
		b := make([]byte, 24, 24+n*48)
		binary.BigEndian.PutUint16(b[0:2], 5)
		binary.BigEndian.PutUint16(b[2:4], uint16(n))
		binary.BigEndian.PutUint32(b[4:8], uptime)
		binary.BigEndian.PutUint32(b[8:12], uint32(now.Unix()))
		binary.BigEndian.PutUint32(b[16:20], e.seq)
		binary.BigEndian.PutUint16(b[22:24], uint16(e.rate&0x3FFF)|0x4000)
		for _, r := range recs[:n] {
			b = append(b, r...)
		}
		e.seq += uint32(n)
		recs = recs[n:]
		out = append(out, b)
	}
	return out
}

// ports returns the L4 ports to export (fragments carry none, ICMP encodes type/code).
func ports(s Spec) (uint16, uint16) {
	if s.Fragment {
		return 0, 0
	}
	if s.Proto == flow.ProtoICMP || s.Proto == flow.ProtoICMPv6 {
		return 0, uint16(s.ICMPType)<<8 | uint16(s.ICMPCode)
	}
	return s.SrcPort, s.DstPort
}

// ------------------------------------------------------- NetFlow v9 / IPFIX

type fieldDef struct{ id, length uint16 }

var v4Fields = []fieldDef{{8, 4}, {12, 4}, {7, 2}, {11, 2}, {4, 1}, {6, 1}, {5, 1}, {1, 8}, {2, 8}, {10, 4}, {14, 4}, {16, 4}, {17, 4}}
var v6Fields = []fieldDef{{27, 16}, {28, 16}, {7, 2}, {11, 2}, {4, 1}, {6, 1}, {5, 1}, {1, 8}, {2, 8}, {10, 4}, {14, 4}, {16, 4}, {17, 4}}

func recordLen(fields []fieldDef) int {
	n := 0
	for _, f := range fields {
		n += int(f.length)
	}
	return n
}

// encodeCommon writes the shared part of a v4/v6 record (fields as listed above).
func encodeCommon(b []byte, s Spec, p uint64) []byte {
	b = append(b, s.Src.AsSlice()...)
	b = append(b, s.Dst.AsSlice()...)
	sp, dp := ports(s)
	b = binary.BigEndian.AppendUint16(b, sp)
	b = binary.BigEndian.AppendUint16(b, dp)
	b = append(b, s.Proto, s.TCPFlags, 0)
	b = binary.BigEndian.AppendUint64(b, p*uint64(s.PktSize))
	b = binary.BigEndian.AppendUint64(b, p)
	b = binary.BigEndian.AppendUint32(b, 1)
	b = binary.BigEndian.AppendUint32(b, 2)
	b = binary.BigEndian.AppendUint32(b, 64500)
	b = binary.BigEndian.AppendUint32(b, 64501)
	return b
}

type nf9Encoder struct {
	rate     uint32
	boot     time.Time
	sourceID uint32
	seq      uint32
	pkts     int
}

func (e *nf9Encoder) Name() string { return "netflow9" }

func (e *nf9Encoder) templateFlowSet() []byte {
	// v4 (256) and v6 (257) templates, both extended with FIRST/LAST_SWITCHED and SAMPLING_INTERVAL.
	extra := []fieldDef{{22, 4}, {21, 4}, {34, 4}}
	b := []byte{0, 0, 0, 0}
	for i, fields := range [][]fieldDef{v4Fields, v6Fields} {
		all := append(append([]fieldDef{}, fields...), extra...)
		b = binary.BigEndian.AppendUint16(b, uint16(256+i))
		b = binary.BigEndian.AppendUint16(b, uint16(len(all)))
		for _, f := range all {
			b = binary.BigEndian.AppendUint16(b, f.id)
			b = binary.BigEndian.AppendUint16(b, f.length)
		}
	}
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	return b
}

func (e *nf9Encoder) Encode(specs []Spec, now time.Time) [][]byte {
	uptime := uint32(now.Sub(e.boot).Milliseconds())
	var v4, v6 [][]byte
	for _, s := range specs {
		p := sampledCount(s.Packets, e.rate)
		if p == 0 {
			continue
		}
		r := encodeCommon(nil, s, p)
		r = binary.BigEndian.AppendUint32(r, uptime-s.duration())
		r = binary.BigEndian.AppendUint32(r, uptime)
		r = binary.BigEndian.AppendUint32(r, e.rate)
		if s.Src.Is4() {
			v4 = append(v4, r)
		} else {
			v6 = append(v6, r)
		}
	}
	var out [][]byte
	emit := func(setID uint16, recs [][]byte) {
		for len(recs) > 0 {
			hdr := make([]byte, 20)
			binary.BigEndian.PutUint16(hdr[0:2], 9)
			binary.BigEndian.PutUint32(hdr[4:8], uptime)
			binary.BigEndian.PutUint32(hdr[8:12], uint32(now.Unix()))
			binary.BigEndian.PutUint32(hdr[12:16], e.seq)
			binary.BigEndian.PutUint32(hdr[16:20], e.sourceID)
			b := hdr
			count := 0
			if e.pkts%20 == 0 {
				t := e.templateFlowSet()
				b = append(b, t...)
				count += 2
			}
			set := []byte{0, 0, 0, 0}
			binary.BigEndian.PutUint16(set[0:2], setID)
			n := 0
			for _, r := range recs {
				if len(b)+len(set)+len(r) > maxDatagram {
					break
				}
				set = append(set, r...)
				n++
			}
			for len(set)%4 != 0 {
				set = append(set, 0)
			}
			binary.BigEndian.PutUint16(set[2:4], uint16(len(set)))
			b = append(b, set...)
			count += n
			binary.BigEndian.PutUint16(b[2:4], uint16(count))
			recs = recs[n:]
			e.seq++
			e.pkts++
			out = append(out, b)
		}
	}
	emit(256, v4)
	emit(257, v6)
	return out
}

type ipfixEncoder struct {
	rate   uint32
	domain uint32
	seq    uint32
	msgs   int
}

func (e *ipfixEncoder) Name() string { return "ipfix" }

func (e *ipfixEncoder) templateSets() []byte {
	extra := []fieldDef{{152, 8}, {153, 8}}
	b := []byte{0, 2, 0, 0}
	for i, fields := range [][]fieldDef{v4Fields, v6Fields} {
		all := append(append([]fieldDef{}, fields...), extra...)
		b = binary.BigEndian.AppendUint16(b, uint16(256+i))
		b = binary.BigEndian.AppendUint16(b, uint16(len(all)))
		for _, f := range all {
			b = binary.BigEndian.AppendUint16(b, f.id)
			b = binary.BigEndian.AppendUint16(b, f.length)
		}
	}
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	// Options template 300: scope observationDomainId, samplingPacketInterval, samplingPacketSpace.
	o := []byte{0, 3, 0, 0}
	o = binary.BigEndian.AppendUint16(o, 300)
	o = binary.BigEndian.AppendUint16(o, 3)
	o = binary.BigEndian.AppendUint16(o, 1)
	for _, f := range []fieldDef{{149, 4}, {305, 4}, {306, 4}} {
		o = binary.BigEndian.AppendUint16(o, f.id)
		o = binary.BigEndian.AppendUint16(o, f.length)
	}
	binary.BigEndian.PutUint16(o[2:4], uint16(len(o)))
	// Options data.
	d := []byte{0x01, 0x2C, 0, 0}
	d = binary.BigEndian.AppendUint32(d, e.domain)
	d = binary.BigEndian.AppendUint32(d, 1)
	d = binary.BigEndian.AppendUint32(d, e.rate-1)
	binary.BigEndian.PutUint16(d[2:4], uint16(len(d)))
	return append(append(b, o...), d...)
}

func (e *ipfixEncoder) Encode(specs []Spec, now time.Time) [][]byte {
	ms := uint64(now.UnixMilli())
	var v4, v6 [][]byte
	for _, s := range specs {
		p := sampledCount(s.Packets, e.rate)
		if p == 0 {
			continue
		}
		r := encodeCommon(nil, s, p)
		r = binary.BigEndian.AppendUint64(r, ms-uint64(s.duration()))
		r = binary.BigEndian.AppendUint64(r, ms)
		if s.Src.Is4() {
			v4 = append(v4, r)
		} else {
			v6 = append(v6, r)
		}
	}
	var out [][]byte
	emit := func(setID uint16, recs [][]byte, force bool) {
		for len(recs) > 0 || force {
			force = false
			b := make([]byte, 16)
			binary.BigEndian.PutUint16(b[0:2], 10)
			binary.BigEndian.PutUint32(b[4:8], uint32(now.Unix()))
			binary.BigEndian.PutUint32(b[8:12], e.seq)
			binary.BigEndian.PutUint32(b[12:16], e.domain)
			dataRecs := 0
			if e.msgs%20 == 0 {
				b = append(b, e.templateSets()...)
				dataRecs++ // the options data record
			}
			if len(recs) > 0 {
				set := []byte{0, 0, 0, 0}
				binary.BigEndian.PutUint16(set[0:2], setID)
				n := 0
				for _, r := range recs {
					if len(b)+len(set)+len(r) > maxDatagram {
						break
					}
					set = append(set, r...)
					n++
				}
				binary.BigEndian.PutUint16(set[2:4], uint16(len(set)))
				b = append(b, set...)
				recs = recs[n:]
				dataRecs += n
			}
			binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
			e.seq += uint32(dataRecs)
			e.msgs++
			out = append(out, b)
		}
	}
	emit(256, v4, e.msgs == 0)
	emit(257, v6, false)
	return out
}

// ------------------------------------------------------------------- sFlow

type sflowEncoder struct {
	rate     uint32
	boot     time.Time
	agent    netip.Addr
	seq      uint32
	sampleSq uint32
	pool     uint32
}

func (e *sflowEncoder) Name() string { return "sflow" }

func (e *sflowEncoder) Encode(specs []Spec, now time.Time) [][]byte {
	var samples [][]byte
	for _, s := range specs {
		n := sampledCount(s.Packets, e.rate)
		for i := uint64(0); i < n; i++ {
			samples = append(samples, e.sample(s))
		}
	}
	rand.Shuffle(len(samples), func(i, j int) { samples[i], samples[j] = samples[j], samples[i] })
	var out [][]byte
	uptime := uint32(now.Sub(e.boot).Milliseconds())
	for len(samples) > 0 {
		b := binary.BigEndian.AppendUint32(nil, 5)
		b = binary.BigEndian.AppendUint32(b, 1)
		b = append(b, e.agent.AsSlice()...)
		b = binary.BigEndian.AppendUint32(b, 0) // sub agent
		b = binary.BigEndian.AppendUint32(b, e.seq)
		b = binary.BigEndian.AppendUint32(b, uptime)
		countOff := len(b)
		b = binary.BigEndian.AppendUint32(b, 0)
		n := 0
		for _, smp := range samples {
			if len(b)+len(smp) > maxDatagram {
				break
			}
			b = append(b, smp...)
			n++
		}
		binary.BigEndian.PutUint32(b[countOff:], uint32(n))
		samples = samples[n:]
		e.seq++
		out = append(out, b)
	}
	return out
}

func (e *sflowEncoder) sample(s Spec) []byte {
	hdr := buildHeader(s)
	frameLen := uint32(s.PktSize) + 14
	// raw packet header record
	rec := binary.BigEndian.AppendUint32(nil, 1) // ethernet
	rec = binary.BigEndian.AppendUint32(rec, frameLen)
	rec = binary.BigEndian.AppendUint32(rec, 4)
	rec = binary.BigEndian.AppendUint32(rec, uint32(len(hdr)))
	rec = append(rec, hdr...)
	for len(rec)%4 != 0 {
		rec = append(rec, 0)
	}
	e.sampleSq++
	e.pool += e.rate
	body := binary.BigEndian.AppendUint32(nil, e.sampleSq)
	body = binary.BigEndian.AppendUint32(body, 3) // source id: ifindex 3
	body = binary.BigEndian.AppendUint32(body, e.rate)
	body = binary.BigEndian.AppendUint32(body, e.pool)
	body = binary.BigEndian.AppendUint32(body, 0) // drops
	body = binary.BigEndian.AppendUint32(body, 1) // input
	body = binary.BigEndian.AppendUint32(body, 2) // output
	body = binary.BigEndian.AppendUint32(body, 1) // one record
	body = binary.BigEndian.AppendUint32(body, 1) // raw header format
	body = binary.BigEndian.AppendUint32(body, uint32(len(rec)))
	body = append(body, rec...)
	smp := binary.BigEndian.AppendUint32(nil, 1) // flow sample
	smp = binary.BigEndian.AppendUint32(smp, uint32(len(body)))
	return append(smp, body...)
}

// buildHeader builds an Ethernet + IP + L4 header for a spec.
func buildHeader(s Spec) []byte {
	b := make([]byte, 12)
	b[0], b[6] = 0x02, 0x02
	if s.Src.Is4() {
		b = binary.BigEndian.AppendUint16(b, 0x0800)
		ip := make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:4], s.PktSize)
		binary.BigEndian.PutUint16(ip[4:6], uint16(rand.Uint32()))
		if s.Fragment {
			binary.BigEndian.PutUint16(ip[6:8], 0x2000|uint16(1+rand.IntN(100)))
		}
		ip[8] = 57
		ip[9] = s.Proto
		copy(ip[12:16], s.Src.AsSlice())
		copy(ip[16:20], s.Dst.AsSlice())
		b = append(b, ip...)
		if s.Fragment {
			return b
		}
	} else {
		b = binary.BigEndian.AppendUint16(b, 0x86DD)
		ip := make([]byte, 40)
		ip[0] = 0x60
		binary.BigEndian.PutUint16(ip[4:6], s.PktSize-40)
		ip[6] = s.Proto
		ip[7] = 57
		copy(ip[8:24], s.Src.AsSlice())
		copy(ip[24:40], s.Dst.AsSlice())
		b = append(b, ip...)
	}
	switch s.Proto {
	case flow.ProtoTCP:
		t := make([]byte, 20)
		binary.BigEndian.PutUint16(t[0:2], s.SrcPort)
		binary.BigEndian.PutUint16(t[2:4], s.DstPort)
		t[12] = 0x50
		t[13] = s.TCPFlags
		b = append(b, t...)
	case flow.ProtoUDP:
		u := make([]byte, 8)
		binary.BigEndian.PutUint16(u[0:2], s.SrcPort)
		binary.BigEndian.PutUint16(u[2:4], s.DstPort)
		b = append(b, u...)
	case flow.ProtoICMP, flow.ProtoICMPv6:
		b = append(b, s.ICMPType, s.ICMPCode, 0, 0, 0, 0, 0, 0)
	}
	return b
}
