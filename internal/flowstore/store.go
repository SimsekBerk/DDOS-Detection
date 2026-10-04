// Package flowstore keeps the most recent flow records in a ring buffer and
// answers forensic queries (top-N, breakdowns, samples) over them.
package flowstore

import (
	"encoding/binary"
	"net/netip"
	"sync"

	"github.com/SimsekBerk/DDOS-Detection/internal/flow"
)

// stored is the compact, pointer-free form of a flow record. At provider
// rates the ring holds tens of millions of records; without pointers the
// garbage collector never scans it, and it is ~40% smaller than flow.Record.
type stored struct {
	recv             int64
	bytes, packets   uint64
	src, dst         [16]byte
	sampling         uint32
	duration         uint32
	inIf, outIf      uint32
	srcAS, dstAS     uint32
	object           int32
	srcPort, dstPort uint16
	exporter         uint16 // index into Store.exporters
	proto, tcpFlags  uint8
	icmpType         uint8
	icmpCode         uint8
	tos              uint8
	direction        uint8
	source           uint8
	bits             uint8 // bitSrc4 | bitDst4 | bitFragment
}

const (
	bitSrc4 = 1 << iota
	bitDst4
	bitFragment
)

// maxExporters bounds the exporter table; more distinct exporters share
// the last slot (the collector already limits exporters to 4096).
const maxExporters = 1 << 16

// Store is a fixed-size ring buffer of normalized flow records.
type Store struct {
	mu        sync.RWMutex
	buf       []stored
	next      int
	full      bool
	total     uint64
	exporters []netip.Addr
	expIndex  map[netip.Addr]uint16
}

func New(size int) *Store {
	if size < 1000 {
		size = 1000
	}
	return &Store{buf: make([]stored, size), expIndex: map[netip.Addr]uint16{}}
}

func addrBytes(a netip.Addr) ([16]byte, bool) {
	if a.Is4() {
		return a.As16(), true
	}
	return a.As16(), false
}

func (s *Store) exporterIndex(a netip.Addr) uint16 {
	if i, ok := s.expIndex[a]; ok {
		return i
	}
	if len(s.exporters) >= maxExporters {
		return maxExporters - 1
	}
	i := uint16(len(s.exporters))
	s.exporters = append(s.exporters, a)
	s.expIndex[a] = i
	return i
}

// Append adds records, overwriting the oldest when full.
func (s *Store) Append(rs []flow.Record) {
	s.mu.Lock()
	for i := range rs {
		r := &rs[i]
		c := &s.buf[s.next]
		var src4, dst4 bool
		c.src, src4 = addrBytes(r.Src)
		c.dst, dst4 = addrBytes(r.Dst)
		c.recv, c.bytes, c.packets = r.ReceivedUnix, r.Bytes, r.Packets
		c.sampling, c.duration = r.SamplingRate, r.DurationMs
		c.inIf, c.outIf, c.srcAS, c.dstAS = r.InIf, r.OutIf, r.SrcAS, r.DstAS
		c.object = r.ObjectID
		c.srcPort, c.dstPort = r.SrcPort, r.DstPort
		c.exporter = s.exporterIndex(r.Exporter)
		c.proto, c.tcpFlags, c.icmpType, c.icmpCode, c.tos = r.Protocol, r.TCPFlags, r.ICMPType, r.ICMPCode, r.TOS
		c.direction, c.source = uint8(r.Direction), uint8(r.Source)
		c.bits = 0
		if src4 {
			c.bits |= bitSrc4
		}
		if dst4 {
			c.bits |= bitDst4
		}
		if r.Fragment {
			c.bits |= bitFragment
		}
		s.next++
		if s.next == len(s.buf) {
			s.next = 0
			s.full = true
		}
	}
	s.total += uint64(len(rs))
	s.mu.Unlock()
}

func toAddr(b [16]byte, is4 bool) netip.Addr {
	a := netip.AddrFrom16(b)
	if is4 {
		return a.Unmap()
	}
	return a
}

// load expands a stored record (into r, reused by the caller).
func (s *Store) load(c *stored, r *flow.Record) {
	*r = flow.Record{
		ReceivedUnix: c.recv, Source: flow.Source(c.source), SamplingRate: c.sampling,
		Src: toAddr(c.src, c.bits&bitSrc4 != 0), Dst: toAddr(c.dst, c.bits&bitDst4 != 0),
		SrcPort: c.srcPort, DstPort: c.dstPort, Protocol: c.proto, TCPFlags: c.tcpFlags, TOS: c.tos,
		ICMPType: c.icmpType, ICMPCode: c.icmpCode, Fragment: c.bits&bitFragment != 0,
		Bytes: c.bytes, Packets: c.packets, DurationMs: c.duration,
		InIf: c.inIf, OutIf: c.outIf, SrcAS: c.srcAS, DstAS: c.dstAS,
		Direction: flow.Direction(c.direction), ObjectID: c.object,
	}
	if int(c.exporter) < len(s.exporters) {
		r.Exporter = s.exporters[c.exporter]
	}
}

// Len returns the number of records currently stored and the capacity.
func (s *Store) Len() (int, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.full {
		return len(s.buf), len(s.buf)
	}
	return s.next, len(s.buf)
}

// OldestUnix returns the receive time of the oldest stored record.
func (s *Store) OldestUnix() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.full {
		return s.buf[s.next].recv
	}
	if s.next == 0 {
		return 0
	}
	return s.buf[0].recv
}

// prefixMatch tests an address stored as 16 bytes (IPv4 v4-mapped) against
// a prefix with two masked 64-bit comparisons.
type prefixMatch struct {
	on               bool
	v4               bool
	hi, lo, mhi, mlo uint64
}

func newPrefixMatch(p netip.Prefix) prefixMatch {
	if !p.IsValid() {
		return prefixMatch{}
	}
	a := p.Addr()
	bits := p.Bits()
	m := prefixMatch{on: true, v4: a.Is4()}
	if m.v4 {
		bits += 96 // position inside the v4-mapped form
	}
	b := a.As16()
	m.hi, m.lo = binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])
	switch {
	case bits >= 128:
		m.mhi, m.mlo = ^uint64(0), ^uint64(0)
	case bits > 64:
		m.mhi, m.mlo = ^uint64(0), ^uint64(0)<<(128-bits)
	case bits > 0:
		m.mhi = ^uint64(0) << (64 - bits)
	}
	m.hi &= m.mhi
	m.lo &= m.mlo
	return m
}

func (m *prefixMatch) match(b *[16]byte, is4 bool) bool {
	if is4 != m.v4 {
		return false
	}
	return binary.BigEndian.Uint64(b[:8])&m.mhi == m.hi && binary.BigEndian.Uint64(b[8:])&m.mlo == m.lo
}

// prefilter rejects records on the compact form, before they are expanded.
// It only narrows: the full predicate is still applied afterwards.
type prefilter struct {
	src, dst prefixMatch
	object   *int32
}

func (p *prefilter) ok(c *stored) bool {
	if p.dst.on && !p.dst.match(&c.dst, c.bits&bitDst4 != 0) {
		return false
	}
	if p.src.on && !p.src.match(&c.src, c.bits&bitSrc4 != 0) {
		return false
	}
	if p.object != nil && c.object != *p.object {
		return false
	}
	return true
}

// Scan visits records newest-first whose receive time is >= since.
// fn returns false to stop early. fn must not retain the pointer: the same
// record is reused for every call.
func (s *Store) Scan(since int64, fn func(*flow.Record) bool) {
	s.scan(since, nil, fn)
}

func (s *Store) scan(since int64, pre *prefilter, fn func(*flow.Record) bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := s.next
	if !s.full && n == 0 {
		return
	}
	count := len(s.buf)
	if !s.full {
		count = n
	}
	var r flow.Record
	i := n
	for k := 0; k < count; k++ {
		i--
		if i < 0 {
			i = len(s.buf) - 1
		}
		c := &s.buf[i]
		if c.recv < since {
			return
		}
		if pre != nil && !pre.ok(c) {
			continue
		}
		s.load(c, &r)
		if !fn(&r) {
			return
		}
	}
}
