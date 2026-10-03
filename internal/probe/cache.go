// Package probe is a passive packet sensor: it captures packets on a local
// interface, aggregates them into flows the way a router's flow cache does
// (active/inactive timeouts, export on TCP FIN/RST) and exports the flows as
// IPFIX to a collector. ddosd then processes them like any router export.
package probe

import (
	"net/netip"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/flow"
	"github.com/SimsekBerk/DDOS-Detection/internal/sim"
)

type flowKey struct {
	src, dst           netip.Addr
	sport, dport       uint16
	proto              uint8
	icmpType, icmpCode uint8
	frag               bool
}

type flowEntry struct {
	first, last    time.Time
	packets, bytes uint64
	flags          uint8
	ended          bool // TCP FIN or RST seen
}

// Cache aggregates packets into flows with router-like timeouts.
type Cache struct {
	active, inactive time.Duration
	max              int
	flows            map[flowKey]*flowEntry
}

// NewCache returns a flow cache. Flows are exported after `active` since
// their first packet, after `inactive` without packets, after a TCP FIN/RST,
// or all at once when the cache holds `max` flows.
func NewCache(active, inactive time.Duration, max int) *Cache {
	return &Cache{active: active, inactive: inactive, max: max, flows: map[flowKey]*flowEntry{}}
}

// Len returns the number of open flows.
func (c *Cache) Len() int { return len(c.flows) }

// Add accounts one packet: r holds the parsed headers, size is the IP-layer
// length. It reports false when the cache is full and must be flushed.
func (c *Cache) Add(r *flow.Record, size int, t time.Time) bool {
	k := flowKey{src: r.Src, dst: r.Dst, sport: r.SrcPort, dport: r.DstPort, proto: r.Protocol, frag: r.Fragment}
	if r.Protocol == flow.ProtoICMP || r.Protocol == flow.ProtoICMPv6 {
		k.icmpType, k.icmpCode = r.ICMPType, r.ICMPCode
	}
	e := c.flows[k]
	if e == nil {
		if len(c.flows) >= c.max {
			return false
		}
		e = &flowEntry{first: t}
		c.flows[k] = e
	}
	if t.After(e.last) {
		e.last = t
	}
	e.packets++
	e.bytes += uint64(size)
	e.flags |= r.TCPFlags
	if r.Protocol == flow.ProtoTCP && r.TCPFlags&(flow.TCPFin|flow.TCPRst) != 0 {
		e.ended = true
	}
	return true
}

// Expire removes and returns the flows that are due for export (all of them
// when force is set).
func (c *Cache) Expire(now time.Time, force bool) []sim.Spec {
	var out []sim.Spec
	for k, e := range c.flows {
		if !force && !e.ended && now.Sub(e.last) < c.inactive && now.Sub(e.first) < c.active {
			continue
		}
		delete(c.flows, k)
		avg := e.bytes / e.packets
		if avg > 65535 {
			avg = 65535
		}
		dur := e.last.Sub(e.first).Milliseconds()
		if dur < 1 {
			dur = 1
		}
		out = append(out, sim.Spec{
			Src: k.src, Dst: k.dst, SrcPort: k.sport, DstPort: k.dport, Proto: k.proto,
			TCPFlags: e.flags, ICMPType: k.icmpType, ICMPCode: k.icmpCode, Fragment: k.frag,
			Packets: e.packets, Bytes: e.bytes, PktSize: uint16(avg), DurationMs: uint32(dur), Probe: true,
		})
	}
	return out
}
