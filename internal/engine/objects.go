package engine

import (
	"net/netip"
	"sort"

	"github.com/SimsekBerk/DDOS-Detection/internal/config"
)

// Object is a protected object (customer, block, service group).
type Object struct {
	ID           int32          `json:"id"`
	Name         string         `json:"name"`
	Prefixes     []netip.Prefix `json:"prefixes"`
	Profile      string         `json:"profile"`
	LinkCapacity float64        `json:"link_capacity_bps"`
	CarpetV4     int            `json:"carpet_prefix_v4"`
	CarpetV6     int            `json:"carpet_prefix_v6"`
	Notes        string         `json:"notes,omitempty"`
}

// prefixLen holds the protected prefixes of one length, keyed by prefix.
type prefixLen struct {
	bits int
	m    map[netip.Prefix]int32
}

// objectTable does longest-prefix-match lookups over protected prefixes.
// Prefixes are grouped by length; a lookup masks the address once per
// distinct length (longest first) and probes a hash map, so the cost
// depends on the number of distinct lengths, not on the number of prefixes
// (thousands of customer prefixes stay as fast as a handful).
type objectTable struct {
	objects []*Object
	v4, v6  []prefixLen // longest first
}

func newObjectTable(cfg []config.ObjectConfig) *objectTable {
	t := &objectTable{}
	byLen := map[bool]map[int]map[netip.Prefix]int32{true: {}, false: {}}
	for i, oc := range cfg {
		o := &Object{
			ID: int32(i), Name: oc.Name, Prefixes: oc.Parsed, Profile: oc.Profile,
			LinkCapacity: float64(oc.LinkCapacity), CarpetV4: oc.CarpetV4, CarpetV6: oc.CarpetV6, Notes: oc.Notes,
		}
		t.objects = append(t.objects, o)
		for _, p := range oc.Parsed {
			p = p.Masked()
			lens := byLen[p.Addr().Is4()]
			if lens[p.Bits()] == nil {
				lens[p.Bits()] = map[netip.Prefix]int32{}
			}
			if _, dup := lens[p.Bits()][p]; !dup { // the first object listing a prefix owns it
				lens[p.Bits()][p] = o.ID
			}
		}
	}
	for v4, lens := range byLen {
		var list []prefixLen
		for bits, m := range lens {
			list = append(list, prefixLen{bits, m})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].bits > list[j].bits })
		if v4 {
			t.v4 = list
		} else {
			t.v6 = list
		}
	}
	return t
}

// lookup returns the object id for an address, or -1.
func (t *objectTable) lookup(a netip.Addr) int32 {
	a = a.Unmap()
	lens := t.v6
	if a.Is4() {
		lens = t.v4
	}
	for _, l := range lens {
		p, err := a.Prefix(l.bits)
		if err != nil {
			continue
		}
		if id, ok := l.m[p]; ok {
			return id
		}
	}
	return -1
}

func (t *objectTable) name(id int32) string {
	if id < 0 || int(id) >= len(t.objects) {
		return "-"
	}
	return t.objects[id].Name
}

// carpetPrefix returns the aggregation prefix for carpet-bombing detection.
func (o *Object) carpetPrefix(a netip.Addr) netip.Prefix {
	bits := o.CarpetV4
	if a.Is6() {
		bits = o.CarpetV6
	}
	p, _ := a.Prefix(bits)
	return p
}
