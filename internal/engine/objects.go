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

type prefixEntry struct {
	p   netip.Prefix
	obj int32
}

// objectTable does longest-prefix-match lookups over protected prefixes.
type objectTable struct {
	objects []*Object
	entries []prefixEntry // sorted by prefix length, longest first
}

func newObjectTable(cfg []config.ObjectConfig) *objectTable {
	t := &objectTable{}
	for i, oc := range cfg {
		o := &Object{
			ID: int32(i), Name: oc.Name, Prefixes: oc.Parsed, Profile: oc.Profile,
			LinkCapacity: float64(oc.LinkCapacity), CarpetV4: oc.CarpetV4, CarpetV6: oc.CarpetV6, Notes: oc.Notes,
		}
		t.objects = append(t.objects, o)
		for _, p := range oc.Parsed {
			t.entries = append(t.entries, prefixEntry{p, o.ID})
		}
	}
	sort.SliceStable(t.entries, func(i, j int) bool { return t.entries[i].p.Bits() > t.entries[j].p.Bits() })
	return t
}

// lookup returns the object id for an address, or -1.
func (t *objectTable) lookup(a netip.Addr) int32 {
	for _, e := range t.entries {
		if e.p.Contains(a) {
			return e.obj
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
