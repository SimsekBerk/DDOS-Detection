package engine

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"testing"

	"github.com/SimsekBerk/DDOS-Detection/internal/config"
)

// operatorObjects builds n protected objects, one random /24 (plus a few
// /22 and /20 aggregates) each, like a provider's customer list.
func operatorObjects(n int) []config.ObjectConfig {
	r := rand.New(rand.NewPCG(1, 2))
	out := make([]config.ObjectConfig, n)
	for i := range out {
		bits := []int{24, 24, 24, 22, 20}[i%5]
		a := netip.AddrFrom4([4]byte{byte(1 + r.IntN(222)), byte(r.IntN(256)), byte(r.IntN(256)), 0})
		p := netip.PrefixFrom(a, bits).Masked()
		out[i] = config.ObjectConfig{Name: fmt.Sprintf("musteri-%d", i), Parsed: []netip.Prefix{p}, Prefixes: []string{p.String()}}
	}
	return out
}

func BenchmarkObjectLookup(b *testing.B) {
	for _, n := range []int{2, 100, 1000, 5000} {
		objs := operatorObjects(n)
		t := newObjectTable(objs)
		r := rand.New(rand.NewPCG(3, 4))
		addrs := make([]netip.Addr, 4096)
		for i := range addrs {
			if i%2 == 0 { // inside a protected prefix
				p := objs[r.IntN(n)].Parsed[0]
				b4 := p.Addr().As4()
				b4[3] = byte(r.IntN(256))
				addrs[i] = netip.AddrFrom4(b4)
			} else { // an Internet source
				addrs[i] = netip.AddrFrom4([4]byte{byte(1 + r.IntN(222)), byte(r.IntN(256)), byte(r.IntN(256)), byte(r.IntN(256))})
			}
		}
		b.Run(fmt.Sprintf("prefixes=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = t.lookup(addrs[i&4095])
			}
		})
	}
}

// The hashed lookup must give the same answers as a plain longest-prefix
// scan, including nested prefixes owned by different objects and IPv6.
func TestObjectLookupMatchesLinearLPM(t *testing.T) {
	objs := operatorObjects(3000)
	objs = append(objs,
		config.ObjectConfig{Name: "v6-a", Parsed: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}},
		config.ObjectConfig{Name: "v6-b", Parsed: []netip.Prefix{netip.MustParsePrefix("2001:db8:100::/48")}},
		config.ObjectConfig{Name: "nested", Parsed: []netip.Prefix{objs[3].Parsed[0]}}, // duplicate of an existing /22
	)
	// A /24 inside an existing /20 aggregate, owned by another object.
	in20 := objs[4].Parsed[0].Addr().As4()
	in20[2] |= 3
	objs = append(objs, config.ObjectConfig{Name: "inner24", Parsed: []netip.Prefix{netip.PrefixFrom(netip.AddrFrom4(in20), 24)}})

	linear := func(a netip.Addr) int32 {
		a = a.Unmap() // v4-mapped IPv6 addresses belong to their IPv4 prefix
		best, bits := int32(-1), -1
		for i, o := range objs {
			for _, p := range o.Parsed {
				if p.Contains(a) && p.Bits() > bits {
					best, bits = int32(i), p.Bits()
				}
			}
		}
		return best
	}
	tbl := newObjectTable(objs)
	r := rand.New(rand.NewPCG(5, 6))
	check := func(a netip.Addr) {
		if got, want := tbl.lookup(a), linear(a); got != want {
			t.Fatalf("lookup(%s) = %d, want %d", a, got, want)
		}
	}
	for i := 0; i < 20000; i++ {
		p := objs[r.IntN(3000)].Parsed[0].Addr().As4() // IPv4 customer prefixes
		p[3] = byte(r.IntN(256))
		check(netip.AddrFrom4(p))
		check(netip.AddrFrom4([4]byte{byte(r.IntN(256)), byte(r.IntN(256)), byte(r.IntN(256)), byte(r.IntN(256))}))
	}
	check(netip.AddrFrom4(in20)) // longest (inner /24) wins over the /20
	if tbl.objects[tbl.lookup(netip.AddrFrom4(in20))].Name != "inner24" {
		t.Fatal("nested /24 must win over the enclosing /20")
	}
	check(netip.MustParseAddr("2001:db8:100::1"))
	check(netip.MustParseAddr("2001:db8:200::1"))
	check(netip.MustParseAddr("2001:db9::1"))
	check(netip.MustParseAddr("::ffff:" + netip.AddrFrom4(in20).String())) // v4-mapped
}
