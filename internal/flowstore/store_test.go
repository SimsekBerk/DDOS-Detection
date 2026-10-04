package flowstore

import (
	"net/netip"
	"testing"

	"github.com/SimsekBerk/DDOS-Detection/internal/flow"
)

func TestCompactRoundTripAndRing(t *testing.T) {
	s := New(1000)
	in := []flow.Record{
		{ReceivedUnix: 100, Exporter: netip.MustParseAddr("10.0.0.1"), Source: flow.SourceIPFIX, SamplingRate: 1000,
			Src: netip.MustParseAddr("192.0.2.1"), Dst: netip.MustParseAddr("198.51.100.7"), SrcPort: 53, DstPort: 40000,
			Protocol: flow.ProtoUDP, TOS: 8, Bytes: 140000, Packets: 100, DurationMs: 1500, InIf: 3, OutIf: 4,
			SrcAS: 64500, DstAS: 64501, Direction: flow.DirInbound, ObjectID: 2},
		{ReceivedUnix: 101, Exporter: netip.MustParseAddr("2001:db8::1"), Source: flow.SourceSFlow, SamplingRate: 1,
			Src: netip.MustParseAddr("2001:db8:1::5"), Dst: netip.MustParseAddr("2001:db8:100::9"), Protocol: flow.ProtoTCP,
			TCPFlags: flow.TCPSyn, Fragment: true, ICMPType: 0, Bytes: 60, Packets: 1, ObjectID: -1},
		{ReceivedUnix: 102, Exporter: netip.MustParseAddr("10.0.0.1"), Src: netip.MustParseAddr("203.0.113.9"),
			Dst: netip.MustParseAddr("198.51.100.8"), Protocol: flow.ProtoICMP, ICMPType: 3, ICMPCode: 4, Bytes: 84, Packets: 1},
	}
	s.Append(in)
	var got []flow.Record
	s.Scan(0, func(r *flow.Record) bool { got = append(got, *r); return true })
	if len(got) != 3 {
		t.Fatalf("scanned %d records", len(got))
	}
	for i := range in { // Scan is newest-first
		if g, w := got[len(got)-1-i], in[i]; g != w {
			t.Errorf("record %d:\n got %+v\nwant %+v", i, g, w)
		}
	}
	if !got[0].Src.Is4() || got[1].Src.Is4() {
		t.Error("IPv4/IPv6 family not preserved")
	}
	// Overwrite: only the newest 1000 remain, oldest-time follows.
	batch := make([]flow.Record, 1500)
	for i := range batch {
		batch[i] = flow.Record{ReceivedUnix: int64(200 + i), Src: in[0].Src, Dst: in[0].Dst}
	}
	s.Append(batch)
	if n, c := s.Len(); n != 1000 || c != 1000 {
		t.Fatalf("len = %d/%d", n, c)
	}
	if o := s.OldestUnix(); o != 200+500 {
		t.Fatalf("oldest = %d, want 700", o)
	}
	cnt := 0
	s.Scan(1600, func(*flow.Record) bool { cnt++; return true })
	if cnt != 100 {
		t.Fatalf("scan since 1600 = %d, want 100", cnt)
	}
}

// The compact-form prefilter must never change query results, only speed.
func TestPrefilterMatchesPredicate(t *testing.T) {
	s := New(10000)
	var recs []flow.Record
	for i := 0; i < 5000; i++ {
		dst := netip.AddrFrom4([4]byte{198, 51, byte(100 + i%3), byte(i)})
		src := netip.AddrFrom4([4]byte{203, 0, byte(i % 7), byte(i * 7)})
		if i%5 == 0 {
			dst = netip.MustParseAddr("2001:db8:100::1")
			if i%10 == 0 {
				dst = netip.MustParseAddr("2001:db8:200::1")
			}
		}
		recs = append(recs, flow.Record{ReceivedUnix: 100, Src: src, Dst: dst, ObjectID: int32(i % 4), Protocol: flow.ProtoUDP, Bytes: 100, Packets: 1, Direction: flow.DirInbound})
	}
	s.Append(recs)
	for _, f := range []Filter{
		{Seconds: 60, Dst: "198.51.101.0/24"},
		{Seconds: 60, Dst: "198.51.100.7"},
		{Seconds: 60, Dst: "198.51.96.0/20"},
		{Seconds: 60, Dst: "2001:db8:100::/48"},
		{Seconds: 60, Src: "203.0.3.0/24"},
		{Seconds: 60, Dst: "0.0.0.0/0"},
		{Seconds: 60, ObjectID: func() *int { v := 2; return &v }()},
	} {
		pred, since, err := f.Compile(120)
		if err != nil {
			t.Fatal(err)
		}
		var want, got int
		s.scan(since, nil, func(r *flow.Record) bool {
			if pred(r) {
				want++
			}
			return true
		})
		s.scan(since, f.prefilter(), func(r *flow.Record) bool {
			if pred(r) {
				got++
			}
			return true
		})
		if got != want || want == 0 {
			t.Errorf("%+v: prefiltered %d, full %d", f, got, want)
		}
	}
}
