package decoder_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/decoder"
	"github.com/SimsekBerk/DDOS-Detection/internal/flow"
	"github.com/SimsekBerk/DDOS-Detection/internal/sim"
)

func specs() []sim.Spec {
	return []sim.Spec{
		{Src: netip.MustParseAddr("192.0.2.10"), Dst: netip.MustParseAddr("198.51.100.20"), SrcPort: 53, DstPort: 40000, Proto: flow.ProtoUDP, Packets: 1000, PktSize: 1200},
		{Src: netip.MustParseAddr("192.0.2.11"), Dst: netip.MustParseAddr("198.51.100.21"), SrcPort: 51000, DstPort: 443, Proto: flow.ProtoTCP, TCPFlags: flow.TCPSyn, Packets: 500, PktSize: 60},
		{Src: netip.MustParseAddr("2001:db8::1"), Dst: netip.MustParseAddr("2001:db8:100::5"), SrcPort: 123, DstPort: 5000, Proto: flow.ProtoUDP, Packets: 200, PktSize: 468},
		{Src: netip.MustParseAddr("192.0.2.12"), Dst: netip.MustParseAddr("198.51.100.22"), Proto: flow.ProtoICMP, ICMPType: 8, Packets: 300, PktSize: 84},
		{Src: netip.MustParseAddr("192.0.2.13"), Dst: netip.MustParseAddr("198.51.100.23"), Proto: flow.ProtoUDP, Fragment: true, Packets: 100, PktSize: 1500},
	}
}

func decodeAll(t *testing.T, kind string, rate uint32) []flow.Record {
	t.Helper()
	enc := sim.NewEncoder(kind, rate)
	dec := decoder.New()
	exp := netip.MustParseAddr("127.0.0.1")
	var out []flow.Record
	for _, dg := range enc.Encode(specs(), time.Now()) {
		res, err := dec.Decode(exp, dg, time.Now().Unix())
		if err != nil {
			t.Fatalf("%s: decode: %v", kind, err)
		}
		if res.MissingTemplate > 0 {
			t.Fatalf("%s: missing template", kind)
		}
		out = append(out, res.Records...)
	}
	return out
}

func TestRoundTripFlowProtocols(t *testing.T) {
	for _, kind := range []string{"netflow9", "ipfix"} {
		recs := decodeAll(t, kind, 1)
		if len(recs) != len(specs()) {
			t.Fatalf("%s: got %d records, want %d", kind, len(recs), len(specs()))
		}
		byDst := map[netip.Addr]flow.Record{}
		for _, r := range recs {
			byDst[r.Dst] = r
		}
		r := byDst[netip.MustParseAddr("198.51.100.20")]
		if r.SrcPort != 53 || r.Protocol != flow.ProtoUDP || r.Packets != 1000 || r.Bytes != 1_200_000 || r.SamplingRate != 1 {
			t.Errorf("%s: dns record mismatch: %+v", kind, r)
		}
		if r.DurationMs != 1000 {
			t.Errorf("%s: duration %d, want 1000", kind, r.DurationMs)
		}
		if r := byDst[netip.MustParseAddr("198.51.100.21")]; r.TCPFlags != flow.TCPSyn {
			t.Errorf("%s: tcp flags %x", kind, r.TCPFlags)
		}
		if r := byDst[netip.MustParseAddr("2001:db8:100::5")]; r.SrcPort != 123 || r.Bytes != 200*468 {
			t.Errorf("%s: v6 record mismatch: %+v", kind, r)
		}
		if r := byDst[netip.MustParseAddr("198.51.100.22")]; r.ICMPType != 8 {
			t.Errorf("%s: icmp type %d", kind, r.ICMPType)
		}
		if r := byDst[netip.MustParseAddr("198.51.100.23")]; !r.Fragment {
			t.Errorf("%s: fragment not detected", kind)
		}
	}
}

func TestIPFIXOptionsSampling(t *testing.T) {
	recs := decodeAll(t, "ipfix", 100)
	if len(recs) == 0 {
		t.Fatal("no records")
	}
	for _, r := range recs {
		if r.SamplingRate != 100 {
			t.Fatalf("sampling learned from options = %d, want 100", r.SamplingRate)
		}
	}
}

func TestNetFlow5(t *testing.T) {
	recs := decodeAll(t, "netflow5", 1)
	if len(recs) != 4 { // v6 spec is skipped by v5
		t.Fatalf("got %d records", len(recs))
	}
	for _, r := range recs {
		if r.Dst == netip.MustParseAddr("198.51.100.20") && (r.SrcPort != 53 || r.Packets != 1000) {
			t.Errorf("v5 mismatch %+v", r)
		}
	}
}

func TestSFlowSamples(t *testing.T) {
	recs := decodeAll(t, "sflow", 10)
	var dns, syn, frag, v6 int
	for _, r := range recs {
		if r.SamplingRate != 10 || r.Packets != 1 {
			t.Fatalf("bad sample %+v", r)
		}
		switch {
		case r.SrcPort == 53 && r.Protocol == flow.ProtoUDP:
			dns++
			if r.Bytes != 1214 {
				t.Errorf("frame length %d", r.Bytes)
			}
		case r.TCPFlags == flow.TCPSyn:
			syn++
		case r.Fragment:
			frag++
		case r.Dst.Is6():
			v6++
		}
	}
	// 1000 packets at 1:10 -> ~100 samples (probabilistic rounding is exact for multiples).
	if dns != 100 || syn != 50 || frag != 10 || v6 != 20 {
		t.Errorf("sample counts dns=%d syn=%d frag=%d v6=%d", dns, syn, frag, v6)
	}
}

func TestGarbage(t *testing.T) {
	dec := decoder.New()
	if _, err := dec.Decode(netip.MustParseAddr("127.0.0.1"), []byte{1, 2, 3, 4, 5, 6}, 0); err == nil {
		t.Fatal("expected error")
	}
	// Truncated v9 should not panic.
	enc := sim.NewEncoder("netflow9", 1)
	for _, dg := range enc.Encode(specs(), time.Now()) {
		for i := 0; i < len(dg); i += 7 {
			_, _ = dec.Decode(netip.MustParseAddr("127.0.0.2"), dg[:i], 0)
		}
	}
}
