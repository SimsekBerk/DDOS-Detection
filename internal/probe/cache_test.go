package probe

import (
	"net/netip"
	"testing"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/flow"
)

func pkt(sport uint16, flags uint8) *flow.Record {
	return &flow.Record{Src: netip.MustParseAddr("192.0.2.10"), Dst: netip.MustParseAddr("198.51.100.5"),
		Protocol: flow.ProtoTCP, SrcPort: sport, DstPort: 443, TCPFlags: flags}
}

func TestCacheAggregatesAndExpires(t *testing.T) {
	c := NewCache(10*time.Second, 5*time.Second, 100)
	t0 := time.Unix(1_000_000, 0)
	for i := 0; i < 10; i++ { // one flow, 10 packets of 1000 bytes over 2 s
		c.Add(pkt(40000, flow.TCPAck), 1000, t0.Add(time.Duration(i)*200*time.Millisecond))
	}
	if got := c.Expire(t0.Add(3*time.Second), false); len(got) != 0 {
		t.Fatalf("flow exported before inactive timeout: %+v", got)
	}
	got := c.Expire(t0.Add(8*time.Second), false)
	if len(got) != 1 {
		t.Fatalf("expected 1 flow after inactive timeout, got %d", len(got))
	}
	f := got[0]
	if f.Packets != 10 || f.Bytes != 10_000 || f.PktSize != 1000 || f.DurationMs != 1800 || !f.Probe {
		t.Fatalf("flow = %+v", f)
	}
	if c.Len() != 0 {
		t.Fatal("expired flow still open")
	}
}

func TestCacheActiveTimeoutAndFin(t *testing.T) {
	c := NewCache(10*time.Second, 5*time.Second, 100)
	t0 := time.Unix(1_000_000, 0)
	for i := 0; i <= 11; i++ { // long-lived flow, a packet every second
		c.Add(pkt(40000, flow.TCPAck), 100, t0.Add(time.Duration(i)*time.Second))
	}
	if got := c.Expire(t0.Add(11*time.Second), false); len(got) != 1 {
		t.Fatalf("active timeout: got %d flows", len(got))
	}
	c.Add(pkt(40001, flow.TCPAck|flow.TCPFin), 60, t0)
	if got := c.Expire(t0.Add(time.Second), false); len(got) != 1 || got[0].TCPFlags&flow.TCPFin == 0 {
		t.Fatalf("FIN flow not exported promptly: %+v", got)
	}
}

func TestCacheFullAndForce(t *testing.T) {
	c := NewCache(10*time.Second, 5*time.Second, 2)
	t0 := time.Unix(1_000_000, 0)
	if !c.Add(pkt(1, 0), 60, t0) || !c.Add(pkt(2, 0), 60, t0) {
		t.Fatal("cache rejected flows below its limit")
	}
	if c.Add(pkt(3, 0), 60, t0) {
		t.Fatal("cache accepted a flow above its limit")
	}
	if !c.Add(pkt(1, 0), 60, t0) {
		t.Fatal("existing flow must still be updated when full")
	}
	if got := c.Expire(t0, true); len(got) != 2 {
		t.Fatalf("force flush returned %d flows", len(got))
	}
}
