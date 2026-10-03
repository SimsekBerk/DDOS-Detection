package collector

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/config"
	"github.com/SimsekBerk/DDOS-Detection/internal/flow"
	"github.com/SimsekBerk/DDOS-Detection/internal/sim"
)

type recSink struct {
	mu   sync.Mutex
	recs []flow.Record
}

func (s *recSink) sink(b []flow.Record) bool {
	s.mu.Lock()
	s.recs = append(s.recs, b...)
	s.mu.Unlock()
	return true
}

func (s *recSink) count() (n int, pkts uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.recs {
		pkts += r.Packets * uint64(max(r.SamplingRate, 1))
	}
	return len(s.recs), pkts
}

func start(t *testing.T, cfg *config.Config, s *recSink) (*Collector, string) {
	t.Helper()
	c := New(cfg, s.sink, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = c.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	for i := 0; i < 200 && len(c.Listening()) == 0; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if len(c.Listening()) == 0 {
		t.Fatal("collector did not start")
	}
	return c, c.Listening()[0]
}

func send(t *testing.T, addr string, n int) {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	enc := sim.NewEncoder("ipfix", 1)
	specs := make([]sim.Spec, n)
	for i := range specs {
		specs[i] = sim.Spec{Src: netip.AddrFrom4([4]byte{45, 1, 0, byte(i)}), Dst: netip.MustParseAddr("198.51.100.10"),
			SrcPort: 53, DstPort: 40000, Proto: flow.ProtoUDP, Packets: 10, PktSize: 1200}
	}
	for _, d := range enc.Encode(specs, time.Now()) {
		if _, err := conn.Write(d); err != nil {
			t.Fatal(err)
		}
	}
}

func testConfig(t *testing.T, extra string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(`
collector:
  listen: ["127.0.0.1:0"]
  workers: 2
protected_objects:
  - name: DC
    prefixes: ["198.51.100.0/24"]
` + extra))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func waitFor(cond func() bool) bool {
	for i := 0; i < 200; i++ {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func TestReceivesDecodesAndForwards(t *testing.T) {
	// A second collector receives the replicated datagrams.
	fwdSink := &recSink{}
	_, fwdAddr := start(t, testConfig(t, ""), fwdSink)

	s := &recSink{}
	cfg := testConfig(t, "")
	cfg.Collector.Forward = []string{fwdAddr}
	c, addr := start(t, cfg, s)
	send(t, addr, 50)
	if !waitFor(func() bool { n, _ := s.count(); return n == 50 }) {
		n, _ := s.count()
		t.Fatalf("received %d records, want 50", n)
	}
	if _, pkts := s.count(); pkts != 500 {
		t.Errorf("packets = %d, want 500", pkts)
	}
	if !waitFor(func() bool { n, _ := fwdSink.count(); return n == 50 }) {
		t.Error("forwarded datagrams not received by the second collector")
	}
	ex := c.Exporters()
	if len(ex) != 1 || ex[0].Records != 50 {
		t.Errorf("exporter stats = %+v", ex)
	}
}

func TestAllowlistRejectsAndHotUpdates(t *testing.T) {
	s := &recSink{}
	cfg := testConfig(t, "")
	cfg.Collector.Allow = []string{"10.0.0.0/8"}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	c, addr := start(t, cfg, s)
	send(t, addr, 20)
	if !waitFor(func() bool { return c.Rejected() > 0 }) {
		t.Fatal("datagram from outside the allowlist was not rejected")
	}
	if n, _ := s.count(); n != 0 {
		t.Fatalf("rejected exporter produced %d records", n)
	}
	// Allow loopback at runtime without restarting the listener.
	cfg2 := testConfig(t, "")
	cfg2.Collector.Allow = []string{"127.0.0.1"}
	if err := cfg2.Normalize(); err != nil {
		t.Fatal(err)
	}
	c.Update(cfg2)
	send(t, addr, 20)
	if !waitFor(func() bool { n, _ := s.count(); return n == 20 }) {
		n, _ := s.count()
		t.Fatalf("after allowlist update received %d records, want 20", n)
	}
}
