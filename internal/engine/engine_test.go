package engine

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/config"
	"github.com/SimsekBerk/DDOS-Detection/internal/flow"
	"github.com/SimsekBerk/DDOS-Detection/internal/flowstore"
)

type hookRec struct{ started, ended []string }

func (h *hookRec) VectorStarted(inc *Incident, rule string) { h.started = append(h.started, rule) }
func (h *hookRec) IncidentEnded(inc *Incident)              { h.ended = append(h.ended, inc.ID) }

func testEngine(t *testing.T) (*Engine, *int64) {
	t.Helper()
	cfg := &config.Config{
		RulesDir: "../../rules",
		DataDir:  t.TempDir(),
		Objects: []config.ObjectConfig{{
			Name: "DC", Prefixes: []string{"198.51.100.0/24"}, Profile: "default", CarpetV4: 24, CarpetV6: 64,
			Parsed: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}, LinkCapacity: 10e9,
		}},
	}
	cfg.Engine.Window.Duration = 5 * time.Second
	cfg.Engine.MaxFlowSpread.Duration = 10 * time.Second
	cfg.Engine.BaselineTau.Duration = 60 * time.Second
	cfg.Engine.BaselineLearn.Duration = 30 * time.Second
	cfg.Engine.IncidentReopen.Duration = time.Minute
	cfg.Engine.EvidenceEvery.Duration = 10 * time.Second
	cfg.Engine.NearMissRatio = 0.5
	cfg.Engine.SignalMinZ = 4
	cfg.Engine.SignalMinPPS = 1000
	cfg.Engine.SignalMinBPS = 10e6
	cfg.Collector.QueueSize = 16
	e, err := New(cfg, flowstore.New(100000), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	e.clock = func() int64 { return now }
	return e, &now
}

// dnsAmp builds one second of DNS amplification: pps packets from n sources.
func dnsAmp(dst netip.Addr, pps int, n int, now int64) []flow.Record {
	var out []flow.Record
	for i := 0; i < n; i++ {
		src := netip.AddrFrom4([4]byte{45, 1, byte(i >> 8), byte(i)})
		p := uint64(pps / n)
		out = append(out, flow.Record{ReceivedUnix: now, Src: src, Dst: dst, Protocol: flow.ProtoUDP, SrcPort: 53, DstPort: 40000,
			Packets: p, Bytes: p * 1400, SamplingRate: 1, Source: flow.SourceNetFlow9, DurationMs: 1000})
	}
	return out
}

func TestDetectsAndEndsDNSAmplification(t *testing.T) {
	e, now := testEngine(t)
	h := &hookRec{}
	e.SetHooks(h)
	victim := netip.MustParseAddr("198.51.100.10")
	// 12 seconds of 60k pps from 100 sources (threshold 20k pps, 20 sources).
	for i := 0; i < 12; i++ {
		e.ingest(dnsAmp(victim, 60000, 100, *now))
		*now++
		e.evaluate(*now)
	}
	act := e.incidents.List("active", 0)
	if len(act) == 0 {
		t.Fatal("expected an active incident")
	}
	inc := act[0]
	if inc.Target != victim.String() || inc.Scope != "host" {
		t.Fatalf("unexpected incident target %s/%s", inc.Target, inc.Scope)
	}
	found := map[string]bool{}
	for _, v := range inc.Vectors {
		found[v.RuleID] = true
	}
	if !found["amp_dns"] {
		t.Fatalf("amp_dns vector missing: %+v", found)
	}
	time.Sleep(200 * time.Millisecond) // evidence goroutine
	if len(h.started) == 0 {
		t.Error("VectorStarted hook not called")
	}
	if got := e.incidents.Get(inc.ID); got.Evidence == nil || got.Evidence.Breakdown.Records == 0 {
		t.Error("evidence not collected")
	}
	// Quiet: hold_down is 60s for amp_dns.
	for i := 0; i < 70; i++ {
		*now++
		e.evaluate(*now)
	}
	if a, _ := e.incidents.Counts(); a != 0 {
		t.Fatalf("incident should have ended, %d still active", a)
	}
	time.Sleep(50 * time.Millisecond)
	if len(h.ended) != 1 {
		t.Errorf("IncidentEnded called %d times", len(h.ended))
	}
}

func TestSustainPreventsSpikes(t *testing.T) {
	e, now := testEngine(t)
	victim := netip.MustParseAddr("198.51.100.11")
	// One-second spike only: should not create an incident (sustain 3s).
	e.ingest(dnsAmp(victim, 200000, 100, *now))
	for i := 0; i < 3; i++ {
		*now++
		e.evaluate(*now)
	}
	if a, _ := e.incidents.Counts(); a != 0 {
		t.Fatal("single spike must not trigger")
	}
}

func TestConditionsUnmetSignal(t *testing.T) {
	e, now := testEngine(t)
	victim := netip.MustParseAddr("198.51.100.12")
	for i := 0; i < 8; i++ {
		e.ingest(dnsAmp(victim, 60000, 4, *now)) // only 4 sources
		*now++
		e.evaluate(*now)
	}
	for _, inc := range e.incidents.List("", 0) {
		for _, v := range inc.Vectors {
			if v.RuleID == "amp_dns" {
				t.Fatal("amp_dns must not trigger with 4 sources")
			}
		}
	}
	ok := false
	for _, s := range e.signals.List(false, 0, 0) {
		if s.RuleID == "amp_dns" && s.Kind == "conditions_unmet" {
			ok = true
		}
	}
	if !ok {
		t.Fatal("expected conditions_unmet signal for amp_dns")
	}
}

func TestCarpetBombing(t *testing.T) {
	e, now := testEngine(t)
	for i := 0; i < 10; i++ {
		var batch []flow.Record
		for h := 1; h < 255; h++ {
			dst := netip.AddrFrom4([4]byte{198, 51, 100, byte(h)})
			for s := 0; s < 2; s++ {
				src := netip.AddrFrom4([4]byte{91, 2, byte(h), byte(s)})
				batch = append(batch, flow.Record{ReceivedUnix: *now, Src: src, Dst: dst, Protocol: flow.ProtoUDP, SrcPort: 123, DstPort: 5000,
					Packets: 400, Bytes: 400 * 468, SamplingRate: 1, Source: flow.SourceIPFIX})
			}
		}
		e.ingest(batch)
		*now++
		e.evaluate(*now)
	}
	var carpet, host bool
	for _, inc := range e.incidents.List("active", 0) {
		for _, v := range inc.Vectors {
			if v.RuleID == "carpet_amplification" && inc.Target == "198.51.100.0/24" {
				carpet = true
			}
			if v.RuleID == "amp_ntp" {
				host = true
			}
		}
	}
	if !carpet {
		t.Error("carpet bombing not detected at prefix scope")
	}
	if host {
		t.Error("per-host NTP rule should stay below threshold")
	}
}

func TestBaselineDeviationSignal(t *testing.T) {
	e, now := testEngine(t)
	victim := netip.MustParseAddr("198.51.100.20")
	mk := func(pps int) []flow.Record {
		var out []flow.Record
		for i := 0; i < 50; i++ {
			p := uint64(pps / 50)
			out = append(out, flow.Record{ReceivedUnix: *now, Src: netip.AddrFrom4([4]byte{77, 1, 1, byte(i)}), Dst: victim,
				Protocol: flow.ProtoUDP, SrcPort: 40000, DstPort: 27015, Packets: p, Bytes: p * 900, SamplingRate: 1, Source: flow.SourceIPFIX})
		}
		return out
	}
	for i := 0; i < 60; i++ { // learn ~5k pps
		e.ingest(mk(5000))
		*now++
		e.evaluate(*now)
	}
	for i := 0; i < 10; i++ { // jump to 25k pps (below the 200k static threshold)
		e.ingest(mk(25000))
		*now++
		e.evaluate(*now)
	}
	ok := false
	for _, s := range e.signals.List(false, 0, 0) {
		if s.RuleID == "udp_flood_host" && (s.Kind == "baseline_deviation" || s.Kind == "near_threshold") {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("expected a baseline deviation signal, got %+v", e.signals.List(false, 0, 0))
	}
}
