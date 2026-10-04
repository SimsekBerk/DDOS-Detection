package bench

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/collector"
	"github.com/SimsekBerk/DDOS-Detection/internal/decoder"
	"github.com/SimsekBerk/DDOS-Detection/internal/engine"
	"github.com/SimsekBerk/DDOS-Detection/internal/flow"
	"github.com/SimsekBerk/DDOS-Detection/internal/flowstore"
	"github.com/SimsekBerk/DDOS-Detection/internal/sim"
)

// ThroughputResult reports processing capacity.
type ThroughputResult struct {
	Stage         string  `json:"stage"`
	Encoder       string  `json:"encoder"`
	RecordsPerSec float64 `json:"records_per_sec"`
	Records       int     `json:"records"`
	Seconds       float64 `json:"seconds"`
	LossPct       float64 `json:"loss_pct,omitempty"`
	Note          string  `json:"note,omitempty"`
}

// mixedSpecs returns one second of mixed baseline + attack traffic.
func mixedSpecs(o Options, now time.Time) []sim.Spec {
	s, _ := sim.New("netflow9", 1, "", []netip.Prefix{dcPrefix, hostingPrefix}, o.BaselineBPS)
	s.SetBaseline(true, o.BaselineBPS)
	for _, id := range []string{"dns_amp", "syn_flood", "carpet_ntp", "udp_flood"} {
		sc, _ := sim.Lookup(id)
		target := defaultTarget(sc)
		if id == "syn_flood" {
			target = "203.0.113.80"
		}
		_, _ = s.StartAt(sim.StartRequest{Scenario: id, Target: target, Duration: 3600}, now)
	}
	var out []sim.Spec
	for i := 0; i < 5; i++ {
		out = append(out, s.Generate(now.Add(time.Duration(i)*time.Second))...)
	}
	return out
}

// DecodeThroughput measures decoder speed for one encoder (single core).
func DecodeThroughput(o Options, encoder string, d time.Duration) ThroughputResult {
	o.defaults()
	now := time.Now()
	sampling := uint32(1)
	if encoder == "sflow" {
		sampling = 1 // one sample per spec packet would explode; use 1:1 specs scaled down below
	}
	specs := mixedSpecs(o, now)
	if encoder == "sflow" {
		for i := range specs { // ~1 sample per spec
			specs[i].Packets = 1
		}
	}
	dgs := sim.NewEncoder(encoder, sampling).Encode(specs, now)
	dec := decoder.New()
	exp := netip.MustParseAddr("192.0.2.250")
	// learn templates
	for _, dg := range dgs {
		_, _ = dec.Decode(exp, dg, now.Unix())
	}
	start := time.Now()
	recs := 0
	for time.Since(start) < d {
		for _, dg := range dgs {
			res, err := dec.Decode(exp, dg, now.Unix())
			if err == nil {
				recs += len(res.Records)
			}
		}
	}
	el := time.Since(start).Seconds()
	return ThroughputResult{Stage: "decode", Encoder: encoder, Records: recs, Seconds: el, RecordsPerSec: float64(recs) / el, Note: "tek çekirdek"}
}

// EngineThroughput measures ingest + 1/s evaluation cost on decoded records.
func EngineThroughput(o Options, d time.Duration) ThroughputResult {
	o.defaults()
	now := time.Now()
	specs := mixedSpecs(o, now)
	var recs []flow.Record
	dec := decoder.New()
	exp := netip.MustParseAddr("192.0.2.250")
	for _, dg := range sim.NewEncoder("ipfix", 1).Encode(specs, now) {
		if res, err := dec.Decode(exp, dg, now.Unix()); err == nil {
			recs = append(recs, res.Records...)
		}
	}
	cfg := benchConfig(o)
	eng, err := engine.New(cfg, flowstore.New(500_000), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		return ThroughputResult{Stage: "engine", Note: err.Error()}
	}
	clock := now.Unix()
	eng.SetClock(func() int64 { return clock })
	const batch = 1024 // collector batch size
	start := time.Now()
	total := 0
	lastEval := time.Now()
	for time.Since(start) < d {
		for i := 0; i < len(recs); i += batch {
			b := make([]flow.Record, min(batch, len(recs)-i))
			copy(b, recs[i:])
			for j := range b {
				b[j].ReceivedUnix = clock
			}
			eng.IngestSync(b)
			total += len(b)
		}
		if time.Since(lastEval) >= 100*time.Millisecond { // evaluate frequently to include its cost
			clock++
			eng.EvaluateAt(clock)
			lastEval = time.Now()
		}
	}
	el := time.Since(start).Seconds()
	return ThroughputResult{Stage: "engine", Encoder: "ipfix", Records: total, Seconds: el, RecordsPerSec: float64(total) / el,
		Note: fmt.Sprintf("52 kural, %d seri, flow tamponu dahil, 1024 kayıtlık partiler", eng.Snapshot().Series)}
}

// EndToEnd sends datagrams over UDP loopback to a live collector+engine at
// a target record rate and reports achieved throughput and loss.
func EndToEnd(o Options, encoder string, targetRPS float64, d time.Duration) ThroughputResult {
	o.defaults()
	cfg := benchConfig(o)
	cfg.Collector.Listen = []string{"127.0.0.1:0"}
	cfg.Collector.ReadBufferBytes = 32 << 20
	cfg.Collector.QueueSize = 8192
	cfg.Collector.DefaultSamplingRate = 1
	cfg.Collector.Workers = 4
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng, err := engine.New(cfg, flowstore.New(500_000), log)
	if err != nil {
		return ThroughputResult{Stage: "e2e", Note: err.Error()}
	}
	col := collector.New(cfg, eng.Submit, eng.Classify, log)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go eng.Run(ctx)
	go func() { _ = col.Run(ctx) }()
	var addr string
	for i := 0; i < 100 && addr == ""; i++ {
		if l := col.Listening(); len(l) > 0 {
			addr = l[0]
		}
		time.Sleep(10 * time.Millisecond)
	}
	now := time.Now()
	specs := mixedSpecs(o, now)
	dgs := sim.NewEncoder(encoder, 1).Encode(specs, now)
	perDG := float64(len(specs)) / float64(len(dgs))
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return ThroughputResult{Stage: "e2e", Note: err.Error()}
	}
	defer conn.Close()
	time.Sleep(200 * time.Millisecond)
	before := eng.Snapshot().RecordsTotal
	dgPerSec := targetRPS / perDG
	interval := time.Duration(float64(time.Second) / dgPerSec * 64)
	start := time.Now()
	sent := 0
	next := start
	for time.Since(start) < d {
		for k := 0; k < 64; k++ {
			_, _ = conn.Write(dgs[(sent+k)%len(dgs)])
		}
		sent += 64
		next = next.Add(interval)
		if s := time.Until(next); s > 0 {
			time.Sleep(s)
		}
	}
	time.Sleep(1500 * time.Millisecond) // drain
	got := eng.Snapshot().RecordsTotal - before
	el := time.Since(start).Seconds() - 1.5
	sentRecs := float64(sent) * perDG
	loss := 0.0
	if sentRecs > 0 {
		loss = 100 * (1 - float64(got)/sentRecs)
		if loss < 0 {
			loss = 0
		}
	}
	snap := eng.Snapshot()
	return ThroughputResult{Stage: "e2e-udp", Encoder: encoder, Records: int(got), Seconds: el, RecordsPerSec: float64(got) / el, LossPct: loss,
		Note: fmt.Sprintf("hedef %.0f kayıt/sn, UDP loopback, %d worker, kuyruk kaybı: worker %d datagram, motor %d kayıt", targetRPS, cfg.Collector.Workers, col.Dropped(), snap.Dropped)}
}
