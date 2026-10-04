package bench

import (
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"runtime"
	"sync"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/config"
	"github.com/SimsekBerk/DDOS-Detection/internal/engine"
	"github.com/SimsekBerk/DDOS-Detection/internal/flow"
	"github.com/SimsekBerk/DDOS-Detection/internal/flowstore"
)

// SizingOptions describe an operator-scale workload.
type SizingOptions struct {
	RecordsPerSec int // flow records per second arriving at ddosd
	Prefixes      int // protected customer prefixes (/24, /22, /20 mix)
	Hosts         int // distinct active destination hosts inside them
	Exporters     int // routers (records are classified in parallel per exporter, as in the collector)
	Sampling      uint32
	Seconds       int // simulated seconds to run
	FlowSeconds   int // seconds of flow history kept for forensics (sizes the flow store)
	MaxSeries     int
	// NetworkPPS is the real packet rate the records describe (e.g. 330e6
	// at peak); each record carries NetworkPPS/Sampling/RecordsPerSec
	// sampled packets on average. 0 = 1–3 sampled packets per record.
	NetworkPPS float64
	// An optional attack on top of normal traffic: AttackPPS real packets
	// per second (spoofed sources, one sampled packet per record) spread
	// over AttackTargets hosts.
	AttackPPS     float64
	AttackTargets int
}

// SizingResult is the measured cost of the workload.
type SizingResult struct {
	SizingOptions
	ClassifyPerCore float64 `json:"classify_records_per_sec_per_core"`
	EngineCapacity  float64 `json:"engine_records_per_sec"` // single engine goroutine incl. evaluation
	Utilization     float64 `json:"engine_utilization"`     // engine busy time per simulated second
	EvalMillis      float64 `json:"eval_ms"`
	Series          int     `json:"series"`
	SeriesOverflow  uint64  `json:"series_overflow"`
	Incidents       int     `json:"incidents"`
	TotalRecords    int     `json:"total_records_per_sec"` // normal + attack
	HeapMB          float64 `json:"heap_mb"`
	FlowstoreMB     float64 `json:"flowstore_mb"` // forensic flow ring
	BaseMB          float64 `json:"base_mb"`      // rules, objects and their traffic history
	SeriesMB        float64 `json:"series_mb"`    // everything else: detection state
	Note            string  `json:"note,omitempty"`
}

// Sizing replays an operator-like traffic mix at the given record rate
// through classification and the engine on a simulated clock and measures
// CPU time, evaluation latency and memory. Decoding is measured separately
// (DecodeThroughput) and is several times faster than the engine.
func Sizing(o Options, s SizingOptions) SizingResult {
	o.defaults()
	res := SizingResult{SizingOptions: s}
	rng := rand.New(rand.NewPCG(7, 8))

	// Protected space: customer prefixes, as a provider would configure them.
	cfg := benchConfig(o)
	cfg.Objects = nil
	var prefixes []netip.Prefix
	for i := 0; i < s.Prefixes; i++ {
		bits := []int{24, 24, 24, 22, 20}[i%5]
		a := netip.AddrFrom4([4]byte{byte(1 + rng.IntN(222)), byte(rng.IntN(256)), byte(rng.IntN(256)), 0})
		p := netip.PrefixFrom(a, bits).Masked()
		prefixes = append(prefixes, p)
		cfg.Objects = append(cfg.Objects, config.ObjectConfig{Name: fmt.Sprintf("musteri-%d", i), Prefixes: []string{p.String()},
			Profile: []string{"default", "datacenter", "residential", "web"}[i%4], LinkCapacity: 10e9, CarpetV4: 24, CarpetV6: 64, Parsed: []netip.Prefix{p}})
	}
	cfg.Engine.MaxSeries = s.MaxSeries
	cfg.Engine.RecentFlows = s.RecordsPerSec * s.FlowSeconds
	hosts := make([]netip.Addr, s.Hosts)
	for i := range hosts {
		p := prefixes[rng.IntN(len(prefixes))]
		b := p.Addr().As4()
		span := 1 << (32 - p.Bits())
		off := rng.IntN(span)
		b[1] |= byte(off >> 16)
		b[2] |= byte(off >> 8)
		b[3] = byte(off)
		hosts[i] = netip.AddrFrom4(b)
	}

	heap := func() float64 {
		var m runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m)
		return float64(m.HeapInuse) / (1 << 20)
	}
	h0 := heap()
	store := flowstore.New(cfg.Engine.RecentFlows)
	h1 := heap()
	eng, err := engine.New(cfg, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		res.Note = err.Error()
		return res
	}
	h2 := heap()
	res.FlowstoreMB, res.BaseMB = h1-h0, h2-h1

	clock := time.Now().Unix()
	eng.SetClock(func() int64 { return clock })
	exporters := make([]netip.Addr, max(1, s.Exporters))
	for i := range exporters {
		exporters[i] = netip.AddrFrom4([4]byte{10, 255, 0, byte(i + 1)})
	}

	const syn, ack, psh, fin, rst = flow.TCPSyn, flow.TCPAck, flow.TCPPsh, flow.TCPFin, flow.TCPRst
	// Host popularity is heavy-tailed: a few hosts get most of the traffic.
	zipf := rand.NewZipf(rng, 1.1, 200, uint64(len(hosts)-1)) // v=200: the busiest host gets ~0.2% of the traffic
	pktsPerRec := 0.0
	if s.NetworkPPS > 0 && s.Sampling > 0 {
		pktsPerRec = s.NetworkPPS / float64(s.Sampling) / float64(s.RecordsPerSec)
	}
	gen := func(r *rand.Rand, n int) []flow.Record {
		out := make([]flow.Record, n)
		for i := range out {
			h := hosts[zipf.Uint64()]
			ext := netip.AddrFrom4([4]byte{byte(1 + r.IntN(222)), byte(r.IntN(256)), byte(r.IntN(256)), byte(r.IntN(256))})
			pk := uint64(1 + r.IntN(3))
			if pktsPerRec > 0 { // Poisson-like spread around the mean, at least one sampled packet
				pk = max(1, uint64(pktsPerRec*2*r.Float64()+0.5))
			}
			rec := flow.Record{ReceivedUnix: clock, Exporter: exporters[r.IntN(len(exporters))], Source: flow.SourceIPFIX,
				SamplingRate: s.Sampling, Packets: pk, DurationMs: uint32(r.IntN(10000))}
			size := 1060
			switch x := r.Float64(); {
			case x < 0.62:
				rec.Protocol, rec.SrcPort, rec.DstPort = flow.ProtoTCP, 443, uint16(1024+r.IntN(60000))
				rec.TCPFlags = []uint8{ack | psh, ack | psh, syn | ack | psh | fin, syn | ack | psh, syn | ack | psh | rst}[r.IntN(5)]
				size = 1300
			case x < 0.80:
				rec.Protocol, rec.SrcPort, rec.DstPort = flow.ProtoUDP, 443, uint16(1024+r.IntN(60000))
				size = 1250
			case x < 0.85:
				rec.Protocol, rec.SrcPort, rec.DstPort = flow.ProtoUDP, 53, uint16(1024+r.IntN(60000))
				size = 180
			case x < 0.95:
				rec.Protocol, rec.SrcPort, rec.DstPort = flow.ProtoTCP, uint16(1024+r.IntN(60000)), 443
				rec.TCPFlags = ack
				size = 80
			case x < 0.98:
				rec.Protocol, rec.SrcPort, rec.DstPort = flow.ProtoUDP, uint16(1024+r.IntN(60000)), uint16(1024+r.IntN(60000))
				size = 900
			default:
				rec.Protocol, rec.ICMPType = flow.ProtoICMP, 8
				size = 84
			}
			rec.Bytes = rec.Packets * uint64(size)
			if r.IntN(10) < 6 { // 60% inbound to the protected host, 40% outbound from it
				rec.Src, rec.Dst = ext, h
			} else {
				rec.Src, rec.Dst = h, ext
				rec.SrcPort, rec.DstPort = rec.DstPort, rec.SrcPort
			}
			out[i] = rec
		}
		return out
	}

	attackRecs := 0
	var victims []netip.Addr
	if s.AttackPPS > 0 && s.Sampling > 0 && s.AttackTargets > 0 {
		attackRecs = int(s.AttackPPS / float64(s.Sampling))
		for i := 0; i < s.AttackTargets; i++ {
			victims = append(victims, hosts[rng.IntN(len(hosts))])
		}
	}
	res.TotalRecords = s.RecordsPerSec + attackRecs
	attack := func(r *rand.Rand, n int) []flow.Record {
		out := make([]flow.Record, n)
		for i := range out { // NTP amplification from many reflectors
			out[i] = flow.Record{ReceivedUnix: clock, Exporter: exporters[r.IntN(len(exporters))], Source: flow.SourceIPFIX,
				SamplingRate: s.Sampling, Packets: 1, Bytes: 468, Protocol: flow.ProtoUDP, SrcPort: 123, DstPort: uint16(1024 + r.IntN(60000)),
				Src: netip.AddrFrom4([4]byte{byte(1 + r.IntN(222)), byte(r.IntN(256)), byte(r.IntN(256)), byte(r.IntN(256))}),
				Dst: victims[r.IntN(len(victims))], Direction: 0, DurationMs: 1000}
		}
		return out
	}

	var classifyDur, engineDur time.Duration
	var classified, evals int
	var evalDur time.Duration
	warm := min(5, s.Seconds/3)
	for sec := 0; sec < s.Seconds; sec++ {
		batch := gen(rng, s.RecordsPerSec)
		if attackRecs > 0 && sec >= warm/2 {
			batch = append(batch, attack(rng, attackRecs)...)
			rng.Shuffle(len(batch), func(i, j int) { batch[i], batch[j] = batch[j], batch[i] })
		}
		// Classification runs in the collector workers, one per exporter.
		t0 := time.Now()
		parts := max(1, s.Exporters)
		var wg sync.WaitGroup
		chunk := (len(batch) + parts - 1) / parts
		for p := 0; p < parts; p++ {
			lo, hi := p*chunk, min(len(batch), (p+1)*chunk)
			if lo >= hi {
				continue
			}
			wg.Add(1)
			go func(b []flow.Record) { defer wg.Done(); eng.Classify(b) }(batch[lo:hi])
		}
		wg.Wait()
		cd := time.Since(t0)
		// The engine goroutine ingests 1024-record batches, then evaluates.
		t1 := time.Now()
		for i := 0; i < len(batch); i += 1024 {
			eng.IngestSync(batch[i:min(len(batch), i+1024)])
		}
		clock++
		te := time.Now()
		eng.EvaluateAt(clock)
		ed := time.Since(te)
		if sec >= warm {
			classifyDur += cd * time.Duration(parts) // CPU time across workers
			classified += len(batch)
			engineDur += time.Since(t1)
			evalDur += ed
			evals++
		}
	}
	measured := s.Seconds - warm
	res.Incidents = len(eng.Incidents().List("", 0))
	res.ClassifyPerCore = float64(classified) / classifyDur.Seconds()
	res.EngineCapacity = float64(classified) / engineDur.Seconds()
	res.Utilization = engineDur.Seconds() / float64(measured)
	res.EvalMillis = float64(evalDur.Milliseconds()) / float64(evals)
	snap := eng.Snapshot()
	res.Series, res.SeriesOverflow = snap.Series, snap.SeriesOverflow
	res.HeapMB = heap() - h0
	res.SeriesMB = res.HeapMB - res.FlowstoreMB - res.BaseMB
	runtime.KeepAlive(eng)
	return res
}
