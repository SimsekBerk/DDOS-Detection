// Package bench runs reproducible detection benchmarks: simulator scenarios
// are encoded as real NetFlow/IPFIX/sFlow datagrams, decoded, and replayed
// through the engine on a simulated clock (hours of traffic in seconds).
// Exporter caching (active/inactive timeouts) is emulated so time-to-detect
// numbers reflect real router behaviour.
package bench

import (
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/config"
	"github.com/SimsekBerk/DDOS-Detection/internal/decoder"
	"github.com/SimsekBerk/DDOS-Detection/internal/engine"
	"github.com/SimsekBerk/DDOS-Detection/internal/flow"
	"github.com/SimsekBerk/DDOS-Detection/internal/flowstore"
	"github.com/SimsekBerk/DDOS-Detection/internal/sim"
)

// Telemetry describes how a router exports traffic.
type Telemetry struct {
	Name            string `json:"name"`
	Encoder         string `json:"encoder"`
	Sampling        uint32 `json:"sampling"`
	ActiveTimeout   int    `json:"active_timeout"`   // seconds; 0 = packet samples (sFlow)
	InactiveTimeout int    `json:"inactive_timeout"` // seconds
}

// DefaultTelemetry covers the common deployment modes.
var DefaultTelemetry = []Telemetry{
	{Name: "sFlow 1:1000", Encoder: "sflow", Sampling: 1000},
	{Name: "IPFIX 1:1 (10s/15s)", Encoder: "ipfix", Sampling: 1, ActiveTimeout: 10, InactiveTimeout: 15},
	{Name: "NetFlow v9 1:1000 (10s/15s)", Encoder: "netflow9", Sampling: 1000, ActiveTimeout: 10, InactiveTimeout: 15},
	{Name: "NetFlow v9 1:1 (60s/15s)", Encoder: "netflow9", Sampling: 1, ActiveTimeout: 60, InactiveTimeout: 15},
}

// Options control a benchmark run.
type Options struct {
	RulesDir    string
	Warmup      int     // seconds of baseline before the attack (baseline learning)
	Attack      int     // attack duration
	Cooldown    int     // seconds after the attack
	BaselineBPS float64 // background traffic
	StartPhase  int     // seconds into the simulator's 10-minute traffic wave at start
	// Engine overrides (zero = defaults used by the demo).
	Window        time.Duration
	MaxFlowSpread time.Duration
}

func (o *Options) defaults() {
	if o.RulesDir == "" {
		o.RulesDir = "rules"
	}
	if o.Warmup == 0 {
		o.Warmup = 420
	}
	if o.Attack == 0 {
		o.Attack = 90
	}
	if o.Cooldown == 0 {
		o.Cooldown = 240
	}
	if o.BaselineBPS == 0 {
		o.BaselineBPS = 600e6
	}
	if o.Window == 0 {
		o.Window = 10 * time.Second
	}
	if o.MaxFlowSpread == 0 {
		o.MaxFlowSpread = 30 * time.Second
	}
}

// Protected space used by benchmarks (same as the demo config).
var (
	dcPrefix      = netip.MustParsePrefix("198.51.100.0/24")
	hostingPrefix = netip.MustParsePrefix("203.0.113.0/24")
)

func benchConfig(o Options) *config.Config {
	cfg := &config.Config{
		RulesDir: o.RulesDir,
		DataDir:  dataDir(),
		Objects: []config.ObjectConfig{
			{Name: "Demo-DC", Prefixes: []string{dcPrefix.String()}, Profile: "datacenter", LinkCapacity: 10e9, CarpetV4: 24, CarpetV6: 64, Parsed: []netip.Prefix{dcPrefix}},
			{Name: "Demo-Hosting", Prefixes: []string{hostingPrefix.String()}, Profile: "default", LinkCapacity: 5e9, CarpetV4: 24, CarpetV6: 64, Parsed: []netip.Prefix{hostingPrefix}},
		},
	}
	cfg.Engine.Window.Duration = o.Window
	cfg.Engine.MaxFlowSpread.Duration = o.MaxFlowSpread
	cfg.Engine.RecentFlows = 100_000
	cfg.Engine.BaselineTau.Duration = 10 * time.Minute
	cfg.Engine.BaselineLearn.Duration = 5 * time.Minute
	cfg.Engine.IncidentReopen.Duration = 2 * time.Minute
	cfg.Engine.EvidenceEvery.Duration = 24 * time.Hour // keep forensic scans out of the measurement
	cfg.Engine.NearMissRatio = 0.5
	cfg.Engine.SignalMinZ = 4
	cfg.Engine.SignalMinPPS = 2000
	cfg.Engine.SignalMinBPS = 20e6
	cfg.Engine.SignalMinSeconds = 10
	cfg.Engine.MaxSeries = 250_000
	cfg.Collector.QueueSize = 64
	return cfg
}

var tmpDir string

// dataDir is a scratch directory so benchmarks never touch real state.
func dataDir() string {
	if tmpDir == "" {
		d, err := os.MkdirTemp("", "ddos-bench-")
		if err != nil {
			d = os.TempDir()
		}
		tmpDir = d
	}
	return tmpDir
}

// exportCache emulates a router flow cache with active/inactive timeouts.
type exportCache struct {
	active, inactive int64
	m                map[cacheKey]*cacheEntry
}

type cacheKey struct {
	src, dst     netip.Addr
	sport, dport uint16
	proto, flags uint8
	icmpT, icmpC uint8
	frag         bool
}

type cacheEntry struct {
	spec        sim.Spec
	first, last int64
}

func newExportCache(active, inactive int) *exportCache {
	return &exportCache{active: int64(active), inactive: int64(inactive), m: map[cacheKey]*cacheEntry{}}
}

// push adds one second of traffic and returns the flows exported at t.
func (c *exportCache) push(specs []sim.Spec, t int64) []sim.Spec {
	for _, s := range specs {
		k := cacheKey{s.Src, s.Dst, s.SrcPort, s.DstPort, s.Proto, s.TCPFlags, s.ICMPType, s.ICMPCode, s.Fragment}
		e := c.m[k]
		if e == nil {
			c.m[k] = &cacheEntry{spec: s, first: t, last: t}
			continue
		}
		e.spec.Packets += s.Packets
		e.last = t
	}
	var out []sim.Spec
	for k, e := range c.m {
		// Routers export when a flow is older than the active timeout or idle
		// longer than the inactive timeout; the reported duration is the
		// time between the first and last packet.
		if t-e.first+1 < c.active && t-e.last < c.inactive {
			continue
		}
		e.spec.DurationMs = uint32((e.last - e.first + 1) * 1000)
		out = append(out, e.spec)
		delete(c.m, k)
	}
	return out
}

// Result is the outcome of one scenario under one telemetry mode.
type Result struct {
	Scenario     string   `json:"scenario"`
	Name         string   `json:"name"`
	Category     string   `json:"category"`
	Telemetry    string   `json:"telemetry"`
	Target       string   `json:"target"`
	AttackPPS    float64  `json:"attack_pps"`
	Expected     []string `json:"expected"`
	ExpectSignal string   `json:"expect_signal,omitempty"`
	Detected     bool     `json:"detected"`
	TTD          int      `json:"ttd_seconds"` // -1 if not detected
	Hit          []string `json:"hit"`
	Missed       []string `json:"missed"`
	Extra        []string `json:"extra"`
	OtherTargets []string `json:"other_targets"` // incidents not on the attack target (false positives)
	SignalOK     bool     `json:"signal_ok"`
	EndAfter     int      `json:"end_after_seconds"` // -1 if still active at the end
	Pass         bool     `json:"pass"`
	Note         string   `json:"note,omitempty"`
}

type harness struct {
	eng   *engine.Engine
	sim   *sim.Simulator
	enc   sim.Encoder
	dec   *decoder.Decoder
	cache *exportCache
	tel   Telemetry
	now   int64
	exp   netip.Addr
}

func newHarness(o Options, tel Telemetry) (*harness, error) {
	cfg := benchConfig(o)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng, err := engine.New(cfg, flowstore.New(cfg.Engine.RecentFlows), log)
	if err != nil {
		return nil, err
	}
	h := &harness{eng: eng, enc: sim.NewEncoder(tel.Encoder, tel.Sampling), dec: decoder.New(), tel: tel, exp: netip.MustParseAddr("192.0.2.250")}
	// Start on a fixed phase of the simulator's 10-minute traffic wave so
	// runs are reproducible (o.StartPhase shifts it for sensitivity runs).
	h.now = time.Now().Unix()/600*600 + int64(o.StartPhase)
	eng.SetClock(func() int64 { return h.now })
	s, err := sim.New(tel.Encoder, tel.Sampling, "", []netip.Prefix{dcPrefix, hostingPrefix}, o.BaselineBPS)
	if err != nil {
		return nil, err
	}
	s.SetBaseline(true, o.BaselineBPS)
	h.sim = s
	if tel.ActiveTimeout > 0 {
		h.cache = newExportCache(tel.ActiveTimeout, tel.InactiveTimeout)
	}
	return h, nil
}

// step advances one simulated second.
func (h *harness) step() {
	t := time.Unix(h.now, 0)
	specs := h.sim.Generate(t)
	if h.cache != nil {
		specs = h.cache.push(specs, h.now)
	}
	var batch []flow.Record
	for _, dg := range h.enc.Encode(specs, t) {
		res, err := h.dec.Decode(h.exp, dg, h.now)
		if err != nil {
			continue
		}
		for i := range res.Records {
			if res.Records[i].SamplingRate == 0 {
				res.Records[i].SamplingRate = 1
			}
		}
		batch = append(batch, res.Records...)
	}
	if len(batch) > 0 {
		h.eng.IngestSync(batch)
	}
	h.now++
	h.eng.EvaluateAt(h.now)
}

func defaultTarget(sc sim.Scenario) string {
	switch sc.TargetKind {
	case "prefix":
		return hostingPrefix.String()
	case "outbound":
		return "198.51.100.25"
	}
	if sc.Category == "near_miss" && sc.ID != "slow_ramp" {
		return "203.0.113.40" // default profile object
	}
	return "198.51.100.10" // a server with baseline traffic
}

func parseExpect(sc sim.Scenario) (rules []string, signal string) {
	for _, e := range sc.Expect {
		if strings.HasPrefix(e, "signal:") {
			signal = strings.TrimSpace(strings.TrimPrefix(e, "signal:"))
			continue
		}
		rules = append(rules, e)
	}
	return
}

// RunScenario benchmarks one scenario under one telemetry mode.
func RunScenario(o Options, tel Telemetry, sc sim.Scenario) Result {
	o.defaults()
	expected, signal := parseExpect(sc)
	r := Result{Scenario: sc.ID, Name: sc.Name, Category: sc.Category, Telemetry: tel.Name, Expected: expected, ExpectSignal: signal, TTD: -1, EndAfter: -1}
	h, err := newHarness(o, tel)
	if err != nil {
		r.Note = err.Error()
		return r
	}
	for i := 0; i < o.Warmup; i++ {
		h.step()
	}
	preIncidents := map[string]bool{}
	for _, inc := range h.eng.Incidents().List("", 0) {
		preIncidents[inc.ID] = true
	}
	target := defaultTarget(sc)
	req := sim.StartRequest{Scenario: sc.ID, Target: target, Duration: o.Attack}
	if sc.RelativeRule != "" {
		if a, err := netip.ParseAddr(target); err == nil {
			if obj := h.eng.LookupObject(a); obj != nil {
				if t, ok := h.eng.EffectiveThresholds(sc.RelativeRule, obj.ID); ok {
					req.PPS = sc.RelativePPS(float64(t.PPS), float64(t.BPS))
				}
			}
		}
	}
	if sc.ID == "slow_ramp" {
		req.Duration = max(o.Attack, 330) // the ramp needs ~5 minutes
	}
	run, err := h.sim.StartAt(req, time.Unix(h.now, 0))
	if err != nil {
		r.Note = err.Error()
		return r
	}
	r.Target, r.AttackPPS = run.Target, run.PPS
	attackStart := h.now
	attackEnd := attackStart + int64(req.Duration)
	want := map[string]bool{}
	for _, e := range expected {
		want[e] = true
	}
	matchTarget := func(inc engine.Incident) bool { return inc.Target == run.Target }
	for h.now < attackEnd+int64(o.Cooldown) {
		h.step()
		if r.TTD < 0 && h.now <= attackEnd+int64(o.Cooldown) {
			for _, inc := range h.eng.Incidents().List("", 0) {
				if preIncidents[inc.ID] || !matchTarget(inc) {
					continue
				}
				for _, v := range inc.Vectors {
					if want[v.RuleID] {
						r.TTD = int(h.now - attackStart)
						break
					}
				}
			}
		}
		if h.now > attackEnd && r.EndAfter < 0 && r.TTD >= 0 {
			active := false
			for _, inc := range h.eng.Incidents().List("active", 0) {
				if matchTarget(inc) {
					active = true
				}
			}
			if !active {
				r.EndAfter = int(h.now - attackEnd)
			}
		}
	}
	hit := map[string]bool{}
	extra := map[string]bool{}
	other := map[string]bool{}
	for _, inc := range h.eng.Incidents().List("", 0) {
		if preIncidents[inc.ID] {
			continue
		}
		if !matchTarget(inc) {
			other[inc.Target+" ("+vectorIDs(inc)+")"] = true
			continue
		}
		for _, v := range inc.Vectors {
			if want[v.RuleID] {
				hit[v.RuleID] = true
			} else {
				extra[v.RuleID] = true
			}
		}
	}
	r.Detected = r.TTD >= 0
	r.Hit, r.Extra, r.OtherTargets = keys(hit), keys(extra), keys(other)
	for _, e := range expected {
		if !hit[e] {
			r.Missed = append(r.Missed, e)
		}
	}
	if signal != "" {
		parts := strings.Fields(signal)
		for _, s := range h.eng.Signals().List(false, 1, 0) {
			if s.Target != run.Target || s.Kind != parts[0] {
				continue
			}
			if len(parts) < 2 || s.RuleID == parts[1] {
				r.SignalOK = true
			}
		}
		if !r.SignalOK && parts[0] == "baseline_deviation" {
			// Any baseline deviation on the target counts.
			for _, s := range h.eng.Signals().List(false, 1, 0) {
				if s.Target == run.Target && s.Kind == "baseline_deviation" {
					r.SignalOK = true
				}
			}
		}
	}
	switch {
	case signal != "":
		// Near-miss scenarios pass when the signal is raised and the
		// expected rule did NOT open an incident on the target.
		r.Pass = r.SignalOK && len(r.Hit) == 0 && len(r.OtherTargets) == 0
	default:
		r.Pass = r.Detected && len(r.OtherTargets) == 0
	}
	return r
}

func vectorIDs(inc engine.Incident) string {
	var ids []string
	for _, v := range inc.Vectors {
		ids = append(ids, v.RuleID)
	}
	return strings.Join(ids, ",")
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// BaselineResult is a false-positive run with background traffic only.
type BaselineResult struct {
	Telemetry string   `json:"telemetry"`
	Seconds   int      `json:"seconds"`
	Incidents []string `json:"incidents"`
	Signals   int      `json:"signals"`
	SignalIDs []string `json:"signal_rules"`
}

// RunBaseline runs background traffic only and reports any incident (= false positive).
func RunBaseline(o Options, tel Telemetry, seconds int) BaselineResult {
	o.defaults()
	res := BaselineResult{Telemetry: tel.Name, Seconds: seconds}
	h, err := newHarness(o, tel)
	if err != nil {
		res.Incidents = []string{"error: " + err.Error()}
		return res
	}
	for i := 0; i < seconds; i++ {
		h.step()
	}
	for _, inc := range h.eng.Incidents().List("", 0) {
		res.Incidents = append(res.Incidents, fmt.Sprintf("%s %s (%s)", inc.Target, vectorIDs(inc), inc.Severity))
	}
	seen := map[string]bool{}
	for _, s := range h.eng.Signals().List(false, 3, 0) {
		res.Signals++
		seen[s.Kind+":"+s.RuleID] = true
	}
	res.SignalIDs = keys(seen)
	return res
}
