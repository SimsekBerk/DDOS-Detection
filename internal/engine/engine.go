// Package engine implements the detection pipeline: normalization, per-rule
// sliding windows, dynamic baselines, incident lifecycle, near-miss signals
// and forensic evidence collection.
package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/bits"
	"net/netip"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/config"
	"github.com/SimsekBerk/DDOS-Detection/internal/flow"
	"github.com/SimsekBerk/DDOS-Detection/internal/flowstore"
	"github.com/SimsekBerk/DDOS-Detection/internal/rules"
	"github.com/SimsekBerk/DDOS-Detection/internal/store"
)

// Hooks receives incident lifecycle events. Implementations must not block
// for long; they are called from background goroutines.
type Hooks interface {
	VectorStarted(inc *Incident, ruleID string)
	IncidentEnded(inc *Incident)
}

// classifier is an immutable snapshot used to classify records concurrently
// (object, direction and matching rules).
type classifier struct {
	gen      uint32
	objs     *objectTable
	inbound  []*rules.Compiled
	outbound []*rules.Compiled
	enabled  [][]bool // [rule][object]
}

func (cl *classifier) classify(r *flow.Record) {
	r.ObjectID = -1
	r.Direction = flow.DirOther
	r.Matched = [2]uint64{}
	r.ClassGen = cl.gen
	list := cl.inbound
	if id := cl.objs.lookup(r.Dst); id >= 0 {
		r.Direction, r.ObjectID = flow.DirInbound, id
	} else if id := cl.objs.lookup(r.Src); id >= 0 {
		r.Direction, r.ObjectID = flow.DirOutbound, id
		list = cl.outbound
	} else {
		return
	}
	for _, c := range list {
		if cl.enabled[c.Index][r.ObjectID] && c.Matches(r) {
			r.Matched[c.Index>>6] |= 1 << (c.Index & 63)
		}
	}
}

type effEntry struct {
	enabled bool
	t       rules.Thresholds
	scale   float64
}

// Snapshot is the engine status published every second.
type Snapshot struct {
	Time            int64          `json:"time"`
	WindowSeconds   int64          `json:"window_seconds"`
	Global          TotalPoint     `json:"global"`
	Objects         []ObjectStatus `json:"objects"`
	Series          int            `json:"series"`
	ActiveIncidents int            `json:"active_incidents"`
	TotalIncidents  int            `json:"total_incidents"`
	PendingSignals  int            `json:"pending_signals"`
	RecordsPerSec   float64        `json:"records_per_sec"`
	RecordsTotal    uint64         `json:"records_total"`
	Dropped         uint64         `json:"dropped_records"`
	EvalMillis      float64        `json:"eval_millis"`
	FlowStoreLen    int            `json:"flowstore_len"`
	FlowStoreCap    int            `json:"flowstore_cap"`
	OldestFlow      int64          `json:"oldest_flow"`
	Rules           int            `json:"rules"`
	RulesActive     int            `json:"rules_active"`
	SeriesOverflow  uint64         `json:"series_overflow"`
	MaxSeries       int            `json:"max_series"`
}

// ObjectStatus is the live status of a protected object.
type ObjectStatus struct {
	Object
	Rates           TotalPoint `json:"rates"`
	ActiveIncidents int        `json:"active_incidents"`
	Utilization     float64    `json:"utilization"`
}

type Engine struct {
	cfg       *config.Config
	objs      *objectTable
	store     *flowstore.Store
	totals    *Totals
	incidents *Incidents
	signals   *Signals
	hooks     Hooks
	log       *slog.Logger

	in   chan []flow.Record
	ctrl chan func()

	rulesPtr  atomic.Pointer[rules.Set]
	objsPtr   atomic.Pointer[objectTable]   // for readers outside the loop
	cfgPtr    atomic.Pointer[config.Config] // for readers outside the loop
	dataDir   string                        // restart-only settings
	rulesDir  string
	cls       atomic.Pointer[classifier]
	clsGen    uint32
	overrides map[string]rules.Override
	ovMu      sync.Mutex

	// owned by the loop goroutine
	set          *rules.Set
	inbound      []*rules.Compiled
	outbound     []*rules.Compiled
	eff          [][]effEntry
	series       map[seriesKey]*series
	lastEvidence map[string]int64
	// per-rule last series cache (attack traffic hits the same target in a row)
	lastKey    [rules.MaxRules]seriesKey
	lastSeries [rules.MaxRules]*series

	window    int64
	maxSpread int64
	tau       float64
	learn     float64
	firstEval int64 // time of the first evaluation (start of global learning)

	clock   func() int64
	running atomic.Bool // Run loop active; otherwise Do executes inline (offline replay)

	evidenceBusy   sync.Map
	recordsIn      atomic.Uint64
	seriesOverflow atomic.Uint64
	dropped        atomic.Uint64
	lastCount      uint64
	rps            float64
	evalMillis     float64
	snap           atomic.Pointer[Snapshot]
}

// New creates an engine and loads rules.
func New(cfg *config.Config, st *flowstore.Store, log *slog.Logger) (*Engine, error) {
	e := &Engine{
		cfg: cfg, objs: newObjectTable(cfg.Objects), store: st,
		incidents: newIncidents(cfg.Engine.IncidentReopen.Duration), signals: newSignals(),
		in: make(chan []flow.Record, cfg.Collector.QueueSize), ctrl: make(chan func(), 64),
		series: map[seriesKey]*series{}, lastEvidence: map[string]int64{},
		window:    int64(cfg.Engine.Window.Seconds()),
		maxSpread: int64(cfg.Engine.MaxFlowSpread.Seconds()),
		tau:       cfg.Engine.BaselineTau.Seconds(),
		learn:     cfg.Engine.BaselineLearn.Seconds(),
		log:       log,
		overrides: map[string]rules.Override{},
		clock:     func() int64 { return time.Now().Unix() },
	}
	if e.maxSpread < 1 {
		e.maxSpread = 1
	}
	e.dataDir, e.rulesDir = cfg.DataDir, cfg.RulesDir
	e.objsPtr.Store(e.objs)
	e.cfgPtr.Store(cfg)
	e.totals = newTotals(len(e.objs.objects))
	_ = store.Load(filepath.Join(cfg.DataDir, "rule_overrides.json"), &e.overrides)
	set, err := rules.Load(cfg.RulesDir, e.overrides)
	if err != nil {
		return nil, err
	}
	for _, o := range e.objs.objects {
		if _, ok := set.Profiles[o.Profile]; !ok {
			return nil, fmt.Errorf("protected object %q uses unknown profile %q", o.Name, o.Profile)
		}
	}
	e.applyRules(set)
	var dump incidentsDump
	if err := store.Load(filepath.Join(cfg.DataDir, "incidents.json"), &dump); err == nil {
		e.incidents.restore(dump, time.Now().Unix())
	}
	e.publish(time.Now().Unix())
	return e, nil
}

// SetClock replaces the wall clock (offline replay / benchmarks). Call before
// any ingest.
func (e *Engine) SetClock(f func() int64) { e.clock = f }

// IngestSync processes a batch synchronously on the caller's goroutine. It is
// only for offline replay and benchmarks; never call it while Run is active.
func (e *Engine) IngestSync(batch []flow.Record) { e.ingest(batch) }

// EvaluateAt runs one evaluation tick at the given second (offline replay /
// benchmarks; never while Run is active).
func (e *Engine) EvaluateAt(now int64) { e.evaluate(now) }

// SetHooks registers lifecycle hooks (call before Run).
func (e *Engine) SetHooks(h Hooks) { e.hooks = h }

func (e *Engine) applyRules(set *rules.Set) {
	e.set = set
	e.inbound, e.outbound = nil, nil
	e.eff = make([][]effEntry, len(set.Rules))
	for _, c := range set.Rules {
		if c.DirectionCode() == flow.DirOutbound {
			e.outbound = append(e.outbound, c)
		} else {
			e.inbound = append(e.inbound, c)
		}
		row := make([]effEntry, len(e.objs.objects))
		for _, o := range e.objs.objects {
			t, ok := set.Effective(c, o.Profile)
			scale := 1.0
			if c.T.PPS > 0 && t.PPS > 0 {
				scale = float64(t.PPS / c.T.PPS)
			} else if c.T.BPS > 0 && t.BPS > 0 {
				scale = float64(t.BPS / c.T.BPS)
			} else if c.T.FPS > 0 && t.FPS > 0 {
				scale = float64(t.FPS / c.T.FPS)
			} else if p := set.Profiles[o.Profile]; p != nil {
				scale = p.Scale
			}
			row[o.ID] = effEntry{enabled: ok, t: t, scale: scale}
		}
		e.eff[c.Index] = row
	}
	e.rulesPtr.Store(set)
	e.rebuildClassifier()
}

// rebuildClassifier publishes a new classification snapshot.
func (e *Engine) rebuildClassifier() {
	e.clsGen++
	cl := &classifier{gen: e.clsGen, objs: e.objs, inbound: e.inbound, outbound: e.outbound, enabled: make([][]bool, len(e.eff))}
	for i, row := range e.eff {
		cl.enabled[i] = make([]bool, len(row))
		for j, ent := range row {
			cl.enabled[i][j] = ent.enabled
		}
	}
	e.cls.Store(cl)
	e.lastSeries = [rules.MaxRules]*series{}
}

// Classify sets object, direction and matching rules on records. It is safe
// for concurrent use; collectors call it in parallel workers so the engine
// goroutine only aggregates.
func (e *Engine) Classify(batch []flow.Record) {
	cl := e.cls.Load()
	for i := range batch {
		cl.classify(&batch[i])
	}
}

// Rules returns the current rule set.
func (e *Engine) Rules() *rules.Set { return e.rulesPtr.Load() }

// Objects returns the protected objects.
func (e *Engine) Objects() []*Object { return e.objsPtr.Load().objects }

// ObjectName resolves an object id.
func (e *Engine) ObjectName(id int32) string { return e.objsPtr.Load().name(id) }

// ObjectByName finds an object.
func (e *Engine) ObjectByName(name string) *Object {
	for _, o := range e.objsPtr.Load().objects {
		if o.Name == name {
			return o
		}
	}
	return nil
}

// LookupObject returns the object containing an address.
func (e *Engine) LookupObject(a netip.Addr) *Object {
	t := e.objsPtr.Load()
	if id := t.lookup(a); id >= 0 {
		return t.objects[id]
	}
	return nil
}

func (e *Engine) Incidents() *Incidents   { return e.incidents }
func (e *Engine) Signals() *Signals       { return e.signals }
func (e *Engine) Totals() *Totals         { return e.totals }
func (e *Engine) Store() *flowstore.Store { return e.store }
func (e *Engine) Snapshot() *Snapshot     { return e.snap.Load() }
func (e *Engine) Config() *config.Config  { return e.cfgPtr.Load() }
func (e *Engine) WindowSeconds() int64    { return e.window }

// Submit hands a batch of decoded records to the engine without blocking.
func (e *Engine) Submit(batch []flow.Record) bool {
	select {
	case e.in <- batch:
		return true
	default:
		e.dropped.Add(uint64(len(batch)))
		return false
	}
}

// Do runs f on the engine goroutine and waits for it (with timeout). When the
// Run loop is not active (offline replay, benchmarks) f runs inline.
func (e *Engine) Do(f func()) error {
	if !e.running.Load() {
		f()
		return nil
	}
	done := make(chan struct{})
	select {
	case e.ctrl <- func() { f(); close(done) }:
	case <-time.After(2 * time.Second):
		return errors.New("engine busy")
	}
	select {
	case <-done:
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("engine timeout")
	}
}

// Run is the engine main loop.
func (e *Engine) Run(ctx context.Context) {
	e.running.Store(true)
	defer e.running.Store(false)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	saveTick := time.NewTicker(15 * time.Second)
	defer saveTick.Stop()
	for {
		select {
		case <-ctx.Done():
			e.persist()
			return
		case batch := <-e.in:
			e.ingest(batch)
		case f := <-e.ctrl:
			f()
		case t := <-tick.C:
			e.evaluate(t.Unix())
		case <-saveTick.C:
			go e.persist()
		}
	}
}

func (e *Engine) persist() {
	if d, ok := e.incidents.dump(); ok {
		if err := store.Save(filepath.Join(e.dataDir, "incidents.json"), d); err != nil {
			e.log.Warn("persist incidents", "err", err)
		}
	}
}

// ingest normalizes records, stores them and updates rule series.
func (e *Engine) ingest(batch []flow.Record) {
	now := e.clock()
	cl := e.cls.Load()
	for i := range batch {
		r := &batch[i]
		if r.ClassGen != cl.gen {
			cl.classify(r)
		}
		if r.ReceivedUnix == 0 || r.ReceivedUnix > now || r.ReceivedUnix < now-5 {
			r.ReceivedUnix = now
		}
	}
	e.store.Append(batch)
	e.recordsIn.Add(uint64(len(batch)))

	e.totals.mu.Lock()
	for i := range batch {
		e.totals.addLocked(&batch[i], batch[i].ReceivedUnix, e.maxSpread)
	}
	e.totals.mu.Unlock()

	for i := range batch {
		r := &batch[i]
		if r.ObjectID < 0 {
			continue
		}
		obj := e.objs.objects[r.ObjectID]
		target, peer := r.Dst, r.Src
		if r.Direction == flow.DirOutbound {
			target, peer = r.Src, r.Dst
		}
		for w, bits := range r.Matched {
			for bits != 0 {
				idx := w<<6 | bits64(bits)
				bits &= bits - 1
				c := e.set.Rules[idx]
				key := seriesKey{rule: uint16(idx), obj: r.ObjectID}
				switch c.Scope {
				case "host":
					key.pfx = netip.PrefixFrom(target, target.BitLen())
				case "prefix":
					key.pfx = obj.carpetPrefix(target)
				}
				s := e.lastSeries[idx]
				if s == nil || e.lastKey[idx] != key {
					s = e.series[key]
					if s == nil {
						if c.Scope == "host" && len(e.series) >= e.cfg.Engine.MaxSeries {
							e.seriesOverflow.Add(1)
							continue
						}
						s = &series{trackUniques: c.Conditions.MinUniqueSources > 0, trackDests: c.Conditions.MinUniqueDests > 0 && c.Scope != "host"}
						e.series[key] = s
					}
					e.lastKey[idx], e.lastSeries[idx] = key, s
				}
				s.add(r, r.ReceivedUnix, e.maxSpread, peer, target)
			}
		}
	}
}

// bits64 returns the index of the lowest set bit.
func bits64(x uint64) int { return bits.TrailingZeros64(x) }

// check evaluates thresholds, baseline and conditions for one series.
type checkResult struct {
	ratio, staticRatio, baseRatio float64
	hit, condOK                   bool
	kind, reason, condFail        string
	z                             float64
	basePPS, baseBPS              float64
	ready                         bool
}

func (e *Engine) check(c *rules.Compiled, ent effEntry, s *series, r rate, uniq, dests int) checkResult {
	var res checkResult
	t := ent.t
	metric := ""
	var val, thr float64
	try := func(name string, v float64, limit float64) {
		if limit > 0 {
			if q := v / limit; q > res.staticRatio {
				res.staticRatio, metric, val, thr = q, name, v, limit
			}
		}
	}
	try("pps", r.PPS, float64(t.PPS))
	try("bps", r.BPS, float64(t.BPS))
	try("fps", r.FPS, float64(t.FPS))

	res.ready = s.learned >= e.learn
	res.basePPS, res.baseBPS = s.bPPS, s.bBPS
	if res.ready {
		res.z = math.Max(zScore(r.PPS, s.bPPS, s.vPPS), zScore(r.BPS, s.bBPS, s.vBPS))
	}
	bMetric := ""
	var bVal, bLvl float64
	if c.Baseline.Enabled && res.ready {
		minPPS := float64(c.Baseline.MinPPS) * ent.scale
		minBPS := float64(c.Baseline.MinBPS) * ent.scale
		if minPPS == 0 && minBPS == 0 {
			minPPS = float64(e.cfg.Engine.SignalMinPPS)
		}
		if minPPS > 0 {
			lvl := math.Max(minPPS, c.Baseline.Factor*s.bPPS)
			if q := r.PPS / lvl; q > res.baseRatio {
				res.baseRatio, bMetric, bVal, bLvl = q, "pps", r.PPS, lvl
			}
		}
		if minBPS > 0 {
			lvl := math.Max(minBPS, c.Baseline.Factor*s.bBPS)
			if q := r.BPS / lvl; q > res.baseRatio {
				res.baseRatio, bMetric, bVal, bLvl = q, "bps", r.BPS, lvl
			}
		}
	}
	res.ratio = math.Max(res.staticRatio, res.baseRatio)
	if res.staticRatio >= res.baseRatio {
		res.kind = "static"
		if metric != "" {
			res.reason = fmt.Sprintf("%s %s ≥ eşik %s", metric, human(val, metric), human(thr, metric))
		}
	} else {
		res.kind = "baseline"
		res.reason = fmt.Sprintf("%s %s ≥ baseline×%.0f (%s)", bMetric, human(bVal, bMetric), c.Baseline.Factor, human(bLvl, bMetric))
	}

	res.condOK = true
	minSamples := c.Conditions.MinSamples
	if minSamples == 0 {
		minSamples = 3
	}
	switch {
	case r.Samples < float64(minSamples):
		res.condOK, res.condFail = false, fmt.Sprintf("örnek sayısı %0.f < %d", r.Samples, minSamples)
	case c.Conditions.MinUniqueSources > 0 && uniq < c.Conditions.MinUniqueSources:
		res.condOK, res.condFail = false, fmt.Sprintf("benzersiz kaynak %d < %d", uniq, c.Conditions.MinUniqueSources)
	case c.Conditions.MinUniqueDests > 0 && c.Scope != "host" && dests < c.Conditions.MinUniqueDests:
		res.condOK, res.condFail = false, fmt.Sprintf("etkilenen benzersiz hedef %d < %d", dests, c.Conditions.MinUniqueDests)
	case c.Conditions.MinAvgPacketSize > 0 && r.AvgPktSize < c.Conditions.MinAvgPacketSize:
		res.condOK, res.condFail = false, fmt.Sprintf("ortalama paket %.0fB < %.0fB", r.AvgPktSize, c.Conditions.MinAvgPacketSize)
	case c.Conditions.MaxAvgPacketSize > 0 && r.AvgPktSize > c.Conditions.MaxAvgPacketSize:
		res.condOK, res.condFail = false, fmt.Sprintf("ortalama paket %.0fB > %.0fB", r.AvgPktSize, c.Conditions.MaxAvgPacketSize)
	}
	res.hit = res.ratio >= 1 && res.condOK
	return res
}

// human formats a rate for messages.
func human(v float64, metric string) string {
	unit := ""
	switch metric {
	case "bps":
		unit = "bps"
	case "pps":
		unit = "pps"
	case "fps":
		unit = "fps"
	}
	switch {
	case v >= 1e9:
		return fmt.Sprintf("%.2fG%s", v/1e9, unit)
	case v >= 1e6:
		return fmt.Sprintf("%.2fM%s", v/1e6, unit)
	case v >= 1e3:
		return fmt.Sprintf("%.1fk%s", v/1e3, unit)
	}
	return fmt.Sprintf("%.0f%s", v, unit)
}

func (e *Engine) targetOf(key seriesKey, c *rules.Compiled) (target, scope string) {
	switch c.Scope {
	case "host":
		return key.pfx.Addr().String(), "host"
	case "prefix":
		return key.pfx.String(), "prefix"
	}
	return e.objs.name(key.obj), "object"
}

// evaluate runs once per second over all series.
func (e *Engine) evaluate(now int64) {
	start := time.Now()
	if e.firstEval == 0 {
		e.firstEval = now
	}
	w := e.window
	learnedIdle := int64(3600)
	var pending []pendingStart
	e.lastSeries = [rules.MaxRules]*series{} // series may be deleted below
	for key, s := range e.series {
		c := e.set.Rules[key.rule]
		ent := e.eff[key.rule][key.obj]
		obj := e.objs.objects[key.obj]
		if !ent.enabled {
			if s.active {
				e.endVector(s, c, now)
			}
			delete(e.series, key)
			continue
		}
		r := s.window(now, w)
		s.recordMinute(now, r)
		uniq, dests := 0, 0
		if s.trackUniques {
			uniq = uniqueCount(s.uniques, now, w)
		}
		if s.trackDests {
			dests = uniqueCount(s.dests, now, w)
		}
		res := e.check(c, ent, s, r, uniq, dests)
		s.lastRate, s.lastRatio = r, res.ratio
		// Unique peers are tracked only for series that approach a threshold.
		s.warm = s.active || res.ratio >= 0.25

		if !s.active {
			// Sustain counts consecutive evaluations over threshold. A single
			// burst that lingers in the sliding window (traffic in only one
			// second) never counts; bursty NetFlow/IPFIX exports spread over
			// several seconds do.
			switch {
			case !res.hit:
				s.over = 0
			case r.ActiveSeconds >= 2:
				s.over++
			}
			target, scope := e.targetOf(key, c)
			sigKey := c.ID + "|" + c.Direction + "|" + target
			switch {
			case s.over >= c.SustainSec && c.Scope == "host" && !c.Generic:
				e.startVector(pendingStart{key, s, c, ent, obj, r, res, uniq, target, scope, sigKey}, now)
			case s.over >= c.SustainSec:
				// Generic and wider-scope vectors are decided after all specific
				// host vectors of this tick (hierarchical correlation).
				pending = append(pending, pendingStart{key, s, c, ent, obj, r, res, uniq, target, scope, sigKey})
			default:
				e.maybeSignal(sigKey, key, c, ent, s, r, res, target, scope, obj, now)
			}
			// Baseline learning is frozen while triggered; outliers are clipped.
			if !res.hit {
				x := r
				if res.ready {
					x.PPS = math.Min(x.PPS, s.bPPS+3*math.Sqrt(s.vPPS)+1)
					x.BPS = math.Min(x.BPS, s.bBPS+3*math.Sqrt(s.vBPS)+1)
				}
				s.updateBaseline(x, e.tau)
			}
			idle := int64(ringSize)
			if res.ready {
				idle = learnedIdle
			}
			if now-s.lastSeen > idle {
				delete(e.series, key)
			}
			continue
		}

		// active vector
		e.incidents.updateVector(s.incident, c.ID, r, uniq, now)
		if res.ratio < 0.7 {
			if s.under == 0 {
				s.under = now
			}
			if now-s.under >= int64(c.HoldDownSec) {
				e.endVector(s, c, now)
			}
		} else {
			s.under = 0
		}
	}
	e.resolvePending(pending, now)
	e.incidents.tick(now)
	e.totals.roll(now)

	// periodic evidence refresh for active incidents
	for _, inc := range e.incidents.List("active", 0) {
		if now-e.lastEvidence[inc.ID] >= int64(e.cfg.Engine.EvidenceEvery.Seconds()) {
			e.lastEvidence[inc.ID] = now
			go e.collectEvidence(inc.ID, "", e.window)
		}
	}
	e.evalMillis = float64(time.Since(start).Microseconds()) / 1000
	e.publish(now)
}

// pendingStart is a vector that reached its sustain time in this tick.
type pendingStart struct {
	key    seriesKey
	s      *series
	c      *rules.Compiled
	ent    effEntry
	obj    *Object
	r      rate
	res    checkResult
	uniq   int
	target string
	scope  string
	sigKey string
}

func scopeTier(p pendingStart) int {
	switch p.c.Scope {
	case "host":
		return 0
	case "prefix":
		if p.c.Generic {
			return 2
		}
		return 1
	}
	return 3
}

// learningSignalRatio: during the engine's initial learning period (after a
// start), near-threshold signals need at least this ratio instead of
// near_miss_ratio.
const learningSignalRatio = 0.8

// coverageThreshold: a generic or wider-scope vector is not reported while
// already-active, more specific vectors explain at least this share of it.
const coverageThreshold = 0.7

// resolvePending starts generic/prefix/object vectors unless covered.
func (e *Engine) resolvePending(pending []pendingStart, now int64) {
	// Narrow before wide: by scope tier, then by rule breadth, so "all UDP"
	// is decided after the specific vectors it may contain started.
	sort.SliceStable(pending, func(i, j int) bool {
		ti, tj := scopeTier(pending[i]), scopeTier(pending[j])
		if ti != tj {
			return ti < tj
		}
		return e.set.Breadth(int(pending[i].key.rule)) < e.set.Breadth(int(pending[j].key.rule))
	})
	for _, p := range pending {
		cov, by := e.coverage(p.key, p.c, p.r)
		if cov >= coverageThreshold {
			p.s.coveredBy = by
			continue
		}
		p.s.coveredBy = ""
		e.startVector(p, now)
	}
}

// coverage returns the share of rate r explained by active, more specific
// vectors (same object) and one incident that explains it. A vector only
// explains this rule if its traffic is a subset of the rule's traffic
// (rules.Set.Within); rates of provably disjoint vectors on one target are
// added, overlapping ones are not double counted.
func (e *Engine) coverage(key seriesKey, c *rules.Compiled, r rate) (float64, string) {
	type vec struct {
		rule     int
		pps, bps float64
	}
	hosts := map[netip.Prefix][]vec{}
	prefixes := map[netip.Prefix][]vec{}
	ci := int(key.rule)
	by := ""
	for k2, s2 := range e.series {
		if !s2.active || k2 == key || k2.obj != key.obj {
			continue
		}
		c2 := e.set.Rules[k2.rule]
		ri := int(k2.rule)
		// Only narrower traffic explains this rule: DNS amp explains "all
		// UDP", TCP SYN never explains UDP. Within one scope a rule with the
		// same match set is not narrower.
		if !e.set.Within(ri, ci) || c2.Scope == c.Scope && e.set.Within(ci, ri) {
			continue
		}
		switch c.Scope {
		case "host": // same host
			if c2.Scope != "host" || k2.pfx != key.pfx {
				continue
			}
		case "prefix": // host vectors inside, or narrower vectors on the same prefix
			switch {
			case c2.Scope == "host" && key.pfx.Contains(k2.pfx.Addr()):
			case c2.Scope == "prefix" && k2.pfx == key.pfx:
			default:
				continue
			}
		default: // object: anything narrower inside the object
			if c2.Scope == "object" {
				continue
			}
		}
		m := hosts
		if c2.Scope == "prefix" {
			m = prefixes
		}
		m[k2.pfx] = append(m[k2.pfx], vec{ri, s2.lastRate.PPS, s2.lastRate.BPS})
		if by == "" {
			by = s2.incident
		}
	}
	// sum adds the largest set of pairwise disjoint vectors of one target.
	sum := func(vs []vec, val func(vec) float64) float64 {
		sort.Slice(vs, func(i, j int) bool { return val(vs[i]) > val(vs[j]) })
		var chosen []int
		total := 0.0
		for _, v := range vs {
			ok := true
			for _, w := range chosen {
				if !e.set.Disjoint(v.rule, w) {
					ok = false
					break
				}
			}
			if ok {
				chosen = append(chosen, v.rule)
				total += val(v)
			}
		}
		return total
	}
	pv := func(v vec) float64 { return v.pps }
	bv := func(v vec) float64 { return v.bps }
	var pps, bps float64
	for p, vs := range prefixes {
		pps += sum(vs, pv)
		bps += sum(vs, bv)
		for h := range hosts { // hosts inside an active prefix are already counted
			if p.Contains(h.Addr()) {
				delete(hosts, h)
			}
		}
	}
	for _, vs := range hosts {
		pps += sum(vs, pv)
		bps += sum(vs, bv)
	}
	cov := 0.0
	if r.PPS > 0 {
		cov = pps / r.PPS
	}
	if r.BPS > 0 {
		cov = math.Max(cov, bps/r.BPS)
	}
	return cov, by
}

// startVector opens (or extends) the incident for a vector.
func (e *Engine) startVector(p pendingStart, now int64) {
	s, c, r, res := p.s, p.c, p.r, p.res
	vs := VectorStart{
		TargetKey: targetKey(c.Direction, p.scope, p.target), Target: p.target, Scope: p.scope, Direction: c.Direction, Object: p.obj,
		Vector: Vector{
			RuleID: c.ID, RuleName: c.Name, Category: c.Category, Severity: c.Severity,
			Reason: res.reason, TriggerKind: res.kind,
			CurPPS: r.PPS, CurBPS: r.BPS, CurFPS: r.FPS, PeakPPS: r.PPS, PeakBPS: r.BPS,
			UniqueSources: p.uniq, AvgPktSize: r.AvgPktSize,
			ThresholdPPS: float64(p.ent.t.PPS), ThresholdBPS: float64(p.ent.t.BPS), ThresholdFPS: float64(p.ent.t.FPS),
			BaselinePPS: s.bPPS, BaselineBPS: s.bBPS, Mitigation: c.Mitigation.Action,
		},
	}
	id, isNew := e.incidents.startVector(vs, now)
	s.active, s.incident, s.under, s.over = true, id, 0, 0
	e.signals.markEscalated(p.sigKey, id)
	e.log.Info("attack vector started", "incident", id, "rule", c.ID, "target", p.target, "reason", res.reason)
	if isNew {
		e.lastEvidence[id] = now
		go e.collectEvidence(id, c.ID, e.window)
	}
}

func (e *Engine) endVector(s *series, c *rules.Compiled, now int64) {
	id := s.incident
	s.active, s.incident, s.under, s.over = false, "", 0, 0
	e.log.Info("attack vector ended", "incident", id, "rule", c.ID)
	if e.incidents.endVector(id, c.ID, now) {
		delete(e.lastEvidence, id)
		e.log.Info("incident ended", "incident", id)
		if e.hooks != nil {
			if inc := e.incidents.Get(id); inc != nil {
				go e.hooks.IncidentEnded(inc)
			}
		}
	}
}

func (e *Engine) maybeSignal(sigKey string, key seriesKey, c *rules.Compiled, ent effEntry, s *series, r rate, res checkResult, target, scope string, obj *Object, now int64) {
	cfg := e.cfg.Engine
	sig := Signal{
		RuleID: c.ID, RuleName: c.Name, Category: c.Category, Scope: scope, Direction: c.Direction,
		Target: target, ObjectID: obj.ID, ObjectName: obj.Name, PeakRatio: res.ratio, PeakZ: res.z,
		CurPPS: r.PPS, CurBPS: r.BPS, BaselinePPS: s.bPPS, BaselineBPS: s.bBPS,
		ThresholdPPS: float64(ent.t.PPS), ThresholdBPS: float64(ent.t.BPS),
	}
	// A rising rate is required for near-threshold signals once the baseline
	// is known: traffic that normally sits near a threshold is a tuning
	// matter (visible in target analysis), not an anomaly. While the
	// baseline is still being learned (e.g. right after a restart) "rising"
	// cannot be judged, so only rates close to the threshold are reported.
	var rising bool
	switch {
	case res.ready:
		rising = r.PPS >= 1.5*s.bPPS || r.BPS >= 1.5*s.bBPS
	case float64(now-e.firstEval) < e.learn:
		// The whole engine is still learning (just started): everything
		// looks new, so only rates close to the threshold are reported.
		rising = res.ratio >= learningSignalRatio
	default:
		// A series that appeared after warm-up has no history: the traffic
		// itself is new.
		rising = true
	}
	switch {
	case res.ratio >= 1 && !res.condOK:
		sig.Kind = "conditions_unmet"
		sig.Condition = res.condFail
		sig.Detail = fmt.Sprintf("Eşik aşıldı (%s) ancak koşul sağlanmadı: %s", res.reason, res.condFail)
	case res.ratio >= cfg.NearMissRatio && rising:
		sig.Kind = "near_threshold"
		if res.ratio >= 1 {
			sig.Detail = fmt.Sprintf("Kısa süreli eşik aşımı (%s), sustain süresi dolmadı", res.reason)
		} else {
			sig.Detail = fmt.Sprintf("Eşiğin %%%.0f seviyesinde (%s)", res.ratio*100, res.reason)
		}
	case res.ready && res.z >= cfg.SignalMinZ &&
		(r.PPS >= 2*s.bPPS || r.BPS >= 2*s.bBPS) &&
		(r.PPS >= float64(cfg.SignalMinPPS) || r.BPS >= float64(cfg.SignalMinBPS)):
		sig.Kind = "baseline_deviation"
		sig.Detail = fmt.Sprintf("Baseline'dan sapma: z=%.1f, %s (baseline %s), %s (baseline %s)",
			res.z, human(r.PPS, "pps"), human(s.bPPS, "pps"), human(r.BPS, "bps"), human(s.bBPS, "bps"))
	default:
		s.devSecs = 0
		return
	}
	// Persistence: short blips are normal at host level and must not wake
	// the analyst.
	s.devSecs++
	if s.devSecs < cfg.SignalMinSeconds {
		return
	}
	sig.RelatedIncident = e.incidents.relatedActive(targetKey(c.Direction, scope, target), c.Direction, scope, target)
	e.signals.observe(sigKey, sig, now)
}

// collectEvidence builds the forensic snapshot for an incident. If newRule is
// set, the VectorStarted hook is invoked once the evidence is available.
func (e *Engine) collectEvidence(id, newRule string, window int64) {
	if _, busy := e.evidenceBusy.LoadOrStore(id, true); busy && newRule == "" {
		return
	}
	defer e.evidenceBusy.Delete(id)
	inc := e.incidents.Get(id)
	if inc == nil {
		return
	}
	pred := e.incidentPredicate(inc)
	f := flowstore.Filter{Seconds: int(window * 3)}
	bd, err := e.store.Breakdown(f, pred, 10)
	if err == nil {
		samples, _ := e.store.Samples(f, pred, 25)
		e.incidents.SetEvidence(id, &Evidence{ComputedAt: time.Now().Unix(), Breakdown: bd, Samples: samples})
	}
	if newRule != "" && e.hooks != nil {
		if cur := e.incidents.Get(id); cur != nil {
			e.hooks.VectorStarted(cur, newRule)
		}
	}
}

// incidentPredicate matches records of the incident's target and vectors.
func (e *Engine) incidentPredicate(inc *Incident) flowstore.Predicate {
	set := e.Rules()
	var rs []*rules.Compiled
	for _, v := range inc.Vectors {
		if c := set.ByID[v.RuleID]; c != nil {
			rs = append(rs, c)
		}
	}
	dir := flow.DirInbound
	if inc.Direction == "outbound" {
		dir = flow.DirOutbound
	}
	var targetMatch func(*flow.Record) bool
	switch inc.Scope {
	case "host":
		a, _ := netip.ParseAddr(inc.Target)
		targetMatch = func(r *flow.Record) bool {
			if dir == flow.DirOutbound {
				return r.Src == a
			}
			return r.Dst == a
		}
	case "prefix":
		p, _ := netip.ParsePrefix(inc.Target)
		targetMatch = func(r *flow.Record) bool {
			if dir == flow.DirOutbound {
				return p.Contains(r.Src)
			}
			return p.Contains(r.Dst)
		}
	default:
		obj := inc.ObjectID
		targetMatch = func(r *flow.Record) bool { return r.ObjectID == obj }
	}
	return func(r *flow.Record) bool {
		if r.Direction != dir || !targetMatch(r) {
			return false
		}
		for _, c := range rs {
			if c.Matches(r) {
				return true
			}
		}
		return len(rs) == 0
	}
}

// IncidentPredicate is exported for the API (flow explorer of an incident).
func (e *Engine) IncidentPredicate(inc *Incident) flowstore.Predicate {
	return e.incidentPredicate(inc)
}

func (e *Engine) publish(now int64) {
	count := e.recordsIn.Load()
	if e.lastCount > 0 || count > 0 {
		e.rps = 0.7*e.rps + 0.3*float64(count-e.lastCount)
	}
	e.lastCount = count
	active, total := e.incidents.Counts()
	n, capacity := e.store.Len()
	activeRules := 0
	for _, c := range e.set.Rules {
		if c.Active {
			activeRules++
		}
	}
	snap := &Snapshot{
		Time: now, WindowSeconds: e.window, Global: e.totals.Window(-1, now, e.window),
		Series: len(e.series), ActiveIncidents: active, TotalIncidents: total,
		PendingSignals: len(e.signals.List(true, 3, 0)),
		RecordsPerSec:  e.rps, RecordsTotal: count, Dropped: e.dropped.Load(), EvalMillis: e.evalMillis,
		FlowStoreLen: n, FlowStoreCap: capacity, OldestFlow: e.store.OldestUnix(),
		Rules: len(e.set.Rules), RulesActive: activeRules,
		SeriesOverflow: e.seriesOverflow.Load(), MaxSeries: e.cfg.Engine.MaxSeries,
	}
	perObj := map[int32]int{}
	for _, inc := range e.incidents.List("active", 0) {
		perObj[inc.ObjectID]++
	}
	for _, o := range e.objs.objects {
		st := ObjectStatus{Object: *o, Rates: e.totals.Window(int(o.ID), now, e.window), ActiveIncidents: perObj[o.ID]}
		if o.LinkCapacity > 0 {
			st.Utilization = st.Rates.InBPS / o.LinkCapacity
		}
		snap.Objects = append(snap.Objects, st)
	}
	e.snap.Store(snap)
}

// ---------------------------------------------------------------- rules admin

// SetRuleOverride persists a runtime override and reloads the rule set.
func (e *Engine) SetRuleOverride(id string, o rules.Override) error {
	e.ovMu.Lock()
	defer e.ovMu.Unlock()
	if _, ok := e.Rules().ByID[id]; !ok {
		return fmt.Errorf("unknown rule %q", id)
	}
	next := map[string]rules.Override{}
	for k, v := range e.overrides {
		next[k] = v
	}
	if o.Enabled == nil && o.PPS == nil && o.BPS == nil && o.FPS == nil {
		delete(next, id)
	} else {
		next[id] = o
	}
	if err := e.reload(next); err != nil {
		return err
	}
	e.overrides = next
	return store.Save(filepath.Join(e.dataDir, "rule_overrides.json"), next)
}

// Overrides returns the current runtime overrides.
func (e *Engine) Overrides() map[string]rules.Override {
	e.ovMu.Lock()
	defer e.ovMu.Unlock()
	out := map[string]rules.Override{}
	for k, v := range e.overrides {
		out[k] = v
	}
	return out
}

// ReloadRules re-reads rule files from disk.
func (e *Engine) ReloadRules() error {
	e.ovMu.Lock()
	defer e.ovMu.Unlock()
	return e.reload(e.overrides)
}

func (e *Engine) reload(ov map[string]rules.Override) error {
	set, err := rules.Load(e.rulesDir, ov)
	if err != nil {
		return err
	}
	for _, o := range e.objsPtr.Load().objects {
		if _, ok := set.Profiles[o.Profile]; !ok {
			return fmt.Errorf("protected object %q uses unknown profile %q", o.Name, o.Profile)
		}
	}
	return e.Do(func() {
		old := e.set
		now := e.clock()
		next := map[seriesKey]*series{}
		for key, s := range e.series {
			oc := old.Rules[key.rule]
			nc, ok := set.ByID[oc.ID]
			if !ok {
				if s.active {
					e.endVector(s, oc, now)
				}
				continue
			}
			key.rule = uint16(nc.Index)
			next[key] = s
		}
		e.series = next
		e.applyRules(set)
	})
}

// EffectiveThresholds returns the effective thresholds of a rule for an object.
func (e *Engine) EffectiveThresholds(ruleID string, obj int32) (rules.Thresholds, bool) {
	set := e.Rules()
	c := set.ByID[ruleID]
	objs := e.objsPtr.Load().objects
	if c == nil || obj < 0 || int(obj) >= len(objs) {
		return rules.Thresholds{}, false
	}
	return set.Effective(c, objs[obj].Profile)
}

// ------------------------------------------------------------- live queries

// TargetRuleState is the live state of one rule for one target.
type TargetRuleState struct {
	RuleID          string  `json:"rule_id"`
	RuleName        string  `json:"rule_name"`
	Scope           string  `json:"scope"`
	Target          string  `json:"target"`
	Direction       string  `json:"direction"`
	ObjectName      string  `json:"object_name"`
	Enabled         bool    `json:"enabled"`
	Active          bool    `json:"active"`
	Incident        string  `json:"incident,omitempty"`
	PPS             float64 `json:"pps"`
	BPS             float64 `json:"bps"`
	FPS             float64 `json:"fps"`
	AvgPktSize      float64 `json:"avg_packet_size"`
	Samples         float64 `json:"samples"`
	Ratio           float64 `json:"ratio"`
	ThresholdPPS    float64 `json:"threshold_pps"`
	ThresholdBPS    float64 `json:"threshold_bps"`
	ThresholdFPS    float64 `json:"threshold_fps"`
	BaselineReady   bool    `json:"baseline_ready"`
	BaselinePPS     float64 `json:"baseline_pps"`
	BaselineBPS     float64 `json:"baseline_bps"`
	BaselineFactor  float64 `json:"baseline_factor,omitempty"`
	SustainSec      int     `json:"sustain_seconds"`
	ConsecutiveOver int     `json:"consecutive_over"`
	MinUnique       int     `json:"min_unique_sources,omitempty"`
	Conditions      string  `json:"conditions"`
	History         []Point `json:"history_minutes,omitempty"`
	Recent          []Point `json:"recent_seconds,omitempty"`
}

// TargetState returns the live state of all rule series whose target contains
// addr (host, carpet prefix and object scope). ruleID filters optionally.
func (e *Engine) TargetState(addr netip.Addr, ruleID string, withHistory bool) ([]TargetRuleState, error) {
	var out []TargetRuleState
	err := e.Do(func() {
		now := e.clock()
		objID := e.objs.lookup(addr)
		for key, s := range e.series {
			if key.obj != objID {
				continue
			}
			c := e.set.Rules[key.rule]
			if ruleID != "" && c.ID != ruleID {
				continue
			}
			if key.pfx.IsValid() && !key.pfx.Contains(addr) {
				continue
			}
			ent := e.eff[key.rule][key.obj]
			r := s.window(now, e.window)
			uniq := len(s.uniques)
			res := e.check(c, ent, s, r, uniq, len(s.dests))
			target, scope := e.targetOf(key, c)
			st := TargetRuleState{
				RuleID: c.ID, RuleName: c.Name, Scope: scope, Target: target, Direction: c.Direction,
				ObjectName: e.objs.name(key.obj), Enabled: ent.enabled, Active: s.active, Incident: s.incident,
				PPS: r.PPS, BPS: r.BPS, FPS: r.FPS, AvgPktSize: r.AvgPktSize, Samples: r.Samples, Ratio: res.ratio,
				ThresholdPPS: float64(ent.t.PPS), ThresholdBPS: float64(ent.t.BPS), ThresholdFPS: float64(ent.t.FPS),
				BaselineReady: res.ready, BaselinePPS: s.bPPS, BaselineBPS: s.bBPS, SustainSec: c.SustainSec,
				ConsecutiveOver: s.over, MinUnique: c.Conditions.MinUniqueSources,
			}
			if c.Baseline.Enabled {
				st.BaselineFactor = c.Baseline.Factor
			}
			if res.condOK {
				st.Conditions = "ok"
			} else {
				st.Conditions = res.condFail
			}
			if withHistory {
				st.History = s.minutes(now)
				st.Recent = s.seconds(now, 60)
			}
			out = append(out, st)
		}
	})
	return out, err
}

// TopSeries returns the series with the highest ratio to their thresholds.
func (e *Engine) TopSeries(limit int) ([]TargetRuleState, error) {
	var out []TargetRuleState
	err := e.Do(func() {
		for key, s := range e.series {
			c := e.set.Rules[key.rule]
			target, scope := e.targetOf(key, c)
			out = append(out, TargetRuleState{
				RuleID: c.ID, RuleName: c.Name, Scope: scope, Target: target, Direction: c.Direction,
				ObjectName: e.objs.name(key.obj), Active: s.active, Incident: s.incident,
				PPS: s.lastRate.PPS, BPS: s.lastRate.BPS, FPS: s.lastRate.FPS, Ratio: s.lastRatio,
				BaselinePPS: s.bPPS, BaselineBPS: s.bBPS, BaselineReady: s.learned >= e.learn,
			})
		}
	})
	if err != nil {
		return nil, err
	}
	sortStates(out)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func sortStates(s []TargetRuleState) {
	sort.Slice(s, func(i, j int) bool { return s[i].Ratio > s[j].Ratio })
}

// SaveJSON is a small helper for other packages persisting under data_dir.
func (e *Engine) SaveJSON(name string, v any) error {
	return store.Save(filepath.Join(e.dataDir, name), v)
}

// LoadJSON loads a file from data_dir.
func (e *Engine) LoadJSON(name string, v any) error {
	return store.Load(filepath.Join(e.dataDir, name), v)
}
