package engine

import (
	"math"
	"net/netip"

	"github.com/SimsekBerk/DDOS-Detection/internal/flow"
)

// ringSize is the number of 1-second buckets kept per series. It must cover
// the evaluation window plus the maximum flow spread.
const ringSize = 64

// maxUniqueTracked caps the per-series unique-source set.
const maxUniqueTracked = 4096

// bucket holds one second of traffic. float32 keeps the ring compact (a
// provider tracks hundreds of thousands of series); 24 bits of mantissa are
// ample for per-second rates.
type bucket struct {
	bytes, packets, flows, samples float32
}

// rate is a windowed rate.
type rate struct {
	BPS, PPS, FPS float64
	Samples       float64
	AvgPktSize    float64
	ActiveSeconds int // buckets in the window that received traffic
}

type seriesKey struct {
	rule uint16
	obj  int32
	pfx  netip.Prefix // host /32-/128, carpet prefix, or zero for object scope
}

// series tracks one (rule, target) pair.
type series struct {
	ring  [ringSize]bucket
	stamp [ringSize]uint32 // unix second of each bucket

	shard        uint16 // index in seriesTable.shards
	trackUniques bool
	warm         bool // near a threshold: track unique peers
	uniques      map[netip.Addr]int64
	trackDests   bool
	dests        map[netip.Addr]int64

	lastSeen int64

	// EWMA baseline of the windowed rate.
	bPPS, vPPS, bBPS, vBPS float64
	learned                float64

	// per-minute history for analyst/UI drill-down; allocated only once the
	// series gets near a threshold or is under attack
	hist *minuteHist

	// trigger state
	devSecs   int // consecutive seconds with a signal-worthy deviation
	over      int
	under     int64
	active    bool
	incident  string
	coveredBy string // incident explaining this (suppressed) generic/wider vector
	lastRate  rate
	lastRatio float64
}

type minuteHist struct {
	t        [60]int64
	pps, bps [60]float64
	accPPS   float64
	accBPS   float64
	accN     float64
	accMin   int64
}

// bucketAt returns the bucket for second t, or nil if the slot already holds
// a newer second (t is too old for the ring).
func (s *series) bucketAt(t int64) *bucket {
	i := t % ringSize
	st := int64(s.stamp[i])
	if st > t {
		return nil
	}
	if st != t {
		s.stamp[i] = uint32(t)
		s.ring[i] = bucket{}
	}
	return &s.ring[i]
}

// add accumulates a record into the ring, spreading long flows over their duration.
func (s *series) add(r *flow.Record, now int64, maxSpread int64, peer, target netip.Addr) {
	bytes := r.ScaledBytes()
	pkts := r.ScaledPackets()
	d := int64(r.DurationMs+999) / 1000
	if d < 1 {
		d = 1
	}
	if d > maxSpread {
		d = maxSpread
	}
	fb, fp := float32(bytes/float64(d)), float32(pkts/float64(d))
	for t := now - d + 1; t <= now; t++ {
		if b := s.bucketAt(t); b != nil {
			b.bytes += fb
			b.packets += fp
		}
	}
	if last := s.bucketAt(now); last != nil {
		last.samples++
		if r.Source != flow.SourceSFlow {
			last.flows++
		}
	}
	s.lastSeen = now
	if s.trackUniques && s.warm && peer.IsValid() {
		if s.uniques == nil {
			s.uniques = make(map[netip.Addr]int64)
		}
		if _, ok := s.uniques[peer]; ok || len(s.uniques) < maxUniqueTracked {
			s.uniques[peer] = now
		}
	}
	if s.trackDests && s.warm && target.IsValid() {
		if s.dests == nil {
			s.dests = make(map[netip.Addr]int64)
		}
		if _, ok := s.dests[target]; ok || len(s.dests) < maxUniqueTracked {
			s.dests[target] = now
		}
	}
}

// window returns the rate over the complete seconds [now-w, now-1].
func (s *series) window(now int64, w int64) rate {
	var bytes, packets, flows, samples float64
	active := 0
	for t := now - w; t < now; t++ {
		i := t % ringSize
		if int64(s.stamp[i]) == t {
			b := &s.ring[i]
			bytes += float64(b.bytes)
			packets += float64(b.packets)
			flows += float64(b.flows)
			samples += float64(b.samples)
			if b.packets > 0 {
				active++
			}
		}
	}
	r := rate{BPS: bytes * 8 / float64(w), PPS: packets / float64(w), FPS: flows / float64(w), Samples: samples, ActiveSeconds: active}
	if packets > 0 {
		r.AvgPktSize = bytes / packets
	}
	return r
}

// uniqueCount counts addresses seen within the window and prunes older ones.
func uniqueCount(m map[netip.Addr]int64, now, w int64) int {
	n := 0
	for a, t := range m {
		if t < now-w {
			delete(m, a)
			continue
		}
		n++
	}
	return n
}

// updateBaseline folds the current rate into the EWMA mean/variance.
func (s *series) updateBaseline(r rate, tauSec float64) {
	alpha := 1 / tauSec
	if s.learned < tauSec {
		// Warm-up: behave like a running mean until we have tau samples.
		alpha = 1 / (s.learned + 1)
	}
	ewma(&s.bPPS, &s.vPPS, r.PPS, alpha)
	ewma(&s.bBPS, &s.vBPS, r.BPS, alpha)
	s.learned++
}

func ewma(mean, variance *float64, x, alpha float64) {
	diff := x - *mean
	incr := alpha * diff
	*mean += incr
	*variance = (1 - alpha) * (*variance + diff*incr)
}

// zScore returns how many standard deviations x is above the mean. A variance
// floor (10% of the mean) prevents huge scores on very flat baselines.
func zScore(x, mean, variance float64) float64 {
	sd := math.Sqrt(variance)
	if floor := 0.1*mean + 1; sd < floor {
		sd = floor
	}
	return (x - mean) / sd
}

// recordMinute accumulates per-second rates into the minute history. Cold
// series (far below every threshold) keep none.
func (s *series) recordMinute(now int64, r rate) {
	h := s.hist
	if h == nil {
		if !s.warm && !s.active {
			return
		}
		h = &minuteHist{}
		s.hist = h
	}
	m := now / 60
	if h.accMin != m && h.accN > 0 {
		i := h.accMin % 60
		h.t[i] = h.accMin * 60
		h.pps[i] = h.accPPS / h.accN
		h.bps[i] = h.accBPS / h.accN
		h.accPPS, h.accBPS, h.accN = 0, 0, 0
	}
	h.accMin = m
	h.accPPS += r.PPS
	h.accBPS += r.BPS
	h.accN++
}

// Point is a time series point.
type Point struct {
	T   int64   `json:"t"`
	BPS float64 `json:"bps"`
	PPS float64 `json:"pps"`
	FPS float64 `json:"fps,omitempty"`
}

// seconds returns per-second points for the last n seconds (n <= ringSize).
func (s *series) seconds(now int64, n int64) []Point {
	if n > ringSize-1 {
		n = ringSize - 1
	}
	out := make([]Point, 0, n)
	for t := now - n; t < now; t++ {
		i := t % ringSize
		p := Point{T: t}
		if int64(s.stamp[i]) == t {
			p.BPS = float64(s.ring[i].bytes) * 8
			p.PPS = float64(s.ring[i].packets)
			p.FPS = float64(s.ring[i].flows)
		}
		out = append(out, p)
	}
	return out
}

// minutes returns the per-minute history, oldest first.
func (s *series) minutes(now int64) []Point {
	var out []Point
	h := s.hist
	if h == nil {
		return out
	}
	cur := now / 60
	for m := cur - 59; m < cur; m++ {
		i := m % 60
		if h.t[i] == m*60 {
			out = append(out, Point{T: m * 60, BPS: h.bps[i], PPS: h.pps[i]})
		}
	}
	return out
}
