package engine

import (
	"sync"

	"github.com/SimsekBerk/DDOS-Detection/internal/flow"
)

const (
	histSeconds = 3600 // 1h at 1s resolution
	histMinutes = 1440 // 24h at 1m resolution
)

// counters is one time slot of traffic totals.
type counters struct {
	InB, InP, InF    float64
	OutB, OutP, OutF float64
	OthB, OthP       float64
	Proto            [4]float64 // inbound bytes: tcp, udp, icmp, other
}

func (c *counters) add(o *counters, scale float64) {
	c.InB += o.InB * scale
	c.InP += o.InP * scale
	c.InF += o.InF * scale
	c.OutB += o.OutB * scale
	c.OutP += o.OutP * scale
	c.OutF += o.OutF * scale
	c.OthB += o.OthB * scale
	c.OthP += o.OthP * scale
	for i := range c.Proto {
		c.Proto[i] += o.Proto[i] * scale
	}
}

type history struct {
	sec     [histSeconds]counters
	secT    [histSeconds]int64
	min     [histMinutes]counters // per-second averages over the minute
	minT    [histMinutes]int64
	lastMin int64
}

func (h *history) slot(t int64) *counters {
	i := t % histSeconds
	if h.secT[i] > t {
		return nil
	}
	if h.secT[i] != t {
		h.secT[i] = t
		h.sec[i] = counters{}
	}
	return &h.sec[i]
}

// rollMinute stores the average of the previous complete minute.
func (h *history) rollMinute(now int64) {
	m := now/60 - 1
	if m <= h.lastMin {
		return
	}
	h.lastMin = m
	var sum counters
	for t := m * 60; t < m*60+60; t++ {
		i := t % histSeconds
		if h.secT[i] == t {
			sum.add(&h.sec[i], 1.0/60)
		}
	}
	i := m % histMinutes
	h.min[i] = sum
	h.minT[i] = m * 60
}

// Totals keeps global and per-object traffic history. Safe for concurrent use.
type Totals struct {
	mu      sync.RWMutex
	global  *history
	objects []*history
}

func newTotals(objects int) *Totals {
	t := &Totals{global: &history{}}
	for i := 0; i < objects; i++ {
		t.objects = append(t.objects, &history{})
	}
	return t
}

func protoIndex(p uint8) int {
	switch p {
	case flow.ProtoTCP:
		return 0
	case flow.ProtoUDP:
		return 1
	case flow.ProtoICMP, flow.ProtoICMPv6:
		return 2
	}
	return 3
}

// addLocked spreads a record over its duration. Caller holds t.mu.
func (t *Totals) addLocked(r *flow.Record, now, maxSpread int64) {
	d := int64(r.DurationMs+999) / 1000
	if d < 1 {
		d = 1
	}
	if d > maxSpread {
		d = maxSpread
	}
	b := r.ScaledBytes() / float64(d)
	p := r.ScaledPackets() / float64(d)
	var obj *history
	if r.ObjectID >= 0 && int(r.ObjectID) < len(t.objects) {
		obj = t.objects[r.ObjectID]
	}
	for s := now - d + 1; s <= now; s++ {
		for _, h := range []*history{t.global, obj} {
			if h == nil {
				continue
			}
			c := h.slot(s)
			if c == nil {
				continue
			}
			switch r.Direction {
			case flow.DirInbound:
				c.InB += b
				c.InP += p
				c.Proto[protoIndex(r.Protocol)] += b
			case flow.DirOutbound:
				c.OutB += b
				c.OutP += p
			default:
				c.OthB += b
				c.OthP += p
			}
			if s == now && r.Source != flow.SourceSFlow {
				switch r.Direction {
				case flow.DirInbound:
					c.InF++
				case flow.DirOutbound:
					c.OutF++
				}
			}
		}
	}
}

func (t *Totals) roll(now int64) {
	t.mu.Lock()
	t.global.rollMinute(now)
	for _, h := range t.objects {
		h.rollMinute(now)
	}
	t.mu.Unlock()
}

// TotalPoint is a point of the traffic history.
type TotalPoint struct {
	T        int64   `json:"t"`
	InBPS    float64 `json:"in_bps"`
	InPPS    float64 `json:"in_pps"`
	InFPS    float64 `json:"in_fps"`
	OutBPS   float64 `json:"out_bps"`
	OutPPS   float64 `json:"out_pps"`
	OtherBPS float64 `json:"other_bps"`
	TCP      float64 `json:"tcp_bps"`
	UDP      float64 `json:"udp_bps"`
	ICMP     float64 `json:"icmp_bps"`
	OtherP   float64 `json:"other_proto_bps"`
}

func toPoint(t int64, c *counters) TotalPoint {
	return TotalPoint{
		T: t, InBPS: c.InB * 8, InPPS: c.InP, InFPS: c.InF, OutBPS: c.OutB * 8, OutPPS: c.OutP, OtherBPS: c.OthB * 8,
		TCP: c.Proto[0] * 8, UDP: c.Proto[1] * 8, ICMP: c.Proto[2] * 8, OtherP: c.Proto[3] * 8,
	}
}

// Series returns traffic history. obj < 0 selects global totals. For ranges
// up to one hour, per-second data is averaged into step-second points;
// longer ranges use minute data.
func (t *Totals) Series(obj int, now int64, rangeSec, step int64) []TotalPoint {
	t.mu.RLock()
	defer t.mu.RUnlock()
	h := t.global
	if obj >= 0 {
		if obj >= len(t.objects) {
			return nil
		}
		h = t.objects[obj]
	}
	if step < 1 {
		step = 1
	}
	var out []TotalPoint
	if rangeSec <= histSeconds {
		end := now // exclude the current (partial) second
		start := end - rangeSec
		start -= start % step
		for s := start; s < end; s += step {
			var sum counters
			for k := s; k < s+step && k < end; k++ {
				i := k % histSeconds
				if h.secT[i] == k {
					sum.add(&h.sec[i], 1/float64(step))
				}
			}
			out = append(out, toPoint(s, &sum))
		}
		return out
	}
	if step < 60 {
		step = 60
	}
	cur := now / 60
	startM := cur - rangeSec/60
	stepM := step / 60
	startM -= startM % stepM
	for m := startM; m < cur; m += stepM {
		var sum counters
		for k := m; k < m+stepM && k < cur; k++ {
			i := k % histMinutes
			if h.minT[i] == k*60 {
				sum.add(&h.min[i], 1/float64(stepM))
			}
		}
		out = append(out, toPoint(m*60, &sum))
	}
	return out
}

// Window returns average rates over the last w complete seconds.
func (t *Totals) Window(obj int, now, w int64) TotalPoint {
	t.mu.RLock()
	defer t.mu.RUnlock()
	h := t.global
	if obj >= 0 {
		if obj >= len(t.objects) {
			return TotalPoint{}
		}
		h = t.objects[obj]
	}
	var sum counters
	for k := now - w; k < now; k++ {
		i := k % histSeconds
		if h.secT[i] == k {
			sum.add(&h.sec[i], 1/float64(w))
		}
	}
	return toPoint(now, &sum)
}
