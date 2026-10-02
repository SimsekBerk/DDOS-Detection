package engine

import (
	"fmt"
	"sort"
	"sync"
)

// Signal is a "near miss": traffic that deviates from normal or approaches a
// threshold but did not (yet) trigger an incident. Signals feed the AI analyst.
type Signal struct {
	ID           string  `json:"id"`
	Kind         string  `json:"kind"` // near_threshold | baseline_deviation | conditions_unmet
	RuleID       string  `json:"rule_id"`
	RuleName     string  `json:"rule_name"`
	Category     string  `json:"category"`
	Scope        string  `json:"scope"`
	Direction    string  `json:"direction"`
	Target       string  `json:"target"`
	ObjectID     int32   `json:"object_id"`
	ObjectName   string  `json:"object_name"`
	FirstSeen    int64   `json:"first_seen"`
	LastSeen     int64   `json:"last_seen"`
	Seconds      int     `json:"seconds"`
	PeakRatio    float64 `json:"peak_ratio"` // max(rate/threshold)
	PeakZ        float64 `json:"peak_z"`
	PeakPPS      float64 `json:"peak_pps"`
	PeakBPS      float64 `json:"peak_bps"`
	CurPPS       float64 `json:"cur_pps"`
	CurBPS       float64 `json:"cur_bps"`
	BaselinePPS  float64 `json:"baseline_pps"`
	BaselineBPS  float64 `json:"baseline_bps"`
	ThresholdPPS float64 `json:"threshold_pps,omitempty"`
	ThresholdBPS float64 `json:"threshold_bps,omitempty"`
	Detail       string  `json:"detail"`
	Condition    string  `json:"condition,omitempty"` // failed condition for conditions_unmet
	// RelatedIncident is an active incident on the same target (or a host
	// inside this prefix); such signals are usually explained by it.
	RelatedIncident string `json:"related_incident,omitempty"`
	Analyzed        bool   `json:"analyzed"`
	FindingID       string `json:"finding_id,omitempty"`
	Escalated       string `json:"escalated_incident,omitempty"`
}

// Signals stores recent near-miss signals. Safe for concurrent use.
type Signals struct {
	mu    sync.RWMutex
	byKey map[string]*Signal
	byID  map[string]*Signal
	seq   int
	max   int
	gap   int64
}

func newSignals() *Signals {
	return &Signals{byKey: map[string]*Signal{}, byID: map[string]*Signal{}, max: 500, gap: 120}
}

// observe merges an observation into an existing signal for the same
// (rule, target) or creates a new one.
func (s *Signals) observe(key string, o Signal, now int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur := s.byKey[key]; cur != nil && now-cur.LastSeen <= s.gap {
		cur.LastSeen = now
		cur.Seconds++
		cur.CurPPS, cur.CurBPS = o.CurPPS, o.CurBPS
		cur.BaselinePPS, cur.BaselineBPS = o.BaselinePPS, o.BaselineBPS
		if o.PeakRatio > cur.PeakRatio {
			cur.PeakRatio = o.PeakRatio
		}
		if o.PeakZ > cur.PeakZ {
			cur.PeakZ = o.PeakZ
		}
		if o.CurPPS > cur.PeakPPS {
			cur.PeakPPS = o.CurPPS
		}
		if o.CurBPS > cur.PeakBPS {
			cur.PeakBPS = o.CurBPS
		}
		// A stronger kind replaces a weaker one; detail follows the latest.
		if kindRank(o.Kind) >= kindRank(cur.Kind) {
			cur.Kind = o.Kind
			cur.Detail = o.Detail
			cur.Condition = o.Condition
		}
		cur.RelatedIncident = o.RelatedIncident
		if cur.Analyzed && now-cur.FirstSeen > 600 {
			cur.Analyzed = false // long-running: allow a fresh analysis
		}
		return
	}
	s.seq++
	o.ID = fmt.Sprintf("SIG-%05d", s.seq)
	o.FirstSeen, o.LastSeen, o.Seconds = now, now, 1
	o.PeakPPS, o.PeakBPS = o.CurPPS, o.CurBPS
	sig := o
	s.byKey[key] = &sig
	s.byID[sig.ID] = &sig
	if len(s.byID) > s.max {
		s.evict()
	}
}

func kindRank(k string) int {
	switch k {
	case "conditions_unmet":
		return 3
	case "near_threshold":
		return 2
	}
	return 1
}

func (s *Signals) evict() {
	all := make([]*Signal, 0, len(s.byID))
	for _, v := range s.byID {
		all = append(all, v)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].LastSeen < all[j].LastSeen })
	for _, v := range all[:len(all)-s.max] {
		delete(s.byID, v.ID)
		for k, p := range s.byKey {
			if p == v {
				delete(s.byKey, k)
			}
		}
	}
}

// markEscalated links a signal to the incident it turned into.
func (s *Signals) markEscalated(key, incident string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur := s.byKey[key]; cur != nil {
		cur.Escalated = incident
	}
}

// List returns signals newest first. minSeconds filters out one-off blips.
func (s *Signals) List(onlyPending bool, minSeconds int, limit int) []Signal {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Signal{}
	for _, v := range s.byID {
		if onlyPending && (v.Analyzed || v.Escalated != "") {
			continue
		}
		if v.Seconds < minSeconds {
			continue
		}
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen > out[j].LastSeen })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Get returns a signal by id.
func (s *Signals) Get(id string) (Signal, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if v := s.byID[id]; v != nil {
		return *v, true
	}
	return Signal{}, false
}

// MarkAnalyzed links signals to a finding.
func (s *Signals) MarkAnalyzed(ids []string, findingID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		if v := s.byID[id]; v != nil {
			v.Analyzed = true
			v.FindingID = findingID
		}
	}
}
