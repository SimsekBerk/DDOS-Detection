package engine

import (
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/flowstore"
)

// Vector is one attack vector (rule) of an incident.
type Vector struct {
	RuleID        string  `json:"rule_id"`
	RuleName      string  `json:"rule_name"`
	Category      string  `json:"category"`
	Severity      string  `json:"severity"`
	Reason        string  `json:"reason"`
	TriggerKind   string  `json:"trigger_kind"` // static | baseline
	StartedAt     int64   `json:"started_at"`
	EndedAt       int64   `json:"ended_at,omitempty"`
	Active        bool    `json:"active"`
	CurPPS        float64 `json:"cur_pps"`
	CurBPS        float64 `json:"cur_bps"`
	CurFPS        float64 `json:"cur_fps"`
	PeakPPS       float64 `json:"peak_pps"`
	PeakBPS       float64 `json:"peak_bps"`
	UniqueSources int     `json:"unique_sources"`
	AvgPktSize    float64 `json:"avg_packet_size"`
	ThresholdPPS  float64 `json:"threshold_pps,omitempty"`
	ThresholdBPS  float64 `json:"threshold_bps,omitempty"`
	ThresholdFPS  float64 `json:"threshold_fps,omitempty"`
	BaselinePPS   float64 `json:"baseline_pps,omitempty"`
	BaselineBPS   float64 `json:"baseline_bps,omitempty"`
	Mitigation    string  `json:"mitigation_action"`
}

// Evidence is a forensic snapshot of the attack traffic.
type Evidence struct {
	ComputedAt int64                  `json:"computed_at"`
	Breakdown  *flowstore.Breakdown   `json:"breakdown"`
	Samples    []flowstore.SampleFlow `json:"samples"`
}

// Incident groups all vectors hitting one target.
type Incident struct {
	ID           string    `json:"id"`
	Target       string    `json:"target"`
	TargetKey    string    `json:"-"`
	Scope        string    `json:"scope"`
	Direction    string    `json:"direction"`
	ObjectID     int32     `json:"object_id"`
	ObjectName   string    `json:"object_name"`
	Profile      string    `json:"profile"`
	LinkCapacity float64   `json:"link_capacity_bps"`
	Status       string    `json:"status"` // active | ended
	Severity     string    `json:"severity"`
	StartedAt    int64     `json:"started_at"`
	UpdatedAt    int64     `json:"updated_at"`
	EndedAt      int64     `json:"ended_at,omitempty"`
	CurPPS       float64   `json:"cur_pps"`
	CurBPS       float64   `json:"cur_bps"`
	PeakPPS      float64   `json:"peak_pps"`
	PeakBPS      float64   `json:"peak_bps"`
	Vectors      []*Vector `json:"vectors"`
	Series       []Point   `json:"series,omitempty"`
	Evidence     *Evidence `json:"evidence,omitempty"`
	Mitigations  []string  `json:"mitigations"`
	Findings     []string  `json:"findings"`
	Reopened     int       `json:"reopened,omitempty"`
}

// Summary returns a copy without heavy fields.
func (i *Incident) Summary() Incident {
	c := *i
	c.Series = nil
	c.Evidence = nil
	c.Vectors = copyVectors(i.Vectors)
	c.Mitigations = append([]string{}, i.Mitigations...)
	c.Findings = append([]string{}, i.Findings...)
	return c
}

func (i *Incident) clone() *Incident {
	c := i.Summary()
	c.Series = append([]Point{}, i.Series...)
	c.Evidence = i.Evidence // evidence is replaced, never mutated in place
	return &c
}

func copyVectors(vs []*Vector) []*Vector {
	out := make([]*Vector, len(vs))
	for k, v := range vs {
		c := *v
		out[k] = &c
	}
	return out
}

func targetKey(direction, scope, target string) string {
	return direction + "|" + scope + "|" + target
}

var severityRank = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

// Incidents is the incident store. Safe for concurrent use.
type Incidents struct {
	mu       sync.RWMutex
	byID     map[string]*Incident
	byTarget map[string]string
	seq      int
	reopen   int64
	dirty    bool
	maxKeep  int
}

func newIncidents(reopen time.Duration) *Incidents {
	return &Incidents{byID: map[string]*Incident{}, byTarget: map[string]string{}, reopen: int64(reopen.Seconds()), maxKeep: 1000}
}

// VectorStart describes a newly triggered vector.
type VectorStart struct {
	TargetKey, Target, Scope, Direction string
	Object                              *Object
	Vector                              Vector
}

// startVector opens (or extends/reopens) the incident for a target and adds
// the vector. It returns the incident id and whether the vector is new.
func (s *Incidents) startVector(v VectorStart, now int64) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dirty = true
	var inc *Incident
	if id, ok := s.byTarget[v.TargetKey]; ok {
		if cur := s.byID[id]; cur != nil && (cur.Status == "active" || now-cur.EndedAt <= s.reopen) {
			inc = cur
			if inc.Status != "active" {
				inc.Status = "active"
				inc.EndedAt = 0
				inc.Reopened++
			}
		}
	}
	if inc == nil {
		s.seq++
		inc = &Incident{
			ID:     fmt.Sprintf("INC-%s-%04d", time.Unix(now, 0).Format("060102"), s.seq),
			Target: v.Target, TargetKey: v.TargetKey, Scope: v.Scope, Direction: v.Direction,
			ObjectID: v.Object.ID, ObjectName: v.Object.Name, Profile: v.Object.Profile, LinkCapacity: v.Object.LinkCapacity,
			Status: "active", StartedAt: now, Mitigations: []string{}, Findings: []string{},
		}
		s.byID[inc.ID] = inc
		s.byTarget[v.TargetKey] = inc.ID
		s.prune()
	}
	inc.UpdatedAt = now
	for _, existing := range inc.Vectors {
		if existing.RuleID == v.Vector.RuleID {
			if existing.Active {
				return inc.ID, false
			}
			*existing = v.Vector
			existing.Active = true
			existing.StartedAt = now
			s.recomputeSeverity(inc)
			return inc.ID, true
		}
	}
	vec := v.Vector
	vec.Active = true
	vec.StartedAt = now
	inc.Vectors = append(inc.Vectors, &vec)
	s.recomputeSeverity(inc)
	return inc.ID, true
}

func (s *Incidents) recomputeSeverity(inc *Incident) {
	sev := "low"
	for _, v := range inc.Vectors {
		if severityRank[v.Severity] > severityRank[sev] {
			sev = v.Severity
		}
	}
	if inc.LinkCapacity > 0 && inc.PeakBPS >= 0.5*inc.LinkCapacity {
		sev = "critical"
	}
	inc.Severity = sev
}

// updateVector refreshes live statistics of an active vector.
func (s *Incidents) updateVector(id, rule string, r rate, uniques int, now int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inc := s.byID[id]
	if inc == nil {
		return
	}
	for _, v := range inc.Vectors {
		if v.RuleID == rule && v.Active {
			v.CurPPS, v.CurBPS, v.CurFPS = r.PPS, r.BPS, r.FPS
			v.AvgPktSize = r.AvgPktSize
			if uniques > 0 {
				v.UniqueSources = uniques
			}
			if r.PPS > v.PeakPPS {
				v.PeakPPS = r.PPS
			}
			if r.BPS > v.PeakBPS {
				v.PeakBPS = r.BPS
			}
		}
	}
	inc.UpdatedAt = now
}

// tick appends the per-second incident series (max over active vectors).
func (s *Incidents) tick(now int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, inc := range s.byID {
		if inc.Status != "active" {
			continue
		}
		var p Point
		p.T = now
		for _, v := range inc.Vectors {
			if !v.Active {
				continue
			}
			if v.CurBPS > p.BPS {
				p.BPS = v.CurBPS
			}
			if v.CurPPS > p.PPS {
				p.PPS = v.CurPPS
			}
		}
		inc.CurBPS, inc.CurPPS = p.BPS, p.PPS
		if p.BPS > inc.PeakBPS {
			inc.PeakBPS = p.BPS
			s.recomputeSeverity(inc)
		}
		if p.PPS > inc.PeakPPS {
			inc.PeakPPS = p.PPS
		}
		inc.Series = append(inc.Series, p)
		if len(inc.Series) > 3600 {
			inc.Series = inc.Series[len(inc.Series)-3600:]
		}
		s.dirty = true
	}
}

// endVector marks a vector finished; returns true if the whole incident ended.
func (s *Incidents) endVector(id, rule string, now int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	inc := s.byID[id]
	if inc == nil {
		return false
	}
	s.dirty = true
	anyActive := false
	for _, v := range inc.Vectors {
		if v.RuleID == rule && v.Active {
			v.Active = false
			v.EndedAt = now
			v.CurBPS, v.CurPPS, v.CurFPS = 0, 0, 0
		}
		if v.Active {
			anyActive = true
		}
	}
	if !anyActive && inc.Status == "active" {
		inc.Status = "ended"
		inc.EndedAt = now
		inc.CurBPS, inc.CurPPS = 0, 0
		return true
	}
	return false
}

func (s *Incidents) prune() {
	if len(s.byID) <= s.maxKeep {
		return
	}
	var ended []*Incident
	for _, i := range s.byID {
		if i.Status == "ended" {
			ended = append(ended, i)
		}
	}
	sort.Slice(ended, func(a, b int) bool { return ended[a].EndedAt < ended[b].EndedAt })
	for _, i := range ended[:len(s.byID)-s.maxKeep] {
		delete(s.byID, i.ID)
		if s.byTarget[i.TargetKey] == i.ID {
			delete(s.byTarget, i.TargetKey)
		}
	}
}

// List returns incident summaries, newest first.
func (s *Incidents) List(status string, limit int) []Incident {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Incident, 0, len(s.byID))
	for _, i := range s.byID {
		if status != "" && i.Status != status {
			continue
		}
		out = append(out, i.Summary())
	}
	sort.Slice(out, func(a, b int) bool {
		if (out[a].Status == "active") != (out[b].Status == "active") {
			return out[a].Status == "active"
		}
		return out[a].StartedAt > out[b].StartedAt
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Get returns a deep copy of an incident.
func (s *Incidents) Get(id string) *Incident {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if i := s.byID[id]; i != nil {
		return i.clone()
	}
	return nil
}

// SetEvidence replaces the forensic snapshot.
func (s *Incidents) SetEvidence(id string, ev *Evidence) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i := s.byID[id]; i != nil {
		i.Evidence = ev
		s.dirty = true
	}
}

// AttachMitigation records a mitigation id on the incident.
func (s *Incidents) AttachMitigation(id, mitID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i := s.byID[id]; i != nil {
		i.Mitigations = append(i.Mitigations, mitID)
		s.dirty = true
	}
}

// AttachFinding records an analyst finding id on the incident.
func (s *Incidents) AttachFinding(id, findingID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i := s.byID[id]; i != nil {
		i.Findings = append(i.Findings, findingID)
		s.dirty = true
	}
}

// relatedActive returns an active incident on the same target key, or, for a
// prefix target, an active host incident inside that prefix.
func (s *Incidents) relatedActive(key, direction, scope, target string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if id, ok := s.byTarget[key]; ok {
		if inc := s.byID[id]; inc != nil && inc.Status == "active" {
			return id
		}
	}
	if scope != "prefix" {
		return ""
	}
	p, err := netip.ParsePrefix(target)
	if err != nil {
		return ""
	}
	for _, inc := range s.byID {
		if inc.Status != "active" || inc.Scope != "host" || inc.Direction != direction {
			continue
		}
		if a, err := netip.ParseAddr(inc.Target); err == nil && p.Contains(a) {
			return inc.ID
		}
	}
	return ""
}

// Counts returns active and total incident counts.
func (s *Incidents) Counts() (active, total int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, i := range s.byID {
		if i.Status == "active" {
			active++
		}
	}
	return active, len(s.byID)
}

type incidentsDump struct {
	Seq       int         `json:"seq"`
	Incidents []*Incident `json:"incidents"`
}

func (s *Incidents) dump() (incidentsDump, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return incidentsDump{}, false
	}
	s.dirty = false
	d := incidentsDump{Seq: s.seq}
	for _, i := range s.byID {
		d.Incidents = append(d.Incidents, i.clone())
	}
	return d, true
}

func (s *Incidents) restore(d incidentsDump, now int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq = d.Seq
	for _, i := range d.Incidents {
		if i.Status == "active" { // the process restarted; we can no longer observe it
			i.Status = "ended"
			i.EndedAt = now
			for _, v := range i.Vectors {
				if v.Active {
					v.Active = false
					v.EndedAt = now
				}
			}
		}
		i.TargetKey = targetKey(i.Direction, i.Scope, i.Target)
		s.byID[i.ID] = i
	}
}
