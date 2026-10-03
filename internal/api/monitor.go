package api

import (
	"net/http"
	"net/netip"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/auth"
	"github.com/SimsekBerk/DDOS-Detection/internal/engine"
	"github.com/SimsekBerk/DDOS-Detection/internal/flow"
	"github.com/SimsekBerk/DDOS-Detection/internal/flowstore"
	"github.com/SimsekBerk/DDOS-Detection/internal/rules"
)

// ------------------------------------------------------------ tenant scope

// scope returns the object ids a user may see (nil = all).
func (s *Server) scope(u *auth.User) map[int32]bool {
	if !u.Scoped() {
		return nil
	}
	m := map[int32]bool{}
	for _, o := range s.app.Eng.Objects() {
		if u.AllowsObject(o.Name) {
			m[o.ID] = true
		}
	}
	return m
}

// allowsTarget checks an IP or prefix against the user's scope.
func (s *Server) allowsTarget(u *auth.User, target string) bool {
	if !u.Scoped() {
		return true
	}
	var a netip.Addr
	if p, err := netip.ParsePrefix(target); err == nil {
		a = p.Addr()
	} else if x, err := netip.ParseAddr(target); err == nil {
		a = x
	} else {
		return u.AllowsObject(target) // object-scope incidents use the object name
	}
	o := s.app.Eng.LookupObject(a)
	return o != nil && u.AllowsObject(o.Name)
}

func scopePredicate(allowed map[int32]bool) flowstore.Predicate {
	if allowed == nil {
		return nil
	}
	return func(r *flow.Record) bool { return allowed[r.ObjectID] }
}

func addPoint(a *engine.TotalPoint, b engine.TotalPoint) {
	a.InBPS += b.InBPS
	a.InPPS += b.InPPS
	a.InFPS += b.InFPS
	a.OutBPS += b.OutBPS
	a.OutPPS += b.OutPPS
	a.OtherBPS += b.OtherBPS
	a.TCP += b.TCP
	a.UDP += b.UDP
	a.ICMP += b.ICMP
	a.OtherP += b.OtherP
}

// ------------------------------------------------------------ handlers

func (s *Server) overview(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	snap := *s.app.Eng.Snapshot()
	allowed := s.scope(u)
	pending, active := s.app.Mit.Counts()
	if allowed != nil {
		var objs []engine.ObjectStatus
		var g engine.TotalPoint
		for _, o := range snap.Objects {
			if allowed[o.ID] {
				objs = append(objs, o)
				addPoint(&g, o.Rates)
			}
		}
		g.T = snap.Global.T
		snap.Objects, snap.Global = objs, g
		snap.ActiveIncidents, snap.TotalIncidents = 0, 0
		for _, inc := range s.app.Eng.Incidents().List("", 0) {
			if u.AllowsObject(inc.ObjectName) {
				snap.TotalIncidents++
				if inc.Status == "active" {
					snap.ActiveIncidents++
				}
			}
		}
		snap.PendingSignals = 0
		pending, active = 0, 0
		for _, m := range s.app.Mit.List("") {
			if s.allowsTarget(u, m.Target) {
				switch m.Status {
				case "pending":
					pending++
				case "active":
					active++
				}
			}
		}
	}
	cfg := s.app.Config()
	exps := s.app.Col.Exporters()
	now := time.Now().Unix()
	up := 0
	for _, e := range exps {
		if now-e.LastSeen < 60 {
			up++
		}
	}
	out := map[string]any{
		"version": Version, "uptime": now - s.app.Started, "engine": snap,
		"mitigation": map[string]any{"pending": pending, "active": active, "mode": s.app.Mit.Mode(), "driver": s.app.Mit.DriverName()},
		"analyst":    s.app.Ana.Status(), "demo": s.app.Sim != nil, "restart_pending": s.app.RestartPending(),
	}
	if allowed == nil {
		out["exporters_total"], out["exporters_up"], out["listening"] = len(exps), up, s.app.Col.Listening()
		out["mitigation_driver"] = cfg.Mitigation.Driver
	}
	return out, nil
}

func (s *Server) timeseries(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	rng := int64(qInt(r, "range", 900))
	step := int64(qInt(r, "step", 0))
	if step <= 0 {
		step = max(1, rng/240)
	}
	now := time.Now().Unix()
	if name := r.URL.Query().Get("object"); name != "" {
		o := s.app.Eng.ObjectByName(name)
		if o == nil || !u.AllowsObject(name) {
			return nil, notFound("nesne bulunamadı")
		}
		return s.app.Eng.Totals().Series(int(o.ID), now, rng, step), nil
	}
	allowed := s.scope(u)
	if allowed == nil {
		return s.app.Eng.Totals().Series(-1, now, rng, step), nil
	}
	var sum []engine.TotalPoint
	for id := range allowed {
		pts := s.app.Eng.Totals().Series(int(id), now, rng, step)
		if sum == nil {
			sum = pts
			continue
		}
		for i := range sum {
			if i < len(pts) {
				addPoint(&sum[i], pts[i])
			}
		}
	}
	return sum, nil
}

func (s *Server) incidents(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	all := s.app.Eng.Incidents().List(r.URL.Query().Get("status"), qInt(r, "limit", 500))
	out := make([]engine.Incident, 0, len(all))
	for _, i := range all {
		if u.AllowsObject(i.ObjectName) {
			out = append(out, i)
		}
	}
	return out, nil
}

func (s *Server) getIncident(u *auth.User, id string) (*engine.Incident, error) {
	inc := s.app.Eng.Incidents().Get(id)
	if inc == nil || !u.AllowsObject(inc.ObjectName) {
		return nil, notFound("olay bulunamadı")
	}
	return inc, nil
}

func (s *Server) incident(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	inc, err := s.getIncident(u, r.PathValue("id"))
	if err != nil {
		return nil, err
	}
	mits := []any{}
	for _, id := range inc.Mitigations {
		if m := s.app.Mit.Get(id); m != nil {
			mits = append(mits, m)
		}
	}
	finds := []any{}
	if !u.Scoped() {
		for _, id := range inc.Findings {
			if f := s.app.Ana.Get(id); f != nil {
				finds = append(finds, f)
			}
		}
	}
	return map[string]any{"incident": inc, "mitigations": mits, "findings": finds}, nil
}

func (s *Server) incidentTop(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	inc, err := s.getIncident(u, r.PathValue("id"))
	if err != nil {
		return nil, err
	}
	dim := r.URL.Query().Get("dimension")
	if dim == "" {
		dim = "src_ip"
	}
	f := flowstore.Filter{Seconds: qInt(r, "seconds", 60)}
	return s.app.Store.TopN(f, s.app.Eng.IncidentPredicate(inc), dim, r.URL.Query().Get("metric"), qInt(r, "limit", 20), s.app.Eng.ObjectName)
}

func (s *Server) signals(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	pending := r.URL.Query().Get("pending") == "true"
	all := s.app.Eng.Signals().List(pending, qInt(r, "min_seconds", 1), qInt(r, "limit", 300))
	out := make([]engine.Signal, 0, len(all))
	for _, x := range all {
		if u.AllowsObject(x.ObjectName) {
			out = append(out, x)
		}
	}
	return out, nil
}

func (s *Server) seriesTop(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	all, err := s.app.Eng.TopSeries(qInt(r, "limit", 25) * 4)
	if err != nil {
		return nil, err
	}
	out := []engine.TargetRuleState{}
	for _, x := range all {
		if u.AllowsObject(x.ObjectName) && len(out) < qInt(r, "limit", 25) {
			out = append(out, x)
		}
	}
	return out, nil
}

func (s *Server) target(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	a, err := netip.ParseAddr(r.URL.Query().Get("ip"))
	if err != nil {
		return nil, errCode(http.StatusBadRequest, "geçersiz IP adresi")
	}
	if !s.allowsTarget(u, a.String()) {
		return nil, forbidden("bu adres kapsamınızda değil")
	}
	return s.app.Eng.TargetState(a, r.URL.Query().Get("rule"), true)
}

type flowReq struct {
	Filter     flowstore.Filter `json:"filter"`
	ObjectName string           `json:"object_name"`
	Dimension  string           `json:"dimension"`
	Metric     string           `json:"metric"`
	Limit      int              `json:"limit"`
}

func (s *Server) parseFlowReq(r *http.Request, u *auth.User) (flowReq, flowstore.Predicate, error) {
	var req flowReq
	if err := readJSON(r, &req); err != nil {
		return req, nil, err
	}
	if req.ObjectName != "" {
		o := s.app.Eng.ObjectByName(req.ObjectName)
		if o == nil || !u.AllowsObject(req.ObjectName) {
			return req, nil, notFound("nesne bulunamadı")
		}
		id := int(o.ID)
		req.Filter.ObjectID = &id
	}
	if req.Filter.Seconds > 3600 {
		req.Filter.Seconds = 3600
	}
	return req, scopePredicate(s.scope(u)), nil
}

func (s *Server) flowsTop(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	req, pred, err := s.parseFlowReq(r, u)
	if err != nil {
		return nil, err
	}
	return s.app.Store.TopN(req.Filter, pred, req.Dimension, req.Metric, req.Limit, s.app.Eng.ObjectName)
}

func (s *Server) flowsBreakdown(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	req, pred, err := s.parseFlowReq(r, u)
	if err != nil {
		return nil, err
	}
	return s.app.Store.Breakdown(req.Filter, pred, 10)
}

func (s *Server) flowsSamples(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	req, pred, err := s.parseFlowReq(r, u)
	if err != nil {
		return nil, err
	}
	return s.app.Store.Samples(req.Filter, pred, req.Limit)
}

func (s *Server) exporters(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	return map[string]any{
		"exporters": s.app.Col.Exporters(), "listening": s.app.Col.Listening(),
		"rejected": s.app.Col.Rejected(), "queue_dropped": s.app.Col.Dropped(),
	}, nil
}

type effectiveView struct {
	Enabled bool    `json:"enabled"`
	Profile string  `json:"profile"`
	PPS     float64 `json:"pps"`
	BPS     float64 `json:"bps"`
	FPS     float64 `json:"fps"`
}

type ruleView struct {
	rules.Rule
	Active       bool                     `json:"active"`
	MatchSummary string                   `json:"match_summary"`
	SustainSec   int                      `json:"sustain_seconds"`
	HoldDownSec  int                      `json:"hold_down_seconds"`
	Base         rules.Thresholds         `json:"base_thresholds"`
	Override     *rules.Override          `json:"override,omitempty"`
	Effective    map[string]effectiveView `json:"effective"`
}

func (s *Server) rules(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	set := s.app.Eng.Rules()
	ov := s.app.Eng.Overrides()
	out := make([]ruleView, 0, len(set.Rules))
	for _, c := range set.Rules {
		v := ruleView{Rule: c.Rule, Active: c.Active, MatchSummary: c.MatchSummary(), SustainSec: c.SustainSec, HoldDownSec: c.HoldDownSec, Base: c.T, Effective: map[string]effectiveView{}}
		if o, ok := ov[c.ID]; ok {
			o := o
			v.Override = &o
		}
		for _, o := range s.app.Eng.Objects() {
			if !u.AllowsObject(o.Name) {
				continue
			}
			t, ok := set.Effective(c, o.Profile)
			v.Effective[o.Name] = effectiveView{Enabled: ok, Profile: o.Profile, PPS: float64(t.PPS), BPS: float64(t.BPS), FPS: float64(t.FPS)}
		}
		out = append(out, v)
	}
	return map[string]any{"rules": out, "profiles": set.Profiles, "files": set.Files}, nil
}

func (s *Server) system(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	return map[string]any{
		"version": Version, "uptime": time.Now().Unix() - s.app.Started, "engine": s.app.Eng.Snapshot(),
		"collector":       map[string]any{"listening": s.app.Col.Listening(), "rejected": s.app.Col.Rejected(), "queue_dropped": s.app.Col.Dropped()},
		"restart_pending": s.app.RestartPending(), "notifications": s.app.Notif.Status(), "config_path": s.app.Path,
	}, nil
}

// ready reports 200 when the engine ticks and the collector listens.
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	snap := s.app.Eng.Snapshot()
	ok := snap != nil && time.Now().Unix()-snap.Time <= 5 && len(s.app.Col.Listening()) > 0
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("not ready"))
		return
	}
	_, _ = w.Write([]byte("ready"))
}
