package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/analyst"
	"github.com/SimsekBerk/DDOS-Detection/internal/auth"
	"github.com/SimsekBerk/DDOS-Detection/internal/config"
	"github.com/SimsekBerk/DDOS-Detection/internal/mitigation"
	"github.com/SimsekBerk/DDOS-Detection/internal/rules"
	"github.com/SimsekBerk/DDOS-Detection/internal/sim"
)

// ------------------------------------------------------------- mitigation

type mitigationResult struct{ *mitigation.Mitigation }

func (m mitigationResult) auditDetail() string {
	if m.Mitigation == nil {
		return ""
	}
	return fmt.Sprintf("%s %s %s → %s", m.ID, m.Kind, m.Target, m.Status)
}

func (s *Server) mitigations(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	out := []*mitigation.Mitigation{}
	for _, m := range s.app.Mit.List(r.URL.Query().Get("status")) {
		if s.allowsTarget(u, m.Target) {
			out = append(out, m)
		}
	}
	return out, nil
}

func (s *Server) mitigationGet(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	m := s.app.Mit.Get(r.PathValue("id"))
	if m == nil || !s.allowsTarget(u, m.Target) {
		return nil, notFound("mitigasyon bulunamadı")
	}
	return m, nil
}

func (s *Server) mitigationCreate(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	var req mitigation.Request
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	req.Source = "manual"
	target := req.RTBHPrefix
	if req.FlowSpec != nil {
		target = req.FlowSpec.Destination
		if target == "" {
			target = req.FlowSpec.Source
		}
	}
	if !s.allowsTarget(u, target) {
		return nil, forbidden("hedef kapsamınızda değil")
	}
	m, err := s.app.Mit.Create(req, u.Username)
	return mitigationResult{m}, err
}

func (s *Server) mitigationAction(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	id := r.PathValue("id")
	cur := s.app.Mit.Get(id)
	if cur == nil || !s.allowsTarget(u, cur.Target) {
		return nil, notFound("mitigasyon bulunamadı")
	}
	var m *mitigation.Mitigation
	var err error
	switch r.PathValue("action") {
	case "approve":
		m, err = s.app.Mit.Approve(id, u.Username)
	case "reject":
		var req struct {
			Reason string `json:"reason"`
		}
		_ = readJSON(r, &req)
		if req.Reason == "" {
			req.Reason = "operatör reddetti"
		}
		m, err = s.app.Mit.Reject(id, u.Username, req.Reason)
	case "withdraw":
		m, err = s.app.Mit.Withdraw(id, u.Username)
	case "extend":
		m, err = s.app.Mit.Extend(id, u.Username, 30*time.Minute)
	default:
		return nil, notFound("bilinmeyen aksiyon")
	}
	return mitigationResult{m}, err
}

// ------------------------------------------------------------- analyst

func (s *Server) analystStatus(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	return s.app.Ana.Status(), nil
}

// findingAllowed: scoped users see findings about their incidents/targets only.
func (s *Server) findingAllowed(u *auth.User, f *analyst.Finding) bool {
	if !u.Scoped() {
		return true
	}
	if f.IncidentID != "" {
		inc := s.app.Eng.Incidents().Get(f.IncidentID)
		return inc != nil && u.AllowsObject(inc.ObjectName)
	}
	if len(f.Targets) == 0 {
		return false
	}
	for _, t := range f.Targets {
		if !s.allowsTarget(u, t) {
			return false
		}
	}
	return true
}

func (s *Server) findings(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	out := []analyst.Finding{}
	for _, f := range s.app.Ana.Findings(qInt(r, "limit", 100)) {
		f := f
		if s.findingAllowed(u, &f) {
			out = append(out, f)
		}
	}
	return out, nil
}

func (s *Server) finding(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	f := s.app.Ana.Get(r.PathValue("id"))
	if f == nil || !s.findingAllowed(u, f) {
		return nil, notFound("bulgu bulunamadı")
	}
	return f, nil
}

func (s *Server) analystRun(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	var req struct {
		SignalIDs []string `json:"signal_ids"`
	}
	_ = readJSON(r, &req)
	id, err := s.app.Ana.AnalyzeSignals(s.ctx, req.SignalIDs)
	if err != nil {
		return nil, errCode(http.StatusConflict, err.Error())
	}
	return map[string]string{"finding_id": id, "status": "running"}, nil
}

func (s *Server) analystIncident(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	id, err := s.app.Ana.AnalyzeIncident(s.ctx, r.PathValue("id"))
	if err != nil {
		return nil, errCode(http.StatusConflict, err.Error())
	}
	return map[string]string{"finding_id": id, "status": "running"}, nil
}

func (s *Server) analystAsk(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	var req struct {
		Question string `json:"question"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	id, err := s.app.Ana.Ask(s.ctx, req.Question)
	if err != nil {
		return nil, errCode(http.StatusConflict, err.Error())
	}
	return map[string]string{"finding_id": id, "status": "running"}, nil
}

// applyRecommendation turns an analyst recommendation into a pending
// mitigation (flowspec/rtbh/scrub) or, for admins, a rule threshold override.
func (s *Server) applyRecommendation(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	f := s.app.Ana.Get(r.PathValue("id"))
	if f == nil {
		return nil, notFound("bulgu bulunamadı")
	}
	idx, err := strconv.Atoi(r.PathValue("idx"))
	if err != nil || idx < 0 || idx >= len(f.Recommendations) {
		return nil, notFound("öneri bulunamadı")
	}
	rec := f.Recommendations[idx]
	if rec.Applied != "" {
		return nil, errCode(http.StatusConflict, "öneri zaten uygulandı: "+rec.Applied)
	}
	reason := "AI analist önerisi " + f.ID + ": " + rec.Title
	switch rec.Type {
	case "flowspec":
		h := rec.FlowSpec
		if h == nil {
			return nil, errors.New("öneride flowspec yok")
		}
		fs, err := mitigation.FlowSpecFromHint(h.Target, h.Direction, h.Protocol, h.SrcPorts, h.DstPorts, h.MinPacketLength, h.Action, h.RateBps)
		if err != nil {
			return nil, err
		}
		m, err := s.app.Mit.Create(mitigation.Request{Kind: "flowspec", FlowSpec: fs, Reason: reason, Source: "analyst", FindingID: f.ID, IncidentID: f.IncidentID}, u.Username)
		if m != nil {
			_ = s.app.Ana.MarkApplied(f.ID, idx, m.ID)
		}
		return mitigationResult{m}, err
	case "rtbh", "scrub":
		target := ""
		if len(f.Targets) > 0 {
			target = f.Targets[0]
		}
		if rec.FlowSpec != nil {
			target = rec.FlowSpec.Target
		}
		m, err := s.app.Mit.Create(mitigation.Request{Kind: rec.Type, RTBHPrefix: target, Reason: reason, Source: "analyst", FindingID: f.ID, IncidentID: f.IncidentID}, u.Username)
		if m != nil {
			_ = s.app.Ana.MarkApplied(f.ID, idx, m.ID)
		}
		return mitigationResult{m}, err
	case "threshold_change":
		if !u.Can(auth.RoleAdmin) {
			return nil, forbidden("eşik değişikliği yönetici yetkisi gerektirir")
		}
		t := rec.Threshold
		if t == nil || t.RuleID == "" {
			return nil, errors.New("öneride eşik bilgisi yok")
		}
		o := s.app.Eng.Overrides()[t.RuleID]
		if t.PPS > 0 {
			v := config.Rate(t.PPS)
			o.PPS = &v
		}
		if t.BPS > 0 {
			v := config.Rate(t.BPS)
			o.BPS = &v
		}
		if err := s.app.Eng.SetRuleOverride(t.RuleID, o); err != nil {
			return nil, err
		}
		_ = s.app.Ana.MarkApplied(f.ID, idx, "rule:"+t.RuleID)
		return map[string]string{"status": "ok", "applied": "rule:" + t.RuleID}, nil
	}
	return nil, errors.New("bu öneri tipi otomatik uygulanamaz; manuel değerlendirin")
}

// ------------------------------------------------------------- rules

func (s *Server) patchRule(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	var req struct {
		Enabled *bool    `json:"enabled"`
		PPS     *float64 `json:"pps"`
		BPS     *float64 `json:"bps"`
		FPS     *float64 `json:"fps"`
		Reset   bool     `json:"reset"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	id := r.PathValue("id")
	o := rules.Override{}
	if !req.Reset {
		if cur, ok := s.app.Eng.Overrides()[id]; ok {
			o = cur
		}
		if req.Enabled != nil {
			o.Enabled = req.Enabled
		}
		conv := func(v *float64) *config.Rate {
			if v == nil || *v < 0 {
				return nil
			}
			x := config.Rate(*v)
			return &x
		}
		if req.PPS != nil {
			o.PPS = conv(req.PPS)
		}
		if req.BPS != nil {
			o.BPS = conv(req.BPS)
		}
		if req.FPS != nil {
			o.FPS = conv(req.FPS)
		}
	}
	if err := s.app.Eng.SetRuleOverride(id, o); err != nil {
		return nil, err
	}
	var d []string
	if req.Reset {
		d = append(d, "varsayılana döndü")
	}
	if req.Enabled != nil {
		d = append(d, fmt.Sprintf("etkin=%v", *req.Enabled))
	}
	for _, x := range []struct {
		name string
		v    *float64
	}{{"pps", req.PPS}, {"bps", req.BPS}, {"fps", req.FPS}} {
		switch {
		case x.v == nil:
		case *x.v < 0:
			d = append(d, x.name+"=dosya değeri")
		default:
			d = append(d, x.name+"="+config.FormatRate(*x.v))
		}
	}
	return ruleResult{Status: "ok", detail: strings.Join(d, " ")}, nil
}

type ruleResult struct {
	Status string `json:"status"`
	detail string
}

func (r ruleResult) auditDetail() string { return r.detail }

func (s *Server) reloadRules(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	if err := s.app.Eng.ReloadRules(); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok", "rules": len(s.app.Eng.Rules().Rules)}, nil
}

// ------------------------------------------------------------- simulator

func (s *Server) simStatus(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	if s.app.Sim == nil {
		return map[string]any{"enabled": false}, nil
	}
	return map[string]any{"enabled": true, "status": s.app.Sim.Status(), "scenarios": sim.Scenarios()}, nil
}

func (s *Server) simStart(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	if s.app.Sim == nil {
		return nil, errors.New("demo simülatörü kapalı (demo.enabled)")
	}
	var req sim.StartRequest
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	// Near-miss scenarios are sized relative to the target's effective threshold.
	if sc, ok := sim.Lookup(req.Scenario); ok && req.PPS <= 0 && sc.RelativeRule != "" {
		target := req.Target
		if target == "" {
			target = s.app.Config().Objects[0].Parsed[0].Addr().String()
		}
		if a, err := netip.ParseAddr(target); err == nil {
			if obj := s.app.Eng.LookupObject(a); obj != nil {
				if t, ok := s.app.Eng.EffectiveThresholds(sc.RelativeRule, obj.ID); ok {
					req.PPS = sc.RelativePPS(float64(t.PPS), float64(t.BPS))
				}
			}
		}
	}
	return s.app.Sim.Start(req)
}

func (s *Server) simStop(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	if s.app.Sim == nil {
		return nil, errors.New("demo simülatörü kapalı")
	}
	var req struct {
		ID string `json:"id"`
	}
	_ = readJSON(r, &req)
	s.app.Sim.Stop(req.ID)
	return map[string]string{"status": "ok"}, nil
}

func (s *Server) simBaseline(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	if s.app.Sim == nil {
		return nil, errors.New("demo simülatörü kapalı")
	}
	var req struct {
		Enabled bool    `json:"enabled"`
		BPS     float64 `json:"bps"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	s.app.Sim.SetBaseline(req.Enabled, req.BPS)
	return s.app.Sim.Status(), nil
}
