// Package api exposes the REST API and serves the embedded web UI.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/analyst"
	"github.com/SimsekBerk/DDOS-Detection/internal/collector"
	"github.com/SimsekBerk/DDOS-Detection/internal/config"
	"github.com/SimsekBerk/DDOS-Detection/internal/engine"
	"github.com/SimsekBerk/DDOS-Detection/internal/flowstore"
	"github.com/SimsekBerk/DDOS-Detection/internal/mitigation"
	"github.com/SimsekBerk/DDOS-Detection/internal/rules"
	"github.com/SimsekBerk/DDOS-Detection/internal/sim"
)

// Version is set at build time.
var Version = "dev"

type Server struct {
	cfg  *config.Config
	eng  *engine.Engine
	col  *collector.Collector
	mit  *mitigation.Manager
	ana  *analyst.Analyst
	sim  *sim.Simulator
	ui   fs.FS
	log  *slog.Logger
	ctx  context.Context
	boot int64
}

func New(cfg *config.Config, eng *engine.Engine, col *collector.Collector, mit *mitigation.Manager, ana *analyst.Analyst, s *sim.Simulator, ui fs.FS, log *slog.Logger) *Server {
	return &Server{cfg: cfg, eng: eng, col: col, mit: mit, ana: ana, sim: s, ui: ui, log: log, boot: time.Now().Unix()}
}

// Run serves HTTP until ctx is done.
func (s *Server) Run(ctx context.Context) error {
	s.ctx = ctx
	srv := &http.Server{Addr: s.cfg.API.Listen, Handler: s.routes(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sh)
	}()
	s.log.Info("web UI and API listening", "addr", s.cfg.API.Listen)
	if s.cfg.API.Password == "" {
		s.log.Warn("API has no authentication; set api.username/api.password before exposing it")
	}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Server) routes() http.Handler {
	m := http.NewServeMux()
	h := func(pattern string, f func(w http.ResponseWriter, r *http.Request) (any, error)) {
		m.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			v, err := f(w, r)
			if err != nil {
				code := http.StatusBadRequest
				var he httpError
				if errors.As(err, &he) {
					code = he.code
				}
				writeJSON(w, code, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, v)
		})
	}
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	h("GET /api/v1/overview", s.overview)
	h("GET /api/v1/timeseries", s.timeseries)
	h("GET /api/v1/incidents", s.incidents)
	h("GET /api/v1/incidents/{id}", s.incident)
	h("GET /api/v1/incidents/{id}/top", s.incidentTop)
	h("GET /api/v1/signals", s.signals)
	h("GET /api/v1/series/top", s.seriesTop)
	h("GET /api/v1/target", s.target)
	h("POST /api/v1/flows/top", s.flowsTop)
	h("POST /api/v1/flows/breakdown", s.flowsBreakdown)
	h("POST /api/v1/flows/samples", s.flowsSamples)
	h("GET /api/v1/rules", s.rules)
	h("PATCH /api/v1/rules/{id}", s.patchRule)
	h("POST /api/v1/rules/reload", s.reloadRules)
	h("GET /api/v1/mitigations", s.mitigations)
	h("GET /api/v1/mitigations/{id}", s.mitigationGet)
	h("POST /api/v1/mitigations", s.mitigationCreate)
	h("POST /api/v1/mitigations/{id}/{action}", s.mitigationAction)
	h("GET /api/v1/exporters", s.exporters)
	h("GET /api/v1/analyst/status", s.analystStatus)
	h("GET /api/v1/analyst/findings", s.findings)
	h("GET /api/v1/analyst/findings/{id}", s.finding)
	h("POST /api/v1/analyst/run", s.analystRun)
	h("POST /api/v1/analyst/incident/{id}", s.analystIncident)
	h("POST /api/v1/analyst/ask", s.analystAsk)
	h("POST /api/v1/analyst/findings/{id}/apply/{idx}", s.applyRecommendation)
	h("GET /api/v1/sim", s.simStatus)
	h("POST /api/v1/sim/start", s.simStart)
	h("POST /api/v1/sim/stop", s.simStop)
	h("POST /api/v1/sim/baseline", s.simBaseline)
	h("GET /api/v1/config", s.configView)

	if s.ui != nil {
		m.Handle("/", spaHandler(s.ui))
	}
	return s.auth(securityHeaders(m))
}

type httpError struct {
	code int
	msg  string
}

func (e httpError) Error() string { return e.msg }

func notFound(msg string) error { return httpError{http.StatusNotFound, msg} }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	if err := dec.Decode(v); err != nil {
		return errors.New("geçersiz JSON gövdesi: " + err.Error())
	}
	return nil
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// auth enforces HTTP basic auth when credentials are configured.
func (s *Server) auth(next http.Handler) http.Handler {
	user, pass := s.cfg.API.Username, s.cfg.API.Password
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if pass == "" || r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		u, p, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(u), []byte(user)) != 1 || subtle.ConstantTimeCompare([]byte(p), []byte(pass)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="ddosd"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) actor(r *http.Request) string {
	if u, _, ok := r.BasicAuth(); ok && u != "" {
		return u
	}
	return "operator"
}

func spaHandler(ui fs.FS) http.Handler {
	files := http.FileServer(http.FS(ui))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(ui, p); err != nil {
			if _, err := fs.Stat(ui, "index.html"); err != nil {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.Write([]byte("UI derlenmemiş. 'make ui' çalıştırın veya API'yi /api/v1/... altında kullanın."))
				return
			}
			r.URL.Path = "/"
		}
		if strings.HasPrefix(p, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		files.ServeHTTP(w, r)
	})
}

func qInt(r *http.Request, k string, def int) int {
	if v, err := strconv.Atoi(r.URL.Query().Get(k)); err == nil {
		return v
	}
	return def
}

// ------------------------------------------------------------------ handlers

func (s *Server) overview(w http.ResponseWriter, r *http.Request) (any, error) {
	pending, active := s.mit.Counts()
	exps := s.col.Exporters()
	now := time.Now().Unix()
	up := 0
	for _, e := range exps {
		if now-e.LastSeen < 60 {
			up++
		}
	}
	return map[string]any{
		"version": Version, "uptime": now - s.boot, "engine": s.eng.Snapshot(),
		"mitigation": map[string]any{"pending": pending, "active": active, "mode": s.mit.Mode(), "driver": s.mit.DriverName()},
		"analyst":    s.ana.Status(), "exporters_total": len(exps), "exporters_up": up,
		"listening": s.col.Listening(), "demo": s.sim != nil,
	}, nil
}

func (s *Server) timeseries(w http.ResponseWriter, r *http.Request) (any, error) {
	obj := -1
	if name := r.URL.Query().Get("object"); name != "" {
		o := s.eng.ObjectByName(name)
		if o == nil {
			return nil, notFound("nesne bulunamadı")
		}
		obj = int(o.ID)
	}
	rng := int64(qInt(r, "range", 900))
	step := int64(qInt(r, "step", 0))
	if step <= 0 {
		step = max(1, rng/240)
	}
	return s.eng.Totals().Series(obj, time.Now().Unix(), rng, step), nil
}

func (s *Server) incidents(w http.ResponseWriter, r *http.Request) (any, error) {
	return s.eng.Incidents().List(r.URL.Query().Get("status"), qInt(r, "limit", 200)), nil
}

func (s *Server) incident(w http.ResponseWriter, r *http.Request) (any, error) {
	inc := s.eng.Incidents().Get(r.PathValue("id"))
	if inc == nil {
		return nil, notFound("olay bulunamadı")
	}
	var mits []*mitigation.Mitigation
	for _, id := range inc.Mitigations {
		if m := s.mit.Get(id); m != nil {
			mits = append(mits, m)
		}
	}
	var finds []*analyst.Finding
	for _, id := range inc.Findings {
		if f := s.ana.Get(id); f != nil {
			finds = append(finds, f)
		}
	}
	return map[string]any{"incident": inc, "mitigations": mits, "findings": finds}, nil
}

func (s *Server) incidentTop(w http.ResponseWriter, r *http.Request) (any, error) {
	inc := s.eng.Incidents().Get(r.PathValue("id"))
	if inc == nil {
		return nil, notFound("olay bulunamadı")
	}
	dim := r.URL.Query().Get("dimension")
	if dim == "" {
		dim = "src_ip"
	}
	f := flowstore.Filter{Seconds: qInt(r, "seconds", 60)}
	return s.eng.Store().TopN(f, s.eng.IncidentPredicate(inc), dim, r.URL.Query().Get("metric"), qInt(r, "limit", 20), s.eng.ObjectName)
}

func (s *Server) signals(w http.ResponseWriter, r *http.Request) (any, error) {
	pending := r.URL.Query().Get("pending") == "true"
	return s.eng.Signals().List(pending, qInt(r, "min_seconds", 1), qInt(r, "limit", 200)), nil
}

func (s *Server) seriesTop(w http.ResponseWriter, r *http.Request) (any, error) {
	return s.eng.TopSeries(qInt(r, "limit", 25))
}

func (s *Server) target(w http.ResponseWriter, r *http.Request) (any, error) {
	a, err := netip.ParseAddr(r.URL.Query().Get("ip"))
	if err != nil {
		return nil, errors.New("geçersiz ip")
	}
	return s.eng.TargetState(a, r.URL.Query().Get("rule"), true)
}

type flowReq struct {
	Filter     flowstore.Filter `json:"filter"`
	ObjectName string           `json:"object_name"`
	Dimension  string           `json:"dimension"`
	Metric     string           `json:"metric"`
	Limit      int              `json:"limit"`
}

func (s *Server) parseFlowReq(r *http.Request) (flowReq, error) {
	var req flowReq
	if err := readJSON(r, &req); err != nil {
		return req, err
	}
	if req.ObjectName != "" {
		o := s.eng.ObjectByName(req.ObjectName)
		if o == nil {
			return req, notFound("nesne bulunamadı")
		}
		id := int(o.ID)
		req.Filter.ObjectID = &id
	}
	return req, nil
}

func (s *Server) flowsTop(w http.ResponseWriter, r *http.Request) (any, error) {
	req, err := s.parseFlowReq(r)
	if err != nil {
		return nil, err
	}
	return s.eng.Store().TopN(req.Filter, nil, req.Dimension, req.Metric, req.Limit, s.eng.ObjectName)
}

func (s *Server) flowsBreakdown(w http.ResponseWriter, r *http.Request) (any, error) {
	req, err := s.parseFlowReq(r)
	if err != nil {
		return nil, err
	}
	return s.eng.Store().Breakdown(req.Filter, nil, 10)
}

func (s *Server) flowsSamples(w http.ResponseWriter, r *http.Request) (any, error) {
	req, err := s.parseFlowReq(r)
	if err != nil {
		return nil, err
	}
	return s.eng.Store().Samples(req.Filter, nil, req.Limit)
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

type effectiveView struct {
	Enabled bool    `json:"enabled"`
	Profile string  `json:"profile"`
	PPS     float64 `json:"pps"`
	BPS     float64 `json:"bps"`
	FPS     float64 `json:"fps"`
}

func (s *Server) rules(w http.ResponseWriter, r *http.Request) (any, error) {
	set := s.eng.Rules()
	ov := s.eng.Overrides()
	out := make([]ruleView, 0, len(set.Rules))
	for _, c := range set.Rules {
		v := ruleView{Rule: c.Rule, Active: c.Active, MatchSummary: c.MatchSummary(), SustainSec: c.SustainSec, HoldDownSec: c.HoldDownSec, Base: c.T, Effective: map[string]effectiveView{}}
		if o, ok := ov[c.ID]; ok {
			o := o
			v.Override = &o
		}
		for _, o := range s.eng.Objects() {
			t, ok := set.Effective(c, o.Profile)
			v.Effective[o.Name] = effectiveView{Enabled: ok, Profile: o.Profile, PPS: float64(t.PPS), BPS: float64(t.BPS), FPS: float64(t.FPS)}
		}
		out = append(out, v)
	}
	return map[string]any{"rules": out, "profiles": set.Profiles, "files": set.Files}, nil
}

func (s *Server) patchRule(w http.ResponseWriter, r *http.Request) (any, error) {
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
		if cur, ok := s.eng.Overrides()[id]; ok {
			o = cur
		}
		if req.Enabled != nil {
			o.Enabled = req.Enabled
		}
		conv := func(v *float64) *config.Rate {
			if v == nil {
				return nil
			}
			if *v < 0 {
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
	if err := s.eng.SetRuleOverride(id, o); err != nil {
		return nil, err
	}
	s.log.Info("rule override changed", "rule", id, "actor", s.actor(r))
	return map[string]string{"status": "ok"}, nil
}

func (s *Server) reloadRules(w http.ResponseWriter, r *http.Request) (any, error) {
	if err := s.eng.ReloadRules(); err != nil {
		return nil, err
	}
	return map[string]any{"status": "ok", "rules": len(s.eng.Rules().Rules)}, nil
}

func (s *Server) mitigations(w http.ResponseWriter, r *http.Request) (any, error) {
	return s.mit.List(r.URL.Query().Get("status")), nil
}

func (s *Server) mitigationGet(w http.ResponseWriter, r *http.Request) (any, error) {
	m := s.mit.Get(r.PathValue("id"))
	if m == nil {
		return nil, notFound("mitigasyon bulunamadı")
	}
	return m, nil
}

func (s *Server) mitigationCreate(w http.ResponseWriter, r *http.Request) (any, error) {
	var req mitigation.Request
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	req.Source = "manual"
	return s.mit.Create(req, s.actor(r))
}

func (s *Server) mitigationAction(w http.ResponseWriter, r *http.Request) (any, error) {
	id, actor := r.PathValue("id"), s.actor(r)
	switch r.PathValue("action") {
	case "approve":
		return s.mit.Approve(id, actor)
	case "reject":
		var req struct {
			Reason string `json:"reason"`
		}
		_ = readJSON(r, &req)
		if req.Reason == "" {
			req.Reason = "operatör reddetti"
		}
		return s.mit.Reject(id, actor, req.Reason)
	case "withdraw":
		return s.mit.Withdraw(id, actor)
	case "extend":
		return s.mit.Extend(id, actor, 30*time.Minute)
	}
	return nil, notFound("bilinmeyen aksiyon")
}

func (s *Server) exporters(w http.ResponseWriter, r *http.Request) (any, error) {
	return map[string]any{"exporters": s.col.Exporters(), "listening": s.col.Listening()}, nil
}

func (s *Server) analystStatus(w http.ResponseWriter, r *http.Request) (any, error) {
	return s.ana.Status(), nil
}

func (s *Server) findings(w http.ResponseWriter, r *http.Request) (any, error) {
	return s.ana.Findings(qInt(r, "limit", 100)), nil
}

func (s *Server) finding(w http.ResponseWriter, r *http.Request) (any, error) {
	f := s.ana.Get(r.PathValue("id"))
	if f == nil {
		return nil, notFound("bulgu bulunamadı")
	}
	return f, nil
}

func (s *Server) analystRun(w http.ResponseWriter, r *http.Request) (any, error) {
	var req struct {
		SignalIDs []string `json:"signal_ids"`
	}
	_ = readJSON(r, &req)
	id, err := s.ana.AnalyzeSignals(s.ctx, req.SignalIDs)
	if err != nil {
		return nil, httpError{http.StatusConflict, err.Error()}
	}
	return map[string]string{"finding_id": id, "status": "running"}, nil
}

func (s *Server) analystIncident(w http.ResponseWriter, r *http.Request) (any, error) {
	id, err := s.ana.AnalyzeIncident(s.ctx, r.PathValue("id"))
	if err != nil {
		return nil, httpError{http.StatusConflict, err.Error()}
	}
	return map[string]string{"finding_id": id, "status": "running"}, nil
}

func (s *Server) analystAsk(w http.ResponseWriter, r *http.Request) (any, error) {
	var req struct {
		Question string `json:"question"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	id, err := s.ana.Ask(s.ctx, req.Question)
	if err != nil {
		return nil, httpError{http.StatusConflict, err.Error()}
	}
	return map[string]string{"finding_id": id, "status": "running"}, nil
}

// applyRecommendation turns an analyst recommendation into a pending
// mitigation (flowspec/rtbh/scrub) or a rule threshold override.
func (s *Server) applyRecommendation(w http.ResponseWriter, r *http.Request) (any, error) {
	f := s.ana.Get(r.PathValue("id"))
	if f == nil {
		return nil, notFound("bulgu bulunamadı")
	}
	idx, err := strconv.Atoi(r.PathValue("idx"))
	if err != nil || idx < 0 || idx >= len(f.Recommendations) {
		return nil, notFound("öneri bulunamadı")
	}
	rec := f.Recommendations[idx]
	if rec.Applied != "" {
		return nil, httpError{http.StatusConflict, "öneri zaten uygulandı: " + rec.Applied}
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
		m, err := s.mit.Create(mitigation.Request{Kind: "flowspec", FlowSpec: fs, Reason: reason, Source: "analyst", FindingID: f.ID, IncidentID: f.IncidentID}, s.actor(r))
		if m != nil {
			_ = s.ana.MarkApplied(f.ID, idx, m.ID)
		}
		return m, err
	case "rtbh", "scrub":
		target := ""
		if len(f.Targets) > 0 {
			target = f.Targets[0]
		}
		if rec.FlowSpec != nil {
			target = rec.FlowSpec.Target
		}
		m, err := s.mit.Create(mitigation.Request{Kind: rec.Type, RTBHPrefix: target, Reason: reason, Source: "analyst", FindingID: f.ID, IncidentID: f.IncidentID}, s.actor(r))
		if m != nil {
			_ = s.ana.MarkApplied(f.ID, idx, m.ID)
		}
		return m, err
	case "threshold_change":
		t := rec.Threshold
		if t == nil || t.RuleID == "" {
			return nil, errors.New("öneride eşik bilgisi yok")
		}
		o := s.eng.Overrides()[t.RuleID]
		if t.PPS > 0 {
			v := config.Rate(t.PPS)
			o.PPS = &v
		}
		if t.BPS > 0 {
			v := config.Rate(t.BPS)
			o.BPS = &v
		}
		if err := s.eng.SetRuleOverride(t.RuleID, o); err != nil {
			return nil, err
		}
		_ = s.ana.MarkApplied(f.ID, idx, "rule:"+t.RuleID)
		s.log.Info("analyst threshold recommendation applied", "finding", f.ID, "rule", t.RuleID, "actor", s.actor(r))
		return map[string]string{"status": "ok", "applied": "rule:" + t.RuleID}, nil
	}
	return nil, errors.New("bu öneri tipi otomatik uygulanamaz; manuel değerlendirin")
}

func (s *Server) simStatus(w http.ResponseWriter, r *http.Request) (any, error) {
	if s.sim == nil {
		return map[string]any{"enabled": false}, nil
	}
	return map[string]any{"enabled": true, "status": s.sim.Status(), "scenarios": sim.Scenarios()}, nil
}

func (s *Server) simStart(w http.ResponseWriter, r *http.Request) (any, error) {
	if s.sim == nil {
		return nil, errors.New("demo simülatörü kapalı (demo.enabled)")
	}
	var req sim.StartRequest
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	// Near-miss scenarios are sized relative to the target's effective threshold
	// so they stay below (or just above) it regardless of the object's profile.
	if sc, ok := sim.Lookup(req.Scenario); ok && req.PPS <= 0 && sc.RelativeRule != "" {
		target := req.Target
		if target == "" {
			target = s.cfg.Objects[0].Parsed[0].Addr().String()
		}
		if a, err := netip.ParseAddr(target); err == nil {
			if obj := s.eng.LookupObject(a); obj != nil {
				if t, ok := s.eng.EffectiveThresholds(sc.RelativeRule, obj.ID); ok {
					pps := float64(t.PPS)
					if t.BPS > 0 && sc.PktSize > 0 {
						if byBPS := float64(t.BPS) / (sc.PktSize * 8); pps == 0 || byBPS < pps {
							pps = byBPS
						}
					}
					req.PPS = pps * sc.RelativeFactor
				}
			}
		}
	}
	return s.sim.Start(req)
}

func (s *Server) simStop(w http.ResponseWriter, r *http.Request) (any, error) {
	if s.sim == nil {
		return nil, errors.New("demo simülatörü kapalı")
	}
	var req struct {
		ID string `json:"id"`
	}
	_ = readJSON(r, &req)
	s.sim.Stop(req.ID)
	return map[string]string{"status": "ok"}, nil
}

func (s *Server) simBaseline(w http.ResponseWriter, r *http.Request) (any, error) {
	if s.sim == nil {
		return nil, errors.New("demo simülatörü kapalı")
	}
	var req struct {
		Enabled bool    `json:"enabled"`
		BPS     float64 `json:"bps"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	s.sim.SetBaseline(req.Enabled, req.BPS)
	return s.sim.Status(), nil
}

func (s *Server) configView(w http.ResponseWriter, r *http.Request) (any, error) {
	c := *s.cfg
	c.API.Password = redact(c.API.Password)
	c.Mitigation.Webhook.Secret = redact(c.Mitigation.Webhook.Secret)
	return c, nil
}

func redact(s string) string {
	if s == "" {
		return ""
	}
	return "********"
}
