package analyst

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/collector"
	"github.com/SimsekBerk/DDOS-Detection/internal/config"
	"github.com/SimsekBerk/DDOS-Detection/internal/engine"
)

const (
	maxToolOutput = 14000
	maxFindings   = 300
)

// Status describes the analyst for the UI.
type Status struct {
	Enabled        bool   `json:"enabled"`
	Provider       string `json:"provider"`
	Model          string `json:"model"`
	ConfiguredAs   string `json:"configured_provider"`
	Note           string `json:"note,omitempty"`
	AutoRun        bool   `json:"auto_run"`
	IntervalSec    int64  `json:"interval_seconds"`
	Running        bool   `json:"running"`
	Current        string `json:"current,omitempty"`
	LastRun        int64  `json:"last_run"`
	LastError      string `json:"last_error,omitempty"`
	Findings       int    `json:"findings"`
	PendingSignals int    `json:"pending_signals"`
	Language       string `json:"language"`
}

// Analyst schedules and runs analyses and stores findings.
type Analyst struct {
	cfg      config.AnalystConfig
	eng      *engine.Engine
	provider Provider
	tools    []Tool
	toolMap  map[string]Tool
	log      *slog.Logger
	note     string

	mu       sync.Mutex
	findings map[string]*Finding
	seq      int
	running  bool
	current  string
	lastRun  int64
	lastErr  string
}

// New creates the analyst with the configured provider.
func New(cfg *config.Config, eng *engine.Engine, col *collector.Collector, log *slog.Logger) *Analyst {
	a := &Analyst{cfg: cfg.Analyst, eng: eng, log: log, findings: map[string]*Finding{}, toolMap: map[string]Tool{}}
	switch cfg.Analyst.Provider {
	case "anthropic":
		if os.Getenv("ANTHROPIC_API_KEY") == "" && os.Getenv("ANTHROPIC_AUTH_TOKEN") == "" {
			a.provider = heuristicProvider{}
			a.note = "ANTHROPIC_API_KEY tanımlı değil; kural tabanlı (heuristic) analiste düşüldü."
			log.Warn("analyst: ANTHROPIC_API_KEY not set, falling back to heuristic provider")
		} else {
			a.provider = newAnthropic(cfg.Analyst.Model, cfg.Analyst.Effort, cfg.Analyst.MaxTokens)
		}
	case "openai_compat":
		model := cfg.Analyst.OpenAICompat.Model
		if model == "" {
			a.provider = heuristicProvider{}
			a.note = "analyst.openai_compat.model tanımlı değil; heuristic analiste düşüldü."
		} else {
			a.provider = newOpenAICompat(cfg.Analyst.OpenAICompat.BaseURL, model, cfg.Analyst.OpenAICompat.APIKeyEnv)
		}
	default:
		a.provider = heuristicProvider{}
	}
	a.tools = buildTools(eng, col)
	for _, t := range a.tools {
		a.toolMap[t.Name] = t
	}
	var dump struct {
		Seq      int        `json:"seq"`
		Findings []*Finding `json:"findings"`
	}
	if err := eng.LoadJSON("findings.json", &dump); err == nil {
		a.seq = dump.Seq
		for _, f := range dump.Findings {
			a.findings[f.ID] = f
		}
	}
	return a
}

// Status returns the analyst status.
func (a *Analyst) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	return Status{
		Enabled: a.cfg.Enabled, Provider: a.provider.Name(), Model: a.provider.Model(), ConfiguredAs: a.cfg.Provider, Note: a.note,
		AutoRun: a.cfg.AutoRun, IntervalSec: int64(a.cfg.Interval.Seconds()), Running: a.running, Current: a.current,
		LastRun: a.lastRun, LastError: a.lastErr, Findings: len(a.findings),
		PendingSignals: len(a.eng.Signals().List(true, 3, 0)), Language: a.cfg.Language,
	}
}

// Loop runs scheduled analyses: only when there are pending signals (gate).
func (a *Analyst) Loop(ctx context.Context) {
	if !a.cfg.Enabled || !a.cfg.AutoRun {
		return
	}
	t := time.NewTicker(a.cfg.Interval.Duration)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if len(a.eng.Signals().List(true, 3, 0)) == 0 {
				continue // nothing new: no model call, no cost
			}
			if _, err := a.Start(ctx, task{Mode: "signals"}); err != nil && !errors.Is(err, errBusy) {
				a.log.Warn("scheduled analysis", "err", err)
			}
		}
	}
}

var errBusy = errors.New("bir analiz zaten çalışıyor")

// AnalyzeSignals starts an analysis of the given (or all pending) signals.
func (a *Analyst) AnalyzeSignals(ctx context.Context, ids []string) (string, error) {
	return a.Start(ctx, task{Mode: "signals", SignalIDs: ids})
}

// AnalyzeIncident starts an incident report.
func (a *Analyst) AnalyzeIncident(ctx context.Context, id string) (string, error) {
	if a.eng.Incidents().Get(id) == nil {
		return "", errors.New("olay bulunamadı")
	}
	return a.Start(ctx, task{Mode: "incident", IncidentID: id})
}

// Ask starts a free-form question.
func (a *Analyst) Ask(ctx context.Context, q string) (string, error) {
	if len(q) < 3 || len(q) > 2000 {
		return "", errors.New("soru 3-2000 karakter olmalı")
	}
	return a.Start(ctx, task{Mode: "question", Question: q})
}

// Start launches an analysis in the background and returns the finding id.
func (a *Analyst) Start(parent context.Context, t task) (string, error) {
	if !a.cfg.Enabled {
		return "", errors.New("analist yapılandırmada kapalı (analyst.enabled)")
	}
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return "", errBusy
	}
	a.running = true
	a.seq++
	id := fmt.Sprintf("FND-%05d", a.seq)
	a.current = id
	a.mu.Unlock()
	go a.run(context.WithoutCancel(parent), id, t)
	return id, nil
}

func (a *Analyst) run(parent context.Context, id string, t task) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(withTask(parent, t), 6*time.Minute)
	defer cancel()
	f := &Finding{
		ID: id, CreatedAt: start.Unix(), Mode: t.Mode, Provider: a.provider.Name(), Model: a.provider.Model(),
		Question: t.Question, IncidentID: t.IncidentID, SignalIDs: t.SignalIDs, Status: "ok",
		Evidence: []EvidenceItem{}, Recommendations: []Recommendation{}, Trace: []TraceStep{},
	}
	submitted := false
	var tmu sync.Mutex
	exec := func(ctx context.Context, turn int, name string, input json.RawMessage) (string, bool, bool) {
		t0 := time.Now()
		if name == submitTool {
			if err := applySubmit(f, input); err != nil {
				a.trace(&tmu, f, turn, name, input, "HATA: "+err.Error(), true, t0)
				return "HATA: " + err.Error() + " — düzeltip submit_finding'i tekrar çağır.", true, false
			}
			submitted = true
			a.trace(&tmu, f, turn, name, input, "bulgu kaydedildi", false, t0)
			return "Bulgu kaydedildi. Çalışma tamamlandı.", false, true
		}
		tool, ok := a.toolMap[name]
		if !ok {
			return "HATA: bilinmeyen araç " + name, true, false
		}
		out, err := tool.Run(ctx, input)
		if err != nil {
			a.trace(&tmu, f, turn, name, input, "HATA: "+err.Error(), true, t0)
			return "HATA: " + err.Error(), true, false
		}
		b, err := json.Marshal(out)
		if err != nil {
			return "HATA: sonuç serileştirilemedi", true, false
		}
		s := string(b)
		if len(s) > maxToolOutput {
			s = s[:maxToolOutput] + "…(kısaltıldı)"
		}
		a.trace(&tmu, f, turn, name, input, s, false, t0)
		return s, false, false
	}

	user := userPromptSignals(t.SignalIDs)
	switch t.Mode {
	case "incident":
		user = userPromptIncident(t.IncidentID)
	case "question":
		user = userPromptQuestion(t.Question)
	}
	usage, err := a.provider.Run(ctx, systemPrompt(a.cfg.Language), user, a.tools, a.cfg.MaxTurns, exec)
	f.Usage = usage
	f.DurationMs = time.Since(start).Milliseconds()
	if err != nil && !submitted {
		f.Status, f.Error = "error", err.Error()
		if f.Title == "" {
			f.Title = "Analiz tamamlanamadı"
		}
		a.log.Warn("analysis failed", "id", id, "err", err)
	}
	if t.Mode == "signals" && len(f.SignalIDs) == 0 {
		for _, s := range a.eng.Signals().List(true, 2, 50) {
			f.SignalIDs = append(f.SignalIDs, s.ID)
		}
	}
	if f.Status == "ok" && len(f.SignalIDs) > 0 {
		a.eng.Signals().MarkAnalyzed(f.SignalIDs, f.ID)
	}
	if f.IncidentID != "" {
		a.eng.Incidents().AttachFinding(f.IncidentID, f.ID)
	}
	a.mu.Lock()
	a.findings[f.ID] = f
	a.running, a.current, a.lastRun = false, "", time.Now().Unix()
	a.lastErr = f.Error
	a.pruneLocked()
	a.saveLocked()
	a.mu.Unlock()
	a.log.Info("analysis finished", "id", id, "mode", t.Mode, "status", f.Status, "turns", usage.Turns, "ms", f.DurationMs)
}

func (a *Analyst) trace(mu *sync.Mutex, f *Finding, turn int, name string, input json.RawMessage, out string, isErr bool, t0 time.Time) {
	in := string(input)
	if len(in) > 600 {
		in = in[:600] + "…"
	}
	if len(out) > 800 {
		out = out[:800] + "…"
	}
	mu.Lock()
	f.Trace = append(f.Trace, TraceStep{Turn: turn, Tool: name, Input: in, Output: out, IsError: isErr, DurationMs: time.Since(t0).Milliseconds()})
	mu.Unlock()
}

// applySubmit validates the submit_finding payload into f.
func applySubmit(f *Finding, raw json.RawMessage) error {
	var in struct {
		Title           string           `json:"title"`
		Summary         string           `json:"summary"`
		Classification  string           `json:"classification"`
		Severity        string           `json:"severity"`
		Confidence      float64          `json:"confidence"`
		Targets         []string         `json:"targets"`
		Hypothesis      string           `json:"hypothesis"`
		MissedReason    string           `json:"missed_reason"`
		Evidence        []EvidenceItem   `json:"evidence"`
		Recommendations []Recommendation `json:"recommendations"`
		SignalIDs       []string         `json:"signal_ids"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return fmt.Errorf("geçersiz JSON: %v", err)
	}
	if in.Title == "" || in.Summary == "" {
		return errors.New("title ve summary zorunlu")
	}
	switch in.Classification {
	case "attack", "suspicious", "benign", "misconfiguration", "unknown":
	default:
		return fmt.Errorf("geçersiz classification %q", in.Classification)
	}
	switch in.Severity {
	case "info", "low", "medium", "high", "critical":
	default:
		return fmt.Errorf("geçersiz severity %q", in.Severity)
	}
	if in.Confidence < 0 {
		in.Confidence = 0
	}
	if in.Confidence > 1 {
		in.Confidence = 1
	}
	valid := map[string]bool{"threshold_change": true, "new_rule": true, "flowspec": true, "scrub": true, "rtbh": true, "whitelist": true, "investigate": true, "no_action": true}
	for i, r := range in.Recommendations {
		if !valid[r.Type] {
			return fmt.Errorf("recommendations[%d]: geçersiz type %q", i, r.Type)
		}
		if r.Type == "flowspec" && (r.FlowSpec == nil || r.FlowSpec.Target == "") {
			return fmt.Errorf("recommendations[%d]: flowspec önerisi flowspec.target içermeli", i)
		}
	}
	f.Title, f.Summary, f.Classification, f.Severity, f.Confidence = in.Title, in.Summary, in.Classification, in.Severity, in.Confidence
	f.Targets, f.Hypothesis, f.MissedReason = in.Targets, in.Hypothesis, in.MissedReason
	if in.Evidence != nil {
		f.Evidence = in.Evidence
	}
	if in.Recommendations != nil {
		f.Recommendations = in.Recommendations
	}
	if len(in.SignalIDs) > 0 {
		f.SignalIDs = in.SignalIDs
	}
	return nil
}

func (a *Analyst) pruneLocked() {
	if len(a.findings) <= maxFindings {
		return
	}
	all := make([]*Finding, 0, len(a.findings))
	for _, f := range a.findings {
		all = append(all, f)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].CreatedAt < all[j].CreatedAt })
	for _, f := range all[:len(all)-maxFindings] {
		delete(a.findings, f.ID)
	}
}

func (a *Analyst) saveLocked() {
	dump := struct {
		Seq      int        `json:"seq"`
		Findings []*Finding `json:"findings"`
	}{Seq: a.seq}
	for _, f := range a.findings {
		dump.Findings = append(dump.Findings, f)
	}
	if err := a.eng.SaveJSON("findings.json", dump); err != nil {
		a.log.Warn("persist findings", "err", err)
	}
}

// Findings returns findings newest first.
func (a *Analyst) Findings(limit int) []Finding {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]Finding, 0, len(a.findings))
	for _, f := range a.findings {
		c := *f
		c.Trace = nil
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Get returns a finding including its trace.
func (a *Analyst) Get(id string) *Finding {
	a.mu.Lock()
	defer a.mu.Unlock()
	if f := a.findings[id]; f != nil {
		c := *f
		c.Trace = append([]TraceStep{}, f.Trace...)
		c.Recommendations = append([]Recommendation{}, f.Recommendations...)
		return &c
	}
	return nil
}

// MarkApplied records that a recommendation was turned into a mitigation or rule change.
func (a *Analyst) MarkApplied(id string, idx int, ref string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	f := a.findings[id]
	if f == nil || idx < 0 || idx >= len(f.Recommendations) {
		return errors.New("öneri bulunamadı")
	}
	f.Recommendations[idx].Applied = ref
	a.saveLocked()
	return nil
}
