// Package app wires all components together and owns the configuration:
// runtime apply (hot reload), persistence with history and rollback, and
// fan-out of lifecycle events to mitigation and notifications.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/analyst"
	"github.com/SimsekBerk/DDOS-Detection/internal/audit"
	"github.com/SimsekBerk/DDOS-Detection/internal/auth"
	"github.com/SimsekBerk/DDOS-Detection/internal/collector"
	"github.com/SimsekBerk/DDOS-Detection/internal/config"
	"github.com/SimsekBerk/DDOS-Detection/internal/engine"
	"github.com/SimsekBerk/DDOS-Detection/internal/flowstore"
	"github.com/SimsekBerk/DDOS-Detection/internal/mitigation"
	"github.com/SimsekBerk/DDOS-Detection/internal/notify"
	"github.com/SimsekBerk/DDOS-Detection/internal/sim"
	"github.com/SimsekBerk/DDOS-Detection/internal/store"
)

type App struct {
	Path    string
	Log     *slog.Logger
	Started int64

	Store *flowstore.Store
	Eng   *engine.Engine
	Col   *collector.Collector
	Mit   *mitigation.Manager
	Ana   *analyst.Analyst
	Notif *notify.Notifier
	Sim   *sim.Simulator
	Users *auth.Store
	Audit *audit.Log

	mu      sync.RWMutex
	cfg     *config.Config
	boot    *config.Config // configuration the process started with
	pending []string       // settings that differ from boot and need a restart
	applyMu sync.Mutex
}

// New loads the configuration and builds all components.
func New(path string, log *slog.Logger) (*App, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return nil, err
	}
	a := &App{Path: path, Log: log, cfg: cfg, boot: cfg.Clone(), Started: time.Now().Unix()}
	a.Store = flowstore.New(cfg.Engine.RecentFlows)
	if a.Eng, err = engine.New(cfg, a.Store, log); err != nil {
		return nil, err
	}
	a.Col = collector.New(cfg, a.Eng.Submit, a.Eng.Classify, log)
	if a.Mit, err = mitigation.New(cfg, a.Eng, log); err != nil {
		return nil, err
	}
	a.Notif = notify.New(cfg, log)
	a.Ana = analyst.New(cfg, a.Eng, a.Col, log)
	if a.Users, err = auth.Open(cfg.DataDir, cfg.API.SessionTTL.Duration, cfg.API.Username, cfg.API.Password, log); err != nil {
		return nil, err
	}
	if a.Audit, err = audit.Open(cfg.DataDir); err != nil {
		return nil, err
	}
	a.Eng.SetHooks(a)
	a.Mit.OnEvent = a.mitigationEvent
	a.Ana.OnFinding = a.findingEvent
	if cfg.Demo.Enabled {
		var prefixes []netip.Prefix
		for _, o := range cfg.Objects {
			prefixes = append(prefixes, o.Parsed...)
		}
		if a.Sim, err = sim.New(cfg.Demo.Encoder, cfg.Demo.SamplingRate, cfg.Demo.Target, prefixes, float64(cfg.Demo.BaselineBPS)); err != nil {
			return nil, fmt.Errorf("demo simulator: %w", err)
		}
		a.Sim.SetBaseline(cfg.Demo.Baseline, 0)
	}
	return a, nil
}

// Run starts all background components and blocks until ctx is done or a
// component fails.
func (a *App) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	errc := make(chan error, 1)
	start := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f() }()
	}
	start(func() { a.Eng.Run(ctx) })
	start(func() { a.Mit.Run(ctx) })
	start(func() { a.Ana.Loop(ctx) })
	start(func() { a.Notif.Run(ctx) })
	start(func() {
		if err := a.Col.Run(ctx); err != nil {
			select {
			case errc <- fmt.Errorf("collector: %w", err):
			default:
			}
		}
	})
	if a.Sim != nil {
		start(func() { a.Sim.Loop(ctx) })
	}
	var err error
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	wg.Wait()
	_ = a.Audit.Close()
	return err
}

// Config returns the active configuration (do not modify).
func (a *App) Config() *config.Config {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cfg
}

// RestartPending lists applied settings that need a restart.
func (a *App) RestartPending() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return append([]string{}, a.pending...)
}

// ApplyResult describes a configuration change.
type ApplyResult struct {
	Version         string   `json:"version"`
	RestartRequired []string `json:"restart_required"`
}

// HistoryEntry is one saved configuration version.
type HistoryEntry struct {
	ID      string   `json:"id"`
	Time    int64    `json:"time"`
	Actor   string   `json:"actor"`
	Comment string   `json:"comment"`
	Restart []string `json:"restart_required,omitempty"`
}

func (a *App) historyDir() string { return filepath.Join(a.Config().DataDir, "config-history") }

// Apply validates, applies at runtime and persists a new configuration.
// The previous file is kept in the history for rollback.
func (a *App) Apply(next *config.Config, actor, comment string) (ApplyResult, error) {
	a.applyMu.Lock()
	defer a.applyMu.Unlock()
	cur := a.Config()
	next.RestoreSecrets(cur)
	if err := next.Normalize(); err != nil {
		return ApplyResult{}, err
	}
	// Validate against loaded rule profiles before touching anything.
	set := a.Eng.Rules()
	for _, o := range next.Objects {
		if _, ok := set.Profiles[o.Profile]; !ok {
			return ApplyResult{}, fmt.Errorf("korunan nesne %q bilinmeyen profil kullanıyor: %q", o.Name, o.Profile)
		}
	}
	restart := config.RestartRequired(cur, next)
	// Persist first: if the disk write fails, nothing changes.
	id, err := a.persist(cur, next, actor, comment, restart)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("yapılandırma kaydedilemedi: %w", err)
	}
	if err := a.Eng.UpdateConfig(next); err != nil {
		return ApplyResult{}, err
	}
	a.Col.Update(next)
	a.Mit.UpdateConfig(next)
	a.Ana.UpdateConfig(next)
	a.Notif.Update(next)
	a.Users.SetTTL(next.API.SessionTTL.Duration)
	a.mu.Lock()
	// Restart-only settings keep their boot values until restart; compare
	// with boot so that reverting a change clears the pending notice.
	a.pending = config.RestartRequired(a.boot, next)
	a.cfg = next
	a.mu.Unlock()
	a.Log.Info("configuration applied", "actor", actor, "version", id, "restart_required", restart)
	return ApplyResult{Version: id, RestartRequired: restart}, nil
}

// writeConfigFile replaces the file atomically (temp file + rename). When
// that is impossible, e.g. the file is a single-file bind mount in a
// container or the directory is not writable, it rewrites the file in place.
func writeConfigFile(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		if err := os.Rename(tmp, path); err == nil {
			return nil
		}
		_ = os.Remove(tmp)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// ConfigWritable reports whether configuration changes can be saved.
func (a *App) ConfigWritable() bool {
	f, err := os.OpenFile(a.Path, os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

func (a *App) persist(cur, next *config.Config, actor, comment string, restart []string) (string, error) {
	dir := a.historyDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	id := time.Now().Format("20060102-150405.000")
	id = strings.ReplaceAll(id, ".", "-")
	// keep the previous active file as a restorable version
	if old, err := os.ReadFile(a.Path); err == nil {
		_ = os.WriteFile(filepath.Join(dir, id+"-onceki.yaml"), old, 0o600)
	}
	header := fmt.Sprintf("ddosd yapılandırması\nSon değişiklik: %s, %s\n%s", time.Now().Format(time.RFC3339), actor, comment)
	b, err := config.Marshal(next, header)
	if err != nil {
		return "", err
	}
	if err := writeConfigFile(a.Path, b); err != nil {
		return "", err
	}
	_ = os.WriteFile(filepath.Join(dir, id+".yaml"), b, 0o600)
	var hist []HistoryEntry
	_ = store.Load(filepath.Join(dir, "index.json"), &hist)
	hist = append(hist, HistoryEntry{ID: id, Time: time.Now().Unix(), Actor: actor, Comment: comment, Restart: restart})
	if len(hist) > 100 {
		for _, h := range hist[:len(hist)-100] {
			_ = os.Remove(filepath.Join(dir, h.ID+".yaml"))
			_ = os.Remove(filepath.Join(dir, h.ID+"-onceki.yaml"))
		}
		hist = hist[len(hist)-100:]
	}
	return id, store.Save(filepath.Join(dir, "index.json"), hist)
}

// History lists saved versions, newest first.
func (a *App) History() []HistoryEntry {
	var hist []HistoryEntry
	_ = store.Load(filepath.Join(a.historyDir(), "index.json"), &hist)
	sort.Slice(hist, func(i, j int) bool { return hist[i].Time > hist[j].Time })
	if hist == nil {
		hist = []HistoryEntry{}
	}
	return hist
}

// Version returns the YAML of a saved version.
func (a *App) Version(id string) ([]byte, error) {
	if strings.ContainsAny(id, "/\\.") {
		return nil, errors.New("geçersiz sürüm")
	}
	return os.ReadFile(filepath.Join(a.historyDir(), id+".yaml"))
}

// Restore applies a saved version.
func (a *App) Restore(id, actor string) (ApplyResult, error) {
	b, err := a.Version(id)
	if err != nil {
		return ApplyResult{}, errors.New("sürüm bulunamadı")
	}
	next, err := config.Parse(b)
	if err != nil {
		return ApplyResult{}, err
	}
	return a.Apply(next, actor, "Geri yükleme: "+id)
}

// ------------------------------------------------------------------ events

// VectorStarted implements engine.Hooks.
func (a *App) VectorStarted(inc *engine.Incident, ruleID string) {
	a.Mit.VectorStarted(inc, ruleID)
	var v *engine.Vector
	for _, x := range inc.Vectors {
		if x.RuleID == ruleID {
			v = x
		}
	}
	if v == nil {
		return
	}
	ev := notify.Event{Severity: inc.Severity, IncidentID: inc.ID, Target: inc.Target, Object: inc.ObjectName}
	if len(inc.Vectors) == 1 && inc.Reopened == 0 {
		ev.Type = "incident.started"
		ev.Title = fmt.Sprintf("DDoS saldırısı başladı: %s (%s)", inc.Target, inc.ObjectName)
	} else {
		ev.Type = "vector.added"
		ev.Title = fmt.Sprintf("Saldırıya yeni vektör eklendi: %s (%s)", inc.Target, inc.ObjectName)
	}
	ev.Text = fmt.Sprintf("Vektör: %s — %s. Önem: %s. Olay: %s", v.RuleName, v.Reason, inc.Severity, inc.ID)
	a.Notif.Notify(ev)
}

// IncidentEnded implements engine.Hooks.
func (a *App) IncidentEnded(inc *engine.Incident) {
	a.Mit.IncidentEnded(inc)
	var names []string
	for _, v := range inc.Vectors {
		names = append(names, v.RuleName)
	}
	a.Notif.Notify(notify.Event{
		Type: "incident.ended", Severity: inc.Severity, IncidentID: inc.ID, Target: inc.Target, Object: inc.ObjectName,
		Title: fmt.Sprintf("Saldırı sona erdi: %s (%s)", inc.Target, inc.ObjectName),
		Text:  fmt.Sprintf("Süre %s, tepe %s / %s. Vektörler: %s", (time.Duration(inc.EndedAt-inc.StartedAt) * time.Second).String(), human(inc.PeakBPS, "bps"), human(inc.PeakPPS, "pps"), strings.Join(names, ", ")),
	})
}

var mitigationTitle = map[string]string{
	"pending":   "Mitigasyon onay bekliyor",
	"active":    "Mitigasyon uygulandı",
	"withdrawn": "Mitigasyon geri çekildi",
	"expired":   "Mitigasyon süresi doldu",
	"failed":    "Mitigasyon HATASI",
	"rejected":  "Mitigasyon reddedildi",
}

func (a *App) mitigationEvent(event string, m *mitigation.Mitigation) {
	title, ok := mitigationTitle[event]
	if !ok || event == "rejected" || event == "expired" {
		return
	}
	sev := "high"
	if inc := a.Eng.Incidents().Get(m.IncidentID); inc != nil {
		sev = inc.Severity
	}
	if event == "failed" {
		sev = "critical"
	}
	a.Notif.Notify(notify.Event{
		Type: "mitigation." + event, Severity: sev, MitigationID: m.ID, IncidentID: m.IncidentID, Target: m.Target,
		Title: fmt.Sprintf("%s: %s %s", title, strings.ToUpper(m.Kind), m.Target),
		Text:  strings.TrimSpace(m.Reason + " " + m.Error),
	})
}

func (a *App) findingEvent(f *analyst.Finding) {
	sev := f.Severity
	if sev == "info" {
		sev = "low"
	}
	a.Notif.Notify(notify.Event{
		Type: "finding.created", Severity: sev, FindingID: f.ID, IncidentID: f.IncidentID,
		Title: "AI analist bulgusu: " + f.Title, Text: f.Summary,
	})
}

func human(v float64, unit string) string {
	switch {
	case v >= 1e9:
		return fmt.Sprintf("%.2f G%s", v/1e9, unit)
	case v >= 1e6:
		return fmt.Sprintf("%.2f M%s", v/1e6, unit)
	case v >= 1e3:
		return fmt.Sprintf("%.1f k%s", v/1e3, unit)
	}
	return fmt.Sprintf("%.0f %s", v, unit)
}
