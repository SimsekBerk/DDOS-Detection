// Package mitigation turns detected attack vectors into FlowSpec / RTBH /
// scrubbing requests, enforces safety guardrails, manages approvals and TTLs
// and drives BGP speakers or webhooks.
package mitigation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/config"
	"github.com/SimsekBerk/DDOS-Detection/internal/engine"
	"github.com/SimsekBerk/DDOS-Detection/internal/flow"
	"github.com/SimsekBerk/DDOS-Detection/internal/flowstore"
	"github.com/SimsekBerk/DDOS-Detection/internal/rules"
)

// Event is an entry in a mitigation's audit history.
type Event struct {
	T      int64  `json:"t"`
	Status string `json:"status"`
	Actor  string `json:"actor"`
	Msg    string `json:"msg,omitempty"`
}

// Mitigation is one mitigation action and its lifecycle.
type Mitigation struct {
	ID          string            `json:"id"`
	IncidentID  string            `json:"incident_id,omitempty"`
	RuleID      string            `json:"rule_id,omitempty"`
	FindingID   string            `json:"finding_id,omitempty"`
	Target      string            `json:"target"`
	Kind        string            `json:"kind"`   // flowspec | rtbh | scrub
	Status      string            `json:"status"` // pending | active | withdrawn | rejected | failed | expired
	Source      string            `json:"source"` // rule | analyst | manual
	FlowSpec    *FlowSpec         `json:"flowspec,omitempty"`
	RTBH        *RTBH             `json:"rtbh,omitempty"`
	Reason      string            `json:"reason"`
	Note        string            `json:"note,omitempty"`
	Guardrails  []string          `json:"guardrails"`
	Rendered    map[string]string `json:"rendered,omitempty"`
	Driver      string            `json:"driver"`
	CreatedAt   int64             `json:"created_at"`
	ActivatedAt int64             `json:"activated_at,omitempty"`
	ExpiresAt   int64             `json:"expires_at,omitempty"`
	WithdrawAt  int64             `json:"withdraw_at,omitempty"`
	EndedAt     int64             `json:"ended_at,omitempty"`
	Error       string            `json:"error,omitempty"`
	History     []Event           `json:"history"`
}

func (m *Mitigation) log(status, actor, msg string) {
	m.Status = status
	m.History = append(m.History, Event{T: time.Now().Unix(), Status: status, Actor: actor, Msg: msg})
}

// Request is a manual/analyst mitigation request.
type Request struct {
	IncidentID string    `json:"incident_id,omitempty"`
	FindingID  string    `json:"finding_id,omitempty"`
	Kind       string    `json:"kind"`
	FlowSpec   *FlowSpec `json:"flowspec,omitempty"`
	RTBHPrefix string    `json:"rtbh_prefix,omitempty"`
	Reason     string    `json:"reason"`
	Source     string    `json:"source"`
}

// Driver applies mitigations to the network.
type Driver interface {
	Name() string
	Announce(m *Mitigation) error
	Withdraw(m *Mitigation) error
}

type Manager struct {
	cfg    config.MitigationConfig
	eng    *engine.Engine
	driver Driver
	log    *slog.Logger
	// OnEvent is called (in a goroutine) on lifecycle changes:
	// pending, active, withdrawn, expired, rejected, failed.
	OnEvent func(event string, m *Mitigation)

	mu   sync.Mutex
	byID map[string]*Mitigation
	seq  int
}

func New(cfg *config.Config, eng *engine.Engine, log *slog.Logger) (*Manager, error) {
	m := &Manager{cfg: cfg.Mitigation, eng: eng, log: log, byID: map[string]*Mitigation{}}
	m.driver = newDriver(cfg.Mitigation, log)
	var dump struct {
		Seq         int           `json:"seq"`
		Mitigations []*Mitigation `json:"mitigations"`
	}
	if err := eng.LoadJSON("mitigations.json", &dump); err == nil {
		m.seq = dump.Seq
		now := time.Now().Unix()
		for _, x := range dump.Mitigations {
			// Pending requests belong to incidents that can no longer be
			// observed after a restart; active rules stay (they are still on
			// the routers and keep their TTL).
			if x.Status == "pending" {
				x.EndedAt = now
				x.log("expired", "system", "süreç yeniden başladı; talep geçersiz")
			}
			m.byID[x.ID] = x
		}
	}
	return m, nil
}

func newDriver(c config.MitigationConfig, log *slog.Logger) Driver {
	switch c.Driver {
	case "exabgp":
		return &exabgpDriver{path: c.ExaBGP.CommandFile}
	case "webhook":
		return &webhookDriver{url: c.Webhook.URL, secret: c.Webhook.Secret}
	}
	return &dryRunDriver{log: log}
}

// UpdateConfig applies mitigation policy changes at runtime. Active rules
// stay announced; a driver change applies to future announcements and
// withdrawals.
func (m *Manager) UpdateConfig(cfg *config.Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	old := m.cfg
	m.cfg = cfg.Mitigation
	if old.Driver != m.cfg.Driver || old.ExaBGP != m.cfg.ExaBGP || old.Webhook != m.cfg.Webhook {
		m.driver = newDriver(m.cfg, m.log)
	}
}

func (m *Manager) emit(event string, x *Mitigation) {
	if m.OnEvent != nil {
		c := x.copy()
		go m.OnEvent(event, c)
	}
}

// DriverName returns the active driver.
func (m *Manager) DriverName() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.driver.Name()
}

// Mode returns the configured mode.
func (m *Manager) Mode() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.Mode
}

func (m *Manager) nextID() string {
	m.seq++
	return fmt.Sprintf("MIT-%05d", m.seq)
}

// ------------------------------------------------------------- engine hooks

// VectorStarted implements engine.Hooks.
func (m *Manager) VectorStarted(inc *engine.Incident, ruleID string) {
	m.mu.Lock()
	cfg := m.cfg
	m.mu.Unlock()
	if cfg.Mode == "off" {
		return
	}
	set := m.eng.Rules()
	c := set.ByID[ruleID]
	if c == nil {
		return
	}
	var vec *engine.Vector
	for _, v := range inc.Vectors {
		if v.RuleID == ruleID {
			vec = v
		}
	}
	if vec == nil {
		return
	}
	var reqs []*Mitigation
	base := func(kind string) *Mitigation {
		return &Mitigation{
			IncidentID: inc.ID, RuleID: c.ID, Target: inc.Target, Kind: kind, Source: "rule",
			Reason: fmt.Sprintf("%s: %s", c.Name, vec.Reason), Note: c.Mitigation.Note,
		}
	}
	switch c.Mitigation.Action {
	case "flowspec-discard", "flowspec-rate-limit":
		if inc.Scope == "object" {
			x := base("scrub")
			x.Note = "Nesne kapsamındaki saldırı için tek bir FlowSpec hedefi yok; scrubbing'e yönlendirme önerilir."
			reqs = append(reqs, x)
			break
		}
		fs := buildFlowSpec(c, inc)
		x := base("flowspec")
		x.FlowSpec = fs
		reqs = append(reqs, x)
	case "scrub":
		reqs = append(reqs, base("scrub"))
	case "rtbh":
		if inc.Scope == "host" {
			x := base("rtbh")
			x.RTBH = m.rtbhFor(cfg, inc.Target)
			reqs = append(reqs, x)
		}
	}
	// RTBH escalation: only for single hosts and only as a manual decision.
	if c.Mitigation.RTBHEscalation > 0 && inc.Scope == "host" && inc.Direction == "inbound" &&
		inc.LinkCapacity > 0 && inc.PeakBPS >= c.Mitigation.RTBHEscalation*inc.LinkCapacity && cfg.AllowRTBH {
		x := base("rtbh")
		x.RTBH = m.rtbhFor(cfg, inc.Target)
		x.Reason = fmt.Sprintf("Eskalasyon: tepe %.2f Gbps, bağlantı kapasitesinin %%%.0f'ini aştı", inc.PeakBPS/1e9, 100*c.Mitigation.RTBHEscalation)
		x.Note = "RTBH hedefi tamamen erişilemez kılar; yalnızca bağlantının tamamı tehlikedeyse onaylayın."
		reqs = append(reqs, x)
	}
	for _, x := range reqs {
		m.submit(x, cfg.Mode == "auto" && x.Kind != "rtbh")
	}
}

// IncidentEnded implements engine.Hooks: schedule withdrawal after a quiet period.
func (m *Manager) IncidentEnded(inc *engine.Incident) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().Unix()
	for _, x := range m.byID {
		if x.IncidentID != inc.ID {
			continue
		}
		switch x.Status {
		case "active":
			x.WithdrawAt = now + int64(m.cfg.WithdrawAfter.Seconds())
			x.History = append(x.History, Event{T: now, Status: x.Status, Actor: "system", Msg: "olay bitti; geri çekme zamanlandı"})
		case "pending":
			m.setStatus(x, "expired", "system", "olay onaydan önce bitti")
			x.EndedAt = now
		}
	}
	m.saveLocked()
}

// setStatus records a lifecycle change and emits an event.
func (m *Manager) setStatus(x *Mitigation, status, actor, msg string) {
	x.log(status, actor, msg)
	m.emit(status, x)
}

// rtbhFor builds an RTBH announcement.
func (m *Manager) rtbhFor(cfg config.MitigationConfig, target string) *RTBH {
	a, err := netip.ParseAddr(target)
	if err != nil {
		return nil
	}
	nh := cfg.ExaBGP.RTBHNextHop
	if nh == "" {
		if a.Is4() {
			nh = "192.0.2.1"
		} else {
			nh = "100::1"
		}
	}
	return &RTBH{Prefix: netip.PrefixFrom(a, a.BitLen()).String(), NextHop: nh, Community: cfg.ExaBGP.RTBHCommunity}
}

// buildFlowSpec derives the narrowest FlowSpec rule from the rule match and evidence.
func buildFlowSpec(c *rules.Compiled, inc *engine.Incident) *FlowSpec {
	fs := &FlowSpec{Action: "discard"}
	if c.Mitigation.Action == "flowspec-rate-limit" {
		fs.Action = "rate-limit"
		fs.RateBps = float64(c.Mitigation.Rate)
	}
	prefix := inc.Target
	if inc.Scope == "host" {
		if a, err := netip.ParseAddr(inc.Target); err == nil {
			prefix = netip.PrefixFrom(a, a.BitLen()).String()
		}
	}
	if inc.Direction == "outbound" {
		fs.Source = prefix
	} else {
		fs.Destination = prefix
	}
	fs.Protocols = append(fs.Protocols, c.Match.Protocols...)
	var bd = evidenceBreakdown(inc)
	if len(fs.Protocols) == 0 && bd != nil && len(bd.Protocols) > 0 {
		fs.Protocols = []string{bd.Protocols[0].Key}
	}
	src := c.Match.SrcPorts
	// Wide port lists (carpet/generic rules) are narrowed to what is observed.
	if (len(src) > 4 || (len(src) == 1 && strings.Contains(src[0], "-"))) && bd != nil {
		var observed []string
		for _, row := range bd.TopSrcPorts {
			if row.Share < 0.1 || len(observed) >= 3 {
				break
			}
			if i := strings.LastIndex(row.Key, "/"); i > 0 {
				observed = append(observed, row.Key[i+1:])
			}
		}
		if len(observed) > 0 {
			src = observed
		}
	}
	fs.SrcPorts = append(fs.SrcPorts, src...)
	fs.DstPorts = append(fs.DstPorts, c.Match.DstPorts...)
	if c.Mitigation.PacketLength && c.Match.MinPacketSize > 0 {
		fs.PacketLength = ">=" + strconv.Itoa(int(c.Match.MinPacketSize))
	}
	if c.Match.Fragment != nil && *c.Match.Fragment {
		fs.Fragment = true
	}
	if t := c.Match.TCPFlags; t != nil {
		fs.TCPSet = append(fs.TCPSet, t.All...)
		fs.TCPNotSet = append(fs.TCPNotSet, t.None...)
	}
	fs.ICMPTypes = append(fs.ICMPTypes, c.Match.ICMPTypes...)
	return fs
}

func evidenceBreakdown(inc *engine.Incident) *flowstore.Breakdown {
	if inc.Evidence == nil {
		return nil
	}
	return inc.Evidence.Breakdown
}

// --------------------------------------------------------------- guardrails

// guard checks safety rules; returns notes and an error if the request must be rejected.
func (m *Manager) guard(x *Mitigation) ([]string, error) {
	var notes []string
	check := func(prefix string) error {
		p, err := netip.ParsePrefix(prefix)
		if err != nil {
			return fmt.Errorf("geçersiz prefix %q", prefix)
		}
		if p.Addr().Is4() && p.Bits() < m.cfg.MinPrefixV4 || p.Addr().Is6() && p.Bits() < m.cfg.MinPrefixV6 {
			return fmt.Errorf("prefix %s çok geniş (min /%d v4, /%d v6)", p, m.cfg.MinPrefixV4, m.cfg.MinPrefixV6)
		}
		obj := m.eng.LookupObject(p.Addr())
		if obj == nil {
			return fmt.Errorf("%s korunan bir nesnenin içinde değil", p)
		}
		inside := false
		for _, op := range obj.Prefixes {
			if op.Bits() <= p.Bits() && op.Contains(p.Addr()) {
				inside = true
			}
		}
		if !inside {
			return fmt.Errorf("%s, %s nesnesinin prefixlerini aşıyor", p, obj.Name)
		}
		for _, n := range m.cfg.NeverParsed {
			if n.Overlaps(p) {
				return fmt.Errorf("%s 'never_mitigate' listesindeki %s ile çakışıyor", p, n)
			}
		}
		notes = append(notes, fmt.Sprintf("✓ %s korunan nesne %q içinde", p, obj.Name), "✓ never_mitigate listesiyle çakışma yok", fmt.Sprintf("✓ prefix uzunluğu /%d uygun", p.Bits()))
		return nil
	}
	switch x.Kind {
	case "flowspec":
		if x.FlowSpec == nil {
			return nil, errors.New("flowspec tanımı yok")
		}
		if err := x.FlowSpec.Validate(); err != nil {
			return nil, err
		}
		pfx := x.FlowSpec.Destination
		if pfx == "" {
			pfx = x.FlowSpec.Source
		}
		if err := check(pfx); err != nil {
			return nil, err
		}
		if len(x.FlowSpec.Protocols) == 0 && len(x.FlowSpec.SrcPorts) == 0 && len(x.FlowSpec.DstPorts) == 0 && x.FlowSpec.Action == "discard" {
			return nil, errors.New("protokol/port olmadan hedefin tüm trafiğini discard etmek FlowSpec ile yapılmaz (RTBH ile eşdeğer)")
		}
	case "rtbh":
		if !m.cfg.AllowRTBH {
			return nil, errors.New("RTBH yapılandırmada kapalı (mitigation.allow_rtbh)")
		}
		if x.RTBH == nil {
			return nil, errors.New("RTBH hedefi yok")
		}
		p, err := netip.ParsePrefix(x.RTBH.Prefix)
		if err != nil || p.Bits() != p.Addr().BitLen() {
			return nil, errors.New("RTBH yalnızca tek host (/32, /128) için uygulanır")
		}
		if err := check(x.RTBH.Prefix); err != nil {
			return nil, err
		}
		notes = append(notes, "⚠ RTBH hedefi tamamen erişilemez kılar")
	case "scrub":
		notes = append(notes, "Scrubbing yönlendirmesi webhook/entegrasyon üzerinden talep edilir")
	default:
		return nil, fmt.Errorf("bilinmeyen tür %q", x.Kind)
	}
	active := 0
	for _, o := range m.byID {
		if o.Status == "active" {
			active++
		}
	}
	if active >= m.cfg.MaxActive {
		return nil, fmt.Errorf("aktif kural sınırı (%d) dolu", m.cfg.MaxActive)
	}
	notes = append(notes, fmt.Sprintf("✓ aktif kural sayısı %d/%d", active, m.cfg.MaxActive))
	// Duplicate check.
	for _, o := range m.byID {
		if (o.Status == "active" || o.Status == "pending") && o.Kind == x.Kind && o.summary() == x.summary() {
			return nil, fmt.Errorf("aynı kural zaten %s durumunda (%s)", o.Status, o.ID)
		}
	}
	return notes, nil
}

func (x *Mitigation) summary() string {
	switch {
	case x.FlowSpec != nil:
		return x.FlowSpec.Summary()
	case x.RTBH != nil:
		return "rtbh " + x.RTBH.Prefix
	}
	return x.Kind + " " + x.Target + " " + x.IncidentID
}

// submit validates and stores a mitigation; apply=true activates it immediately.
func (m *Manager) submit(x *Mitigation, apply bool) (*Mitigation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	x.ID = m.nextID()
	x.CreatedAt = time.Now().Unix()
	x.Driver = m.driver.Name()
	notes, err := m.guard(x)
	x.Guardrails = notes
	x.Rendered = x.render()
	if err != nil {
		x.Error = err.Error()
		m.setStatus(x, "rejected", "guardrail", err.Error())
		m.byID[x.ID] = x
		m.attach(x)
		m.saveLocked()
		m.log.Warn("mitigation rejected by guardrail", "id", x.ID, "err", err)
		return x, err
	}
	m.setStatus(x, "pending", x.Source, "onay bekliyor")
	m.byID[x.ID] = x
	m.attach(x)
	if apply {
		m.activateLocked(x, "auto")
	}
	m.saveLocked()
	return x, nil
}

func (m *Manager) attach(x *Mitigation) {
	if x.IncidentID != "" {
		go m.eng.Incidents().AttachMitigation(x.IncidentID, x.ID)
	}
}

func (m *Manager) activateLocked(x *Mitigation, actor string) {
	if err := m.driver.Announce(x); err != nil {
		x.Error = err.Error()
		m.setStatus(x, "failed", actor, err.Error())
		return
	}
	now := time.Now().Unix()
	x.ActivatedAt = now
	x.ExpiresAt = now + int64(m.cfg.DefaultTTL.Seconds())
	m.setStatus(x, "active", actor, "sürücü: "+m.driver.Name())
	m.log.Info("mitigation activated", "id", x.ID, "kind", x.Kind, "target", x.Target, "driver", m.driver.Name())
}

func (m *Manager) withdrawLocked(x *Mitigation, actor, msg, status string) {
	if err := m.driver.Withdraw(x); err != nil {
		x.Error = err.Error()
		m.setStatus(x, "failed", actor, "geri çekme hatası: "+err.Error())
		return
	}
	x.EndedAt = time.Now().Unix()
	m.setStatus(x, status, actor, msg)
	m.log.Info("mitigation withdrawn", "id", x.ID, "reason", msg)
}

// ------------------------------------------------------------- operator API

// Create submits a manual or analyst mitigation (always requires approval).
func (m *Manager) Create(req Request, actor string) (*Mitigation, error) {
	if m.cfg.Mode == "off" {
		return nil, errors.New("mitigasyon yapılandırmada kapalı (mode: off)")
	}
	src := req.Source
	if src == "" {
		src = "manual"
	}
	x := &Mitigation{IncidentID: req.IncidentID, FindingID: req.FindingID, Kind: req.Kind, Source: src, Reason: req.Reason}
	switch req.Kind {
	case "flowspec":
		x.FlowSpec = req.FlowSpec
		if x.FlowSpec != nil {
			x.Target = x.FlowSpec.Destination
			if x.Target == "" {
				x.Target = x.FlowSpec.Source
			}
		}
	case "rtbh":
		p, err := netip.ParsePrefix(req.RTBHPrefix)
		if err != nil {
			a, err2 := netip.ParseAddr(req.RTBHPrefix)
			if err2 != nil {
				return nil, fmt.Errorf("geçersiz RTBH hedefi")
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		m.mu.Lock()
		cfg := m.cfg
		m.mu.Unlock()
		x.RTBH = m.rtbhFor(cfg, p.Addr().String())
		x.Target = p.Addr().String()
	case "scrub":
		x.Target = req.RTBHPrefix
	default:
		return nil, fmt.Errorf("bilinmeyen tür %q", req.Kind)
	}
	if x.Reason == "" {
		x.Reason = "Operatör tarafından oluşturuldu (" + actor + ")"
	}
	return m.submit(x, false)
}

// Approve activates a pending mitigation.
func (m *Manager) Approve(id, actor string) (*Mitigation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	x := m.byID[id]
	if x == nil {
		return nil, errors.New("bulunamadı")
	}
	if x.Status != "pending" {
		return nil, fmt.Errorf("durum %s; yalnızca pending onaylanabilir", x.Status)
	}
	m.activateLocked(x, actor)
	m.saveLocked()
	return x.copy(), nil
}

// Reject discards a pending mitigation.
func (m *Manager) Reject(id, actor, reason string) (*Mitigation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	x := m.byID[id]
	if x == nil {
		return nil, errors.New("bulunamadı")
	}
	if x.Status != "pending" {
		return nil, fmt.Errorf("durum %s; yalnızca pending reddedilebilir", x.Status)
	}
	x.EndedAt = time.Now().Unix()
	m.setStatus(x, "rejected", actor, reason)
	m.saveLocked()
	return x.copy(), nil
}

// Withdraw removes an active mitigation.
func (m *Manager) Withdraw(id, actor string) (*Mitigation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	x := m.byID[id]
	if x == nil {
		return nil, errors.New("bulunamadı")
	}
	if x.Status != "active" {
		return nil, fmt.Errorf("durum %s; yalnızca active geri çekilebilir", x.Status)
	}
	m.withdrawLocked(x, actor, "operatör geri çekti", "withdrawn")
	m.saveLocked()
	return x.copy(), nil
}

// Extend pushes the TTL of an active mitigation.
func (m *Manager) Extend(id, actor string, d time.Duration) (*Mitigation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	x := m.byID[id]
	if x == nil || x.Status != "active" {
		return nil, errors.New("aktif mitigasyon bulunamadı")
	}
	x.ExpiresAt += int64(d.Seconds())
	x.WithdrawAt = 0
	x.History = append(x.History, Event{T: time.Now().Unix(), Status: x.Status, Actor: actor, Msg: "TTL uzatıldı: " + d.String()})
	m.saveLocked()
	return x.copy(), nil
}

func (x *Mitigation) copy() *Mitigation {
	c := *x
	c.History = append([]Event{}, x.History...)
	c.Guardrails = append([]string{}, x.Guardrails...)
	return &c
}

// List returns mitigations (newest first), optionally by status.
func (m *Manager) List(status string) []*Mitigation {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []*Mitigation{}
	for _, x := range m.byID {
		if status == "" || x.Status == status {
			out = append(out, x.copy())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}

// Get returns one mitigation.
func (m *Manager) Get(id string) *Mitigation {
	m.mu.Lock()
	defer m.mu.Unlock()
	if x := m.byID[id]; x != nil {
		return x.copy()
	}
	return nil
}

// Counts returns pending and active counts.
func (m *Manager) Counts() (pending, active int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.byID {
		switch x.Status {
		case "pending":
			pending++
		case "active":
			active++
		}
	}
	return
}

// Run handles TTL expiry and scheduled withdrawals.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := time.Now().Unix()
			m.mu.Lock()
			changed := false
			for _, x := range m.byID {
				if x.Status != "active" {
					continue
				}
				switch {
				case x.WithdrawAt > 0 && now >= x.WithdrawAt:
					m.withdrawLocked(x, "system", "olay bitti, sessiz dönem doldu", "withdrawn")
					changed = true
				case x.ExpiresAt > 0 && now >= x.ExpiresAt:
					m.withdrawLocked(x, "system", "TTL doldu", "expired")
					changed = true
				}
			}
			if changed {
				m.saveLocked()
			}
			m.mu.Unlock()
		}
	}
}

func (m *Manager) saveLocked() {
	dump := struct {
		Seq         int           `json:"seq"`
		Mitigations []*Mitigation `json:"mitigations"`
	}{Seq: m.seq}
	for _, x := range m.byID {
		dump.Mitigations = append(dump.Mitigations, x.copy())
	}
	go func() {
		if err := m.eng.SaveJSON("mitigations.json", dump); err != nil {
			m.log.Warn("persist mitigations", "err", err)
		}
	}()
}

// FlowSpecFromHint builds a FlowSpec from a simplified analyst recommendation.
func FlowSpecFromHint(target, direction, protocol string, srcPorts, dstPorts []int, minLen int, action string, rateBps float64) (*FlowSpec, error) {
	p, err := netip.ParsePrefix(target)
	if err != nil {
		a, err2 := netip.ParseAddr(target)
		if err2 != nil {
			return nil, fmt.Errorf("geçersiz hedef %q", target)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	fs := &FlowSpec{Action: action, RateBps: rateBps}
	if fs.Action == "" {
		fs.Action = "discard"
	}
	if direction == "outbound" {
		fs.Source = p.String()
	} else {
		fs.Destination = p.String()
	}
	if protocol != "" {
		if _, ok := flow.ProtoNumber(protocol); !ok {
			return nil, fmt.Errorf("geçersiz protokol %q", protocol)
		}
		fs.Protocols = []string{protocol}
	}
	for _, sp := range srcPorts {
		fs.SrcPorts = append(fs.SrcPorts, strconv.Itoa(sp))
	}
	for _, dp := range dstPorts {
		fs.DstPorts = append(fs.DstPorts, strconv.Itoa(dp))
	}
	if minLen > 0 {
		fs.PacketLength = ">=" + strconv.Itoa(minLen)
	}
	return fs, fs.Validate()
}
