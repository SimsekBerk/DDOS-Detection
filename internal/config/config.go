// Package config loads, validates, edits and persists the ddosd configuration.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that (un)marshals as strings like "10s".
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("satır %d: geçersiz süre %q", n.Line, n.Value)
	}
	d.Duration = v
	return nil
}

func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		var n float64
		if err2 := json.Unmarshal(b, &n); err2 != nil {
			return err
		}
		d.Duration = time.Duration(n * float64(time.Second))
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("geçersiz süre %q", s)
	}
	d.Duration = v
	return nil
}

// Rate is a numeric value that accepts SI suffixes: "200Mbps", "1.5G", "50k".
type Rate float64

func (r *Rate) UnmarshalYAML(n *yaml.Node) error {
	v, err := ParseRate(n.Value)
	if err != nil {
		return fmt.Errorf("satır %d: %w", n.Line, err)
	}
	*r = Rate(v)
	return nil
}

// MarshalYAML writes a compact SI value ("10G", "200M", "50k").
func (r Rate) MarshalYAML() (any, error) { return FormatRate(float64(r)), nil }

func (r *Rate) UnmarshalJSON(b []byte) error {
	var n float64
	if err := json.Unmarshal(b, &n); err == nil {
		*r = Rate(n)
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := ParseRate(s)
	if err != nil {
		return err
	}
	*r = Rate(v)
	return nil
}

// FormatRate renders a value with an SI suffix without losing precision.
func FormatRate(v float64) string {
	for _, u := range []struct {
		m float64
		s string
	}{{1e12, "T"}, {1e9, "G"}, {1e6, "M"}, {1e3, "k"}} {
		if v >= u.m {
			return strconv.FormatFloat(v/u.m, 'f', -1, 64) + u.s
		}
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// ParseRate parses "10Gbps", "200Mbps", "50k", "1.2M", "1000".
func ParseRate(s string) (float64, error) {
	t := strings.TrimSpace(strings.ToLower(s))
	for _, suf := range []string{"bps", "pps", "fps", "/s"} {
		t = strings.TrimSuffix(t, suf)
	}
	mult := 1.0
	switch {
	case strings.HasSuffix(t, "t"):
		mult, t = 1e12, t[:len(t)-1]
	case strings.HasSuffix(t, "g"):
		mult, t = 1e9, t[:len(t)-1]
	case strings.HasSuffix(t, "m"):
		mult, t = 1e6, t[:len(t)-1]
	case strings.HasSuffix(t, "k"):
		mult, t = 1e3, t[:len(t)-1]
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("geçersiz değer %q", s)
	}
	return v * mult, nil
}

type Config struct {
	Collector     CollectorConfig     `yaml:"collector" json:"collector"`
	API           APIConfig           `yaml:"api" json:"api"`
	Engine        EngineConfig        `yaml:"engine" json:"engine"`
	Exporters     []ExporterConfig    `yaml:"exporters" json:"exporters"`
	Objects       []ObjectConfig      `yaml:"protected_objects" json:"protected_objects"`
	RulesDir      string              `yaml:"rules_dir" json:"rules_dir"`
	DataDir       string              `yaml:"data_dir" json:"data_dir"`
	Mitigation    MitigationConfig    `yaml:"mitigation" json:"mitigation"`
	Notifications NotificationsConfig `yaml:"notifications" json:"notifications"`
	Analyst       AnalystConfig       `yaml:"analyst" json:"analyst"`
	Demo          DemoConfig          `yaml:"demo" json:"demo"`
}

type CollectorConfig struct {
	Listen              []string `yaml:"listen" json:"listen"`
	ReadBufferBytes     int      `yaml:"read_buffer_bytes" json:"read_buffer_bytes"`
	QueueSize           int      `yaml:"queue_size" json:"queue_size"`
	DefaultSamplingRate uint32   `yaml:"default_sampling_rate" json:"default_sampling_rate"`
	// Workers decode and classify in parallel (datagrams of one exporter
	// always go to the same worker).
	Workers int `yaml:"workers" json:"workers"`
	// Allow restricts accepted exporters (IPs or prefixes). Empty = accept all.
	Allow []string `yaml:"allow" json:"allow"`
	// Forward replicates every accepted datagram to these collectors
	// (host:port), e.g. to run side by side with an existing system.
	Forward []string `yaml:"forward" json:"forward"`

	AllowParsed []netip.Prefix `yaml:"-" json:"-"`
}

type APIConfig struct {
	Listen     string   `yaml:"listen" json:"listen"`
	TLSCert    string   `yaml:"tls_cert" json:"tls_cert"`
	TLSKey     string   `yaml:"tls_key" json:"tls_key"`
	SessionTTL Duration `yaml:"session_ttl" json:"session_ttl"`
	// BaseURL is used for links in notifications (e.g. https://ddos.example.net).
	BaseURL string `yaml:"base_url" json:"base_url"`
	// Bootstrap admin, used only when the user store is empty.
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
}

type EngineConfig struct {
	Window        Duration `yaml:"window" json:"window"`
	MaxFlowSpread Duration `yaml:"max_flow_spread" json:"max_flow_spread"`
	RecentFlows   int      `yaml:"recent_flows" json:"recent_flows"`
	BaselineTau   Duration `yaml:"baseline_tau" json:"baseline_tau"`
	BaselineLearn Duration `yaml:"baseline_learn" json:"baseline_learn"`
	NearMissRatio float64  `yaml:"near_miss_ratio" json:"near_miss_ratio"`
	SignalMinZ    float64  `yaml:"signal_min_z" json:"signal_min_z"`
	SignalMinPPS  Rate     `yaml:"signal_min_pps" json:"signal_min_pps"`
	SignalMinBPS  Rate     `yaml:"signal_min_bps" json:"signal_min_bps"`
	// SignalMinSeconds: a deviation must persist this long to become a signal.
	SignalMinSeconds int      `yaml:"signal_min_seconds" json:"signal_min_seconds"`
	IncidentReopen   Duration `yaml:"incident_reopen" json:"incident_reopen"`
	EvidenceEvery    Duration `yaml:"evidence_every" json:"evidence_every"`
	// MaxSeries caps tracked (rule, target) series. When reached, new
	// host-scope series are not created (prefix/object scope still are),
	// which bounds memory during wide carpet-bombing / random-destination floods.
	MaxSeries int `yaml:"max_series" json:"max_series"`
}

type ExporterConfig struct {
	Address      string `yaml:"address" json:"address"`
	Name         string `yaml:"name" json:"name"`
	SamplingRate uint32 `yaml:"sampling_rate" json:"sampling_rate"`
}

type ObjectConfig struct {
	Name         string   `yaml:"name" json:"name"`
	Prefixes     []string `yaml:"prefixes" json:"prefixes"`
	Profile      string   `yaml:"profile" json:"profile"`
	LinkCapacity Rate     `yaml:"link_capacity" json:"link_capacity"`
	CarpetV4     int      `yaml:"carpet_prefix_v4" json:"carpet_prefix_v4"`
	CarpetV6     int      `yaml:"carpet_prefix_v6" json:"carpet_prefix_v6"`
	Notes        string   `yaml:"notes" json:"notes"`

	Parsed []netip.Prefix `yaml:"-" json:"-"`
}

type ExaBGPConfig struct {
	CommandFile   string `yaml:"command_file" json:"command_file"`
	RTBHNextHop   string `yaml:"rtbh_next_hop" json:"rtbh_next_hop"`
	RTBHCommunity string `yaml:"rtbh_community" json:"rtbh_community"`
}

type WebhookConfig struct {
	URL    string `yaml:"url" json:"url"`
	Secret string `yaml:"secret" json:"secret"`
}

type MitigationConfig struct {
	Mode          string        `yaml:"mode" json:"mode"`     // manual | auto | off
	Driver        string        `yaml:"driver" json:"driver"` // dryrun | exabgp | webhook
	DefaultTTL    Duration      `yaml:"default_ttl" json:"default_ttl"`
	WithdrawAfter Duration      `yaml:"withdraw_after" json:"withdraw_after"`
	MaxActive     int           `yaml:"max_active" json:"max_active"`
	MinPrefixV4   int           `yaml:"min_prefix_v4" json:"min_prefix_v4"`
	MinPrefixV6   int           `yaml:"min_prefix_v6" json:"min_prefix_v6"`
	AllowRTBH     bool          `yaml:"allow_rtbh" json:"allow_rtbh"`
	NeverMitigate []string      `yaml:"never_mitigate" json:"never_mitigate"`
	ExaBGP        ExaBGPConfig  `yaml:"exabgp" json:"exabgp"`
	Webhook       WebhookConfig `yaml:"webhook" json:"webhook"`

	NeverParsed []netip.Prefix `yaml:"-" json:"-"`
}

// NotificationsConfig lists alert channels.
type NotificationsConfig struct {
	Channels []ChannelConfig `yaml:"channels" json:"channels"`
}

// ChannelConfig is one notification destination.
type ChannelConfig struct {
	Name        string   `yaml:"name" json:"name"`
	Type        string   `yaml:"type" json:"type"` // webhook | slack | teams | telegram | syslog | email
	Enabled     bool     `yaml:"enabled" json:"enabled"`
	MinSeverity string   `yaml:"min_severity" json:"min_severity"` // low | medium | high | critical
	Events      []string `yaml:"events" json:"events"`             // empty = default set
	URL         string   `yaml:"url,omitempty" json:"url,omitempty"`
	Secret      string   `yaml:"secret,omitempty" json:"secret,omitempty"`
	BotToken    string   `yaml:"bot_token,omitempty" json:"bot_token,omitempty"`
	ChatID      string   `yaml:"chat_id,omitempty" json:"chat_id,omitempty"`
	Address     string   `yaml:"address,omitempty" json:"address,omitempty"`   // syslog host:port
	Protocol    string   `yaml:"protocol,omitempty" json:"protocol,omitempty"` // syslog udp | tcp
	SMTPHost    string   `yaml:"smtp_host,omitempty" json:"smtp_host,omitempty"`
	SMTPPort    int      `yaml:"smtp_port,omitempty" json:"smtp_port,omitempty"`
	Username    string   `yaml:"username,omitempty" json:"username,omitempty"`
	Password    string   `yaml:"password,omitempty" json:"password,omitempty"`
	From        string   `yaml:"from,omitempty" json:"from,omitempty"`
	To          []string `yaml:"to,omitempty" json:"to,omitempty"`
}

type OpenAICompatConfig struct {
	BaseURL   string `yaml:"base_url" json:"base_url"`
	Model     string `yaml:"model" json:"model"`
	APIKeyEnv string `yaml:"api_key_env" json:"api_key_env"`
}

type AnalystConfig struct {
	Enabled      bool               `yaml:"enabled" json:"enabled"`
	Provider     string             `yaml:"provider" json:"provider"` // anthropic | openai_compat | heuristic
	Model        string             `yaml:"model" json:"model"`
	Effort       string             `yaml:"effort" json:"effort"`
	Interval     Duration           `yaml:"interval" json:"interval"`
	Language     string             `yaml:"language" json:"language"`
	MaxTurns     int                `yaml:"max_turns" json:"max_turns"`
	MaxTokens    int                `yaml:"max_tokens" json:"max_tokens"`
	AutoRun      bool               `yaml:"auto_run" json:"auto_run"`
	OpenAICompat OpenAICompatConfig `yaml:"openai_compat" json:"openai_compat"`
}

type DemoConfig struct {
	Enabled      bool   `yaml:"enabled" json:"enabled"`
	Encoder      string `yaml:"encoder" json:"encoder"`
	SamplingRate uint32 `yaml:"sampling_rate" json:"sampling_rate"`
	Target       string `yaml:"target" json:"target"`
	Baseline     bool   `yaml:"baseline" json:"baseline"`
	BaselineBPS  Rate   `yaml:"baseline_bps" json:"baseline_bps"`
}

func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	if pfx, err := netip.ParsePrefix(s); err == nil {
		return pfx.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("geçersiz adres veya prefix %q", s)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Load reads, defaults and validates a config file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Parse decodes YAML, applies defaults and validates.
func Parse(b []byte) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if err := c.Normalize(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Normalize applies defaults and validates (idempotent).
func (c *Config) Normalize() error {
	c.applyDefaults()
	return c.validate()
}

// Marshal renders the configuration as YAML.
func Marshal(c *Config, header string) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	_ = enc.Close()
	b := buf.Bytes()
	if header != "" {
		var h strings.Builder
		for _, l := range strings.Split(strings.TrimRight(header, "\n"), "\n") {
			h.WriteString("# " + l + "\n")
		}
		b = append([]byte(h.String()+"\n"), b...)
	}
	return b, nil
}

// Clone deep-copies a configuration.
func (c *Config) Clone() *Config {
	b, _ := json.Marshal(c)
	var out Config
	_ = json.Unmarshal(b, &out)
	// non-JSON (derived) fields
	out.Collector.AllowParsed = append([]netip.Prefix(nil), c.Collector.AllowParsed...)
	out.Mitigation.NeverParsed = append([]netip.Prefix(nil), c.Mitigation.NeverParsed...)
	for i := range out.Objects {
		if i < len(c.Objects) {
			out.Objects[i].Parsed = append([]netip.Prefix(nil), c.Objects[i].Parsed...)
		}
	}
	return &out
}

// SecretMask replaces secrets in API responses.
const SecretMask = "********"

// Masked returns a copy with secrets replaced by SecretMask.
func (c *Config) Masked() *Config {
	out := c.Clone()
	mask := func(s *string) {
		if *s != "" {
			*s = SecretMask
		}
	}
	mask(&out.API.Password)
	mask(&out.Mitigation.Webhook.Secret)
	for i := range out.Notifications.Channels {
		ch := &out.Notifications.Channels[i]
		mask(&ch.Secret)
		mask(&ch.BotToken)
		mask(&ch.Password)
		if ch.Type == "slack" || ch.Type == "teams" {
			mask(&ch.URL)
		}
	}
	return out
}

// RestoreSecrets copies secrets from old where next still carries the mask.
func (next *Config) RestoreSecrets(old *Config) {
	keep := func(dst *string, src string) {
		if *dst == SecretMask {
			*dst = src
		}
	}
	keep(&next.API.Password, old.API.Password)
	keep(&next.Mitigation.Webhook.Secret, old.Mitigation.Webhook.Secret)
	byName := map[string]ChannelConfig{}
	for _, ch := range old.Notifications.Channels {
		byName[ch.Name] = ch
	}
	for i := range next.Notifications.Channels {
		ch := &next.Notifications.Channels[i]
		o := byName[ch.Name]
		keep(&ch.Secret, o.Secret)
		keep(&ch.BotToken, o.BotToken)
		keep(&ch.Password, o.Password)
		keep(&ch.URL, o.URL)
	}
}

// RestartRequired lists changed settings that only take effect after a restart.
func RestartRequired(old, next *Config) []string {
	out := []string{}
	add := func(changed bool, name string) {
		if changed {
			out = append(out, name)
		}
	}
	add(strings.Join(old.Collector.Listen, ",") != strings.Join(next.Collector.Listen, ","), "collector.listen")
	add(old.Collector.Workers != next.Collector.Workers, "collector.workers")
	add(old.Collector.ReadBufferBytes != next.Collector.ReadBufferBytes, "collector.read_buffer_bytes")
	add(old.Collector.QueueSize != next.Collector.QueueSize, "collector.queue_size")
	add(strings.Join(old.Collector.Forward, ",") != strings.Join(next.Collector.Forward, ","), "collector.forward")
	add(old.API.Listen != next.API.Listen || old.API.TLSCert != next.API.TLSCert || old.API.TLSKey != next.API.TLSKey, "api.listen/tls")
	add(old.DataDir != next.DataDir, "data_dir")
	add(old.RulesDir != next.RulesDir, "rules_dir")
	add(old.Engine.RecentFlows != next.Engine.RecentFlows, "engine.recent_flows")
	add(old.Demo != next.Demo, "demo")
	return out
}

func (c *Config) applyDefaults() {
	if len(c.Collector.Listen) == 0 {
		c.Collector.Listen = []string{":2055", ":4739", ":6343"}
	}
	if c.Collector.ReadBufferBytes == 0 {
		c.Collector.ReadBufferBytes = 16 << 20
	}
	if c.Collector.QueueSize == 0 {
		c.Collector.QueueSize = 8192
	}
	if c.Collector.DefaultSamplingRate == 0 {
		c.Collector.DefaultSamplingRate = 1
	}
	if c.Collector.Workers == 0 {
		c.Collector.Workers = min(8, max(1, runtime.NumCPU()/2))
	}
	if c.API.Listen == "" {
		c.API.Listen = ":8080"
	}
	def := func(d *Duration, v time.Duration) {
		if d.Duration == 0 {
			d.Duration = v
		}
	}
	def(&c.API.SessionTTL, 12*time.Hour)
	e := &c.Engine
	def(&e.Window, 10*time.Second)
	def(&e.MaxFlowSpread, 30*time.Second)
	def(&e.BaselineTau, 30*time.Minute)
	def(&e.BaselineLearn, 10*time.Minute)
	def(&e.IncidentReopen, 2*time.Minute)
	def(&e.EvidenceEvery, 10*time.Second)
	if e.RecentFlows == 0 {
		e.RecentFlows = 500_000
	}
	if e.MaxSeries == 0 {
		e.MaxSeries = 250_000
	}
	if e.NearMissRatio == 0 {
		e.NearMissRatio = 0.5
	}
	if e.SignalMinZ == 0 {
		e.SignalMinZ = 4
	}
	if e.SignalMinPPS == 0 {
		e.SignalMinPPS = 2000
	}
	if e.SignalMinBPS == 0 {
		e.SignalMinBPS = 20e6
	}
	if e.SignalMinSeconds == 0 {
		e.SignalMinSeconds = 10
	}
	if c.RulesDir == "" {
		c.RulesDir = "rules"
	}
	if c.DataDir == "" {
		c.DataDir = "data"
	}
	for i := range c.Objects {
		o := &c.Objects[i]
		if o.Profile == "" {
			o.Profile = "default"
		}
		if o.CarpetV4 == 0 {
			o.CarpetV4 = 24
		}
		if o.CarpetV6 == 0 {
			o.CarpetV6 = 64
		}
	}
	m := &c.Mitigation
	if m.Mode == "" {
		m.Mode = "manual"
	}
	if m.Driver == "" {
		m.Driver = "dryrun"
	}
	def(&m.DefaultTTL, 30*time.Minute)
	def(&m.WithdrawAfter, 5*time.Minute)
	if m.MaxActive == 0 {
		m.MaxActive = 50
	}
	if m.MinPrefixV4 == 0 {
		m.MinPrefixV4 = 24
	}
	if m.MinPrefixV6 == 0 {
		m.MinPrefixV6 = 48
	}
	if m.ExaBGP.RTBHCommunity == "" {
		m.ExaBGP.RTBHCommunity = "65535:666"
	}
	for i := range c.Notifications.Channels {
		c.Notifications.Channels[i].applyDefaults()
	}
	a := &c.Analyst
	if a.Provider == "" {
		a.Provider = "heuristic"
	}
	if a.Model == "" {
		a.Model = "claude-opus-5-5"
	}
	if a.Effort == "" {
		a.Effort = "high"
	}
	def(&a.Interval, 5*time.Minute)
	if a.Language == "" {
		a.Language = "tr"
	}
	if a.MaxTurns == 0 {
		a.MaxTurns = 12
	}
	if a.MaxTokens == 0 {
		a.MaxTokens = 16000
	}
	if a.OpenAICompat.BaseURL == "" {
		a.OpenAICompat.BaseURL = "http://localhost:11434/v1"
	}
	d := &c.Demo
	if d.Encoder == "" {
		d.Encoder = "netflow9"
	}
	if d.SamplingRate == 0 {
		d.SamplingRate = 1
	}
	if d.Target == "" {
		d.Target = "127.0.0.1:2055"
	}
	if d.BaselineBPS == 0 {
		d.BaselineBPS = 400e6
	}
}

var (
	validEvents   = map[string]bool{"incident.started": true, "incident.ended": true, "vector.added": true, "mitigation.pending": true, "mitigation.active": true, "mitigation.withdrawn": true, "mitigation.failed": true, "finding.created": true}
	validSeverity = map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
)

func (c *Config) validate() error {
	if c.Engine.Window.Duration < time.Second || c.Engine.Window.Duration > 30*time.Second {
		return fmt.Errorf("engine.window 1s ile 30s arasında olmalı")
	}
	if c.Engine.MaxFlowSpread.Duration > 30*time.Second {
		return fmt.Errorf("engine.max_flow_spread en fazla 30s olabilir")
	}
	if c.Engine.MaxSeries < 1000 {
		return fmt.Errorf("engine.max_series en az 1000 olmalı")
	}
	if c.Engine.NearMissRatio <= 0 || c.Engine.NearMissRatio >= 1 {
		return fmt.Errorf("engine.near_miss_ratio 0 ile 1 arasında olmalı")
	}
	if len(c.Objects) == 0 {
		return fmt.Errorf("en az bir korunan nesne (protected_objects) gerekli")
	}
	seen := map[string]bool{}
	for i := range c.Objects {
		o := &c.Objects[i]
		o.Name = strings.TrimSpace(o.Name)
		if o.Name == "" {
			return fmt.Errorf("korunan nesne %d: ad zorunlu", i+1)
		}
		if seen[o.Name] {
			return fmt.Errorf("korunan nesne adı tekrarlanıyor: %q", o.Name)
		}
		seen[o.Name] = true
		if len(o.Prefixes) == 0 {
			return fmt.Errorf("korunan nesne %q: en az bir prefix gerekli", o.Name)
		}
		o.Parsed = nil
		for _, p := range o.Prefixes {
			pfx, err := netip.ParsePrefix(strings.TrimSpace(p))
			if err != nil {
				return fmt.Errorf("korunan nesne %q: geçersiz prefix %q", o.Name, p)
			}
			o.Parsed = append(o.Parsed, pfx.Masked())
		}
		if o.CarpetV4 < 8 || o.CarpetV4 > 32 || o.CarpetV6 < 32 || o.CarpetV6 > 128 {
			return fmt.Errorf("korunan nesne %q: carpet prefix uzunluğu geçersiz", o.Name)
		}
	}
	for _, e := range c.Exporters {
		if _, err := netip.ParseAddr(e.Address); err != nil {
			return fmt.Errorf("exporter adresi geçersiz: %q", e.Address)
		}
	}
	c.Collector.AllowParsed = nil
	for _, a := range c.Collector.Allow {
		p, err := parsePrefixOrAddr(strings.TrimSpace(a))
		if err != nil {
			return fmt.Errorf("collector.allow: %w", err)
		}
		c.Collector.AllowParsed = append(c.Collector.AllowParsed, p)
	}
	for _, f := range c.Collector.Forward {
		if _, _, err := splitHostPort(f); err != nil {
			return fmt.Errorf("collector.forward: %q host:port olmalı", f)
		}
	}
	if (c.API.TLSCert == "") != (c.API.TLSKey == "") {
		return fmt.Errorf("api.tls_cert ve api.tls_key birlikte verilmeli")
	}
	if c.API.BaseURL != "" {
		if u, err := url.Parse(c.API.BaseURL); err != nil || u.Scheme == "" {
			return fmt.Errorf("api.base_url geçerli bir URL olmalı")
		}
	}
	m := &c.Mitigation
	switch m.Mode {
	case "manual", "auto", "off":
	default:
		return fmt.Errorf("mitigation.mode manual, auto veya off olmalı")
	}
	switch m.Driver {
	case "dryrun", "exabgp", "webhook":
	default:
		return fmt.Errorf("mitigation.driver dryrun, exabgp veya webhook olmalı")
	}
	if m.Driver == "exabgp" && m.ExaBGP.CommandFile == "" {
		return fmt.Errorf("exabgp sürücüsü için mitigation.exabgp.command_file gerekli")
	}
	if m.Driver == "webhook" && m.Webhook.URL == "" {
		return fmt.Errorf("webhook sürücüsü için mitigation.webhook.url gerekli")
	}
	if m.MinPrefixV4 < 8 || m.MinPrefixV4 > 32 || m.MinPrefixV6 < 16 || m.MinPrefixV6 > 128 {
		return fmt.Errorf("mitigation.min_prefix değerleri geçersiz")
	}
	m.NeverParsed = nil
	for _, p := range m.NeverMitigate {
		pfx, err := parsePrefixOrAddr(strings.TrimSpace(p))
		if err != nil {
			return fmt.Errorf("mitigation.never_mitigate: %w", err)
		}
		m.NeverParsed = append(m.NeverParsed, pfx)
	}
	names := map[string]bool{}
	for i, ch := range c.Notifications.Channels {
		if ch.Name == "" {
			return fmt.Errorf("bildirim kanalı %d: ad zorunlu", i+1)
		}
		if names[ch.Name] {
			return fmt.Errorf("bildirim kanalı adı tekrarlanıyor: %q", ch.Name)
		}
		names[ch.Name] = true
		if err := ch.check(); err != nil {
			return err
		}
	}
	switch c.Analyst.Provider {
	case "anthropic", "openai_compat", "heuristic":
	default:
		return fmt.Errorf("analyst.provider anthropic, openai_compat veya heuristic olmalı")
	}
	switch c.Analyst.Effort {
	case "low", "medium", "high", "xhigh", "max":
	default:
		return fmt.Errorf("analyst.effort low, medium, high, xhigh veya max olmalı")
	}
	if c.Analyst.MaxTurns < 2 || c.Analyst.MaxTurns > 40 {
		return fmt.Errorf("analyst.max_turns 2 ile 40 arasında olmalı")
	}
	switch c.Demo.Encoder {
	case "netflow5", "netflow9", "ipfix", "sflow":
	default:
		return fmt.Errorf("demo.encoder netflow5, netflow9, ipfix veya sflow olmalı")
	}
	return nil
}

func splitHostPort(s string) (string, int, error) {
	i := strings.LastIndex(s, ":")
	if i <= 0 {
		return "", 0, fmt.Errorf("missing port")
	}
	p, err := strconv.Atoi(s[i+1:])
	if err != nil || p <= 0 || p > 65535 {
		return "", 0, fmt.Errorf("invalid port")
	}
	return s[:i], p, nil
}

func (ch *ChannelConfig) applyDefaults() {
	if ch.MinSeverity == "" {
		ch.MinSeverity = "high"
	}
	if ch.Type == "syslog" && ch.Protocol == "" {
		ch.Protocol = "udp"
	}
	if ch.Type == "email" && ch.SMTPPort == 0 {
		ch.SMTPPort = 587
	}
}

// NormalizeChannel applies defaults to one channel and validates it. It is
// used to test a channel from the UI before the configuration is saved.
func NormalizeChannel(ch *ChannelConfig) error {
	ch.applyDefaults()
	return ch.check()
}

func (ch *ChannelConfig) check() error {
	if !validSeverity[ch.MinSeverity] {
		return fmt.Errorf("kanal %q: min_severity low, medium, high veya critical olmalı", ch.Name)
	}
	for _, ev := range ch.Events {
		if !validEvents[ev] {
			return fmt.Errorf("kanal %q: bilinmeyen olay tipi %q", ch.Name, ev)
		}
	}
	switch ch.Type {
	case "webhook", "slack", "teams":
		if u, err := url.Parse(ch.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			if ch.URL != SecretMask {
				return fmt.Errorf("kanal %q: geçerli bir http(s) URL gerekli", ch.Name)
			}
		}
	case "telegram":
		if ch.BotToken == "" || ch.ChatID == "" {
			return fmt.Errorf("kanal %q: bot_token ve chat_id gerekli", ch.Name)
		}
	case "syslog":
		if _, _, err := splitHostPort(ch.Address); err != nil {
			return fmt.Errorf("kanal %q: syslog adresi host:port olmalı", ch.Name)
		}
		if ch.Protocol != "udp" && ch.Protocol != "tcp" {
			return fmt.Errorf("kanal %q: syslog protokolü udp veya tcp olmalı", ch.Name)
		}
	case "email":
		if ch.SMTPHost == "" || ch.From == "" || len(ch.To) == 0 {
			return fmt.Errorf("kanal %q: smtp_host, from ve to gerekli", ch.Name)
		}
	default:
		return fmt.Errorf("kanal %q: tip webhook, slack, teams, telegram, syslog veya email olmalı", ch.Name)
	}
	return nil
}
