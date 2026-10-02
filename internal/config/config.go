// Package config loads and validates the ddosd YAML configuration.
package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that unmarshals from strings like "10s".
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: invalid duration %q", n.Line, n.Value)
	}
	d.Duration = v
	return nil
}

func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

// MarshalJSON renders the duration as a string ("10s") for the API.
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

// Rate is a numeric value that accepts SI suffixes: "200Mbps", "1.5G", "50k".
type Rate float64

func (r *Rate) UnmarshalYAML(n *yaml.Node) error {
	v, err := ParseRate(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*r = Rate(v)
	return nil
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
		return 0, fmt.Errorf("invalid rate %q", s)
	}
	return v * mult, nil
}

type Config struct {
	Collector  CollectorConfig  `yaml:"collector"`
	API        APIConfig        `yaml:"api"`
	Engine     EngineConfig     `yaml:"engine"`
	Exporters  []ExporterConfig `yaml:"exporters"`
	Objects    []ObjectConfig   `yaml:"protected_objects"`
	RulesDir   string           `yaml:"rules_dir"`
	DataDir    string           `yaml:"data_dir"`
	Mitigation MitigationConfig `yaml:"mitigation"`
	Analyst    AnalystConfig    `yaml:"analyst"`
	Demo       DemoConfig       `yaml:"demo"`
}

type CollectorConfig struct {
	Listen              []string `yaml:"listen"`
	ReadBufferBytes     int      `yaml:"read_buffer_bytes"`
	QueueSize           int      `yaml:"queue_size"`
	DefaultSamplingRate uint32   `yaml:"default_sampling_rate"`
}

type APIConfig struct {
	Listen   string `yaml:"listen"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type EngineConfig struct {
	Window         Duration `yaml:"window"`
	MaxFlowSpread  Duration `yaml:"max_flow_spread"`
	RecentFlows    int      `yaml:"recent_flows"`
	BaselineTau    Duration `yaml:"baseline_tau"`
	BaselineLearn  Duration `yaml:"baseline_learn"`
	NearMissRatio  float64  `yaml:"near_miss_ratio"`
	SignalMinZ     float64  `yaml:"signal_min_z"`
	SignalMinPPS   Rate     `yaml:"signal_min_pps"`
	SignalMinBPS   Rate     `yaml:"signal_min_bps"`
	IncidentReopen Duration `yaml:"incident_reopen"`
	EvidenceEvery  Duration `yaml:"evidence_every"`
}

type ExporterConfig struct {
	Address      string `yaml:"address"`
	Name         string `yaml:"name"`
	SamplingRate uint32 `yaml:"sampling_rate"`
}

type ObjectConfig struct {
	Name         string   `yaml:"name"`
	Prefixes     []string `yaml:"prefixes"`
	Profile      string   `yaml:"profile"`
	LinkCapacity Rate     `yaml:"link_capacity"`
	CarpetV4     int      `yaml:"carpet_prefix_v4"`
	CarpetV6     int      `yaml:"carpet_prefix_v6"`
	Notes        string   `yaml:"notes"`

	Parsed []netip.Prefix `yaml:"-"`
}

type MitigationConfig struct {
	Mode          string   `yaml:"mode"`   // manual | auto | off
	Driver        string   `yaml:"driver"` // dryrun | exabgp | webhook
	DefaultTTL    Duration `yaml:"default_ttl"`
	WithdrawAfter Duration `yaml:"withdraw_after"`
	MaxActive     int      `yaml:"max_active"`
	MinPrefixV4   int      `yaml:"min_prefix_v4"`
	MinPrefixV6   int      `yaml:"min_prefix_v6"`
	AllowRTBH     bool     `yaml:"allow_rtbh"`
	NeverMitigate []string `yaml:"never_mitigate"`
	ExaBGP        struct {
		CommandFile   string `yaml:"command_file"`
		RTBHNextHop   string `yaml:"rtbh_next_hop"`
		RTBHCommunity string `yaml:"rtbh_community"`
	} `yaml:"exabgp"`
	Webhook struct {
		URL    string `yaml:"url"`
		Secret string `yaml:"secret"`
	} `yaml:"webhook"`

	NeverParsed []netip.Prefix `yaml:"-"`
}

type AnalystConfig struct {
	Enabled      bool     `yaml:"enabled"`
	Provider     string   `yaml:"provider"` // anthropic | openai_compat | heuristic
	Model        string   `yaml:"model"`
	Effort       string   `yaml:"effort"`
	Interval     Duration `yaml:"interval"`
	Language     string   `yaml:"language"`
	MaxTurns     int      `yaml:"max_turns"`
	MaxTokens    int      `yaml:"max_tokens"`
	AutoRun      bool     `yaml:"auto_run"`
	OpenAICompat struct {
		BaseURL   string `yaml:"base_url"`
		Model     string `yaml:"model"`
		APIKeyEnv string `yaml:"api_key_env"`
	} `yaml:"openai_compat"`
}

type DemoConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Encoder      string `yaml:"encoder"`
	SamplingRate uint32 `yaml:"sampling_rate"`
	Target       string `yaml:"target"`
	Baseline     bool   `yaml:"baseline"`
	BaselineBPS  Rate   `yaml:"baseline_bps"`
}

// Load reads, defaults and validates a config file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
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
	if c.API.Listen == "" {
		c.API.Listen = ":8080"
	}
	e := &c.Engine
	def := func(d *Duration, v time.Duration) {
		if d.Duration == 0 {
			d.Duration = v
		}
	}
	def(&e.Window, 10*time.Second)
	def(&e.MaxFlowSpread, 30*time.Second)
	def(&e.BaselineTau, 30*time.Minute)
	def(&e.BaselineLearn, 10*time.Minute)
	def(&e.IncidentReopen, 2*time.Minute)
	def(&e.EvidenceEvery, 10*time.Second)
	if e.RecentFlows == 0 {
		e.RecentFlows = 500_000
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

func (c *Config) validate() error {
	if c.Engine.Window.Duration < time.Second || c.Engine.Window.Duration > 30*time.Second {
		return fmt.Errorf("engine.window must be between 1s and 30s")
	}
	if c.Engine.MaxFlowSpread.Duration > 30*time.Second {
		return fmt.Errorf("engine.max_flow_spread must be <= 30s")
	}
	if len(c.Objects) == 0 {
		return fmt.Errorf("at least one protected_objects entry is required")
	}
	seen := map[string]bool{}
	for i := range c.Objects {
		o := &c.Objects[i]
		if o.Name == "" {
			return fmt.Errorf("protected_objects[%d]: name is required", i)
		}
		if seen[o.Name] {
			return fmt.Errorf("protected_objects: duplicate name %q", o.Name)
		}
		seen[o.Name] = true
		if len(o.Prefixes) == 0 {
			return fmt.Errorf("protected object %q: no prefixes", o.Name)
		}
		for _, p := range o.Prefixes {
			pfx, err := netip.ParsePrefix(p)
			if err != nil {
				return fmt.Errorf("protected object %q: %w", o.Name, err)
			}
			o.Parsed = append(o.Parsed, pfx.Masked())
		}
		if o.CarpetV4 < 8 || o.CarpetV4 > 32 || o.CarpetV6 < 32 || o.CarpetV6 > 128 {
			return fmt.Errorf("protected object %q: invalid carpet prefix length", o.Name)
		}
	}
	for _, e := range c.Exporters {
		if _, err := netip.ParseAddr(e.Address); err != nil {
			return fmt.Errorf("exporters: %w", err)
		}
	}
	m := &c.Mitigation
	switch m.Mode {
	case "manual", "auto", "off":
	default:
		return fmt.Errorf("mitigation.mode must be manual, auto or off")
	}
	switch m.Driver {
	case "dryrun", "exabgp", "webhook":
	default:
		return fmt.Errorf("mitigation.driver must be dryrun, exabgp or webhook")
	}
	if m.Driver == "exabgp" && m.ExaBGP.CommandFile == "" {
		return fmt.Errorf("mitigation.exabgp.command_file is required for the exabgp driver")
	}
	if m.Driver == "webhook" && m.Webhook.URL == "" {
		return fmt.Errorf("mitigation.webhook.url is required for the webhook driver")
	}
	for _, p := range m.NeverMitigate {
		pfx, err := netip.ParsePrefix(p)
		if err != nil {
			a, err2 := netip.ParseAddr(p)
			if err2 != nil {
				return fmt.Errorf("mitigation.never_mitigate: %w", err)
			}
			pfx = netip.PrefixFrom(a, a.BitLen())
		}
		m.NeverParsed = append(m.NeverParsed, pfx.Masked())
	}
	switch c.Analyst.Provider {
	case "anthropic", "openai_compat", "heuristic":
	default:
		return fmt.Errorf("analyst.provider must be anthropic, openai_compat or heuristic")
	}
	switch c.Demo.Encoder {
	case "netflow5", "netflow9", "ipfix", "sflow":
	default:
		return fmt.Errorf("demo.encoder must be netflow5, netflow9, ipfix or sflow")
	}
	return nil
}
