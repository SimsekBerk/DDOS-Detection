// Package rules loads DDoS detection rule sets and profiles from YAML and
// compiles them into fast flow matchers.
package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/SimsekBerk/DDOS-Detection/internal/config"
	"github.com/SimsekBerk/DDOS-Detection/internal/flow"
)

type Rule struct {
	ID          string `yaml:"id" json:"id"`
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description" json:"description"`
	Category    string `yaml:"category" json:"category"`
	Direction   string `yaml:"direction" json:"direction"` // inbound | outbound
	Scope       string `yaml:"scope" json:"scope"`         // host | prefix | object
	Enabled     *bool  `yaml:"enabled" json:"-"`
	Severity    string `yaml:"severity" json:"severity"`
	// Generic marks catch-all rules (e.g. "all UDP to a host"). A generic
	// vector is suppressed while specific vectors on the same target already
	// explain most of its traffic, so one attack is reported once.
	Generic        bool       `yaml:"generic" json:"generic"`
	Match          Match      `yaml:"match" json:"match"`
	Thresholds     Thresholds `yaml:"thresholds" json:"thresholds"`
	Baseline       Baseline   `yaml:"baseline" json:"baseline"`
	Conditions     Conditions `yaml:"conditions" json:"conditions"`
	Trigger        Trigger    `yaml:"trigger" json:"trigger"`
	Mitigation     Mitigation `yaml:"mitigation" json:"mitigation"`
	Rationale      string     `yaml:"rationale" json:"rationale"`
	FalsePositives string     `yaml:"false_positives" json:"false_positives"`
	References     []string   `yaml:"references" json:"references"`
}

type Match struct {
	Protocols     []string  `yaml:"protocols" json:"protocols,omitempty"`
	NotProtocols  []string  `yaml:"not_protocols" json:"not_protocols,omitempty"`
	SrcPorts      []string  `yaml:"src_ports" json:"src_ports,omitempty"`
	DstPorts      []string  `yaml:"dst_ports" json:"dst_ports,omitempty"`
	TCPFlags      *TCPMatch `yaml:"tcp_flags" json:"tcp_flags,omitempty"`
	ICMPTypes     []int     `yaml:"icmp_types" json:"icmp_types,omitempty"`
	ICMPCodes     []int     `yaml:"icmp_codes" json:"icmp_codes,omitempty"`
	Fragment      *bool     `yaml:"fragment" json:"fragment,omitempty"`
	MinPacketSize float64   `yaml:"min_packet_size" json:"min_packet_size,omitempty"`
	MaxPacketSize float64   `yaml:"max_packet_size" json:"max_packet_size,omitempty"`
	IPVersion     int       `yaml:"ip_version" json:"ip_version,omitempty"`
}

// TCPMatch: all flags in All must be set, none of None may be set, at least
// one of Any must be set; Empty matches flows with no flags at all.
type TCPMatch struct {
	All   []string `yaml:"all" json:"all,omitempty"`
	None  []string `yaml:"none" json:"none,omitempty"`
	Any   []string `yaml:"any" json:"any,omitempty"`
	Empty bool     `yaml:"empty" json:"empty,omitempty"`
}

type Thresholds struct {
	PPS config.Rate `yaml:"pps" json:"pps"`
	BPS config.Rate `yaml:"bps" json:"bps"`
	FPS config.Rate `yaml:"fps" json:"fps"`
}

type Baseline struct {
	Enabled bool        `yaml:"enabled" json:"enabled"`
	Factor  float64     `yaml:"factor" json:"factor"`
	MinPPS  config.Rate `yaml:"min_pps" json:"min_pps"`
	MinBPS  config.Rate `yaml:"min_bps" json:"min_bps"`
}

type Conditions struct {
	MinUniqueSources int `yaml:"min_unique_sources" json:"min_unique_sources,omitempty"`
	// MinUniqueDests applies to prefix/object scope: the attack must hit at
	// least this many distinct hosts (separates carpet bombing from a
	// single-host attack inside the prefix).
	MinUniqueDests   int     `yaml:"min_unique_destinations" json:"min_unique_destinations,omitempty"`
	MinAvgPacketSize float64 `yaml:"min_avg_packet_size" json:"min_avg_packet_size,omitempty"`
	MaxAvgPacketSize float64 `yaml:"max_avg_packet_size" json:"max_avg_packet_size,omitempty"`
	MinSamples       int     `yaml:"min_samples" json:"min_samples,omitempty"`
}

type Trigger struct {
	Sustain  config.Duration `yaml:"sustain" json:"-"`
	HoldDown config.Duration `yaml:"hold_down" json:"-"`
}

type Mitigation struct {
	// Action: flowspec-discard | flowspec-rate-limit | rtbh | scrub | alert
	Action string `yaml:"action" json:"action"`
	// Rate for flowspec-rate-limit, bits per second.
	Rate config.Rate `yaml:"rate" json:"rate,omitempty"`
	// Include the rule's packet-length match in the FlowSpec rule.
	PacketLength bool `yaml:"packet_length" json:"packet_length,omitempty"`
	// Escalate to RTBH when attack bps exceeds this fraction of link capacity.
	RTBHEscalation float64 `yaml:"rtbh_escalation" json:"rtbh_escalation,omitempty"`
	Note           string  `yaml:"note" json:"note,omitempty"`
}

type Profile struct {
	Name        string                     `yaml:"name" json:"name"`
	Description string                     `yaml:"description" json:"description"`
	Scale       float64                    `yaml:"scale" json:"scale"`
	Disable     []string                   `yaml:"disable" json:"disable,omitempty"`
	Overrides   map[string]ProfileOverride `yaml:"overrides" json:"overrides,omitempty"`
}

type ProfileOverride struct {
	Scale float64     `yaml:"scale" json:"scale,omitempty"`
	PPS   config.Rate `yaml:"pps" json:"pps,omitempty"`
	BPS   config.Rate `yaml:"bps" json:"bps,omitempty"`
	FPS   config.Rate `yaml:"fps" json:"fps,omitempty"`
}

type file struct {
	Profiles []Profile `yaml:"profiles"`
	Rules    []Rule    `yaml:"rules"`
}

// Override is a runtime change made from the UI/API (persisted separately).
type Override struct {
	Enabled *bool        `json:"enabled,omitempty"`
	PPS     *config.Rate `json:"pps,omitempty"`
	BPS     *config.Rate `json:"bps,omitempty"`
	FPS     *config.Rate `json:"fps,omitempty"`
}

// MaxRules is the maximum number of rules (classification uses a 128-bit set).
const MaxRules = 128

// Set is an immutable, compiled rule set.
type Set struct {
	Rules    []*Compiled
	Profiles map[string]*Profile
	ByID     map[string]*Compiled
	Files    []string

	within   [][]bool // within[a][b]: every flow matching rule a also matches rule b
	disjoint [][]bool // disjoint[a][b]: no flow can match both rules
	breadth  []int    // number of rules contained in each rule (more = more general)
}

// Within reports whether every flow matched by rule a (index) is also
// matched by rule b. The engine uses it for hierarchical correlation: an
// active vector can only explain ("cover") traffic of a rule that contains
// it, e.g. DNS amplification inside "all UDP", but never TCP SYN inside UDP.
func (s *Set) Within(a, b int) bool {
	if a < 0 || b < 0 || a >= len(s.within) || b >= len(s.within) {
		return false
	}
	return s.within[a][b]
}

// Disjoint reports whether no flow can match both rules (by index). Rates of
// disjoint vectors on one target can be added without double counting.
func (s *Set) Disjoint(a, b int) bool {
	if a < 0 || b < 0 || a >= len(s.disjoint) || b >= len(s.disjoint) {
		return false
	}
	return s.disjoint[a][b]
}

// Breadth is the number of rules contained in rule i; general rules have a
// larger breadth and are decided after narrower ones.
func (s *Set) Breadth(i int) int {
	if i < 0 || i >= len(s.breadth) {
		return 0
	}
	return s.breadth[i]
}

// Load reads all *.yaml / *.yml files in dir (sorted) and compiles them.
func Load(dir string, overrides map[string]Override) (*Set, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && (strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml")) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	s := &Set{Profiles: map[string]*Profile{}, ByID: map[string]*Compiled{}}
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		var f file
		if err := yaml.Unmarshal(b, &f); err != nil {
			return nil, fmt.Errorf("%s: %w", n, err)
		}
		s.Files = append(s.Files, n)
		for i := range f.Profiles {
			p := f.Profiles[i]
			if p.Scale == 0 {
				p.Scale = 1
			}
			s.Profiles[p.Name] = &p
		}
		for i := range f.Rules {
			r := f.Rules[i]
			if _, dup := s.ByID[r.ID]; dup {
				return nil, fmt.Errorf("%s: duplicate rule id %q", n, r.ID)
			}
			c, err := compile(&r, len(s.Rules))
			if err != nil {
				return nil, fmt.Errorf("%s: rule %q: %w", n, r.ID, err)
			}
			if o, ok := overrides[r.ID]; ok {
				c.applyOverride(o)
			}
			s.Rules = append(s.Rules, c)
			s.ByID[r.ID] = c
		}
	}
	if _, ok := s.Profiles["default"]; !ok {
		s.Profiles["default"] = &Profile{Name: "default", Scale: 1}
	}
	for _, p := range s.Profiles {
		for _, id := range p.Disable {
			if _, ok := s.ByID[id]; !ok {
				return nil, fmt.Errorf("profile %q disables unknown rule %q", p.Name, id)
			}
		}
		for id := range p.Overrides {
			if _, ok := s.ByID[id]; !ok {
				return nil, fmt.Errorf("profile %q overrides unknown rule %q", p.Name, id)
			}
		}
	}
	if len(s.Rules) == 0 {
		return nil, fmt.Errorf("no rules found in %s", dir)
	}
	if len(s.Rules) > MaxRules {
		return nil, fmt.Errorf("too many rules (%d > %d)", len(s.Rules), MaxRules)
	}
	n := len(s.Rules)
	s.within, s.disjoint, s.breadth = make([][]bool, n), make([][]bool, n), make([]int, n)
	for i, a := range s.Rules {
		s.within[i], s.disjoint[i] = make([]bool, n), make([]bool, n)
		for j, b := range s.Rules {
			s.within[i][j] = a.within(b)
			s.disjoint[i][j] = a.disjoint(b)
		}
	}
	for i := range s.Rules {
		for j := range s.Rules {
			if s.within[j][i] {
				s.breadth[i]++
			}
		}
	}
	return s, nil
}

// disjoint is a conservative test that no flow can match both rules: true
// only when some constraint pair provably excludes each other.
func (a *Compiled) disjoint(b *Compiled) bool {
	if a.Direction != b.Direction {
		return true
	}
	common := false
	for p := 0; p < 256 && !common; p++ {
		common = (a.anyProto || a.protos[p]) && !a.notProtos[p] && (b.anyProto || b.protos[p]) && !b.notProtos[p]
	}
	if !common {
		return true
	}
	am, bm := &a.Match, &b.Match
	// Port constraints never match fragments.
	fragOnly := func(m *Match) bool { return m.Fragment != nil && *m.Fragment }
	hasPorts := func(c *Compiled) bool { return len(c.srcPorts) > 0 || len(c.dstPorts) > 0 }
	if am.Fragment != nil && bm.Fragment != nil && *am.Fragment != *bm.Fragment ||
		fragOnly(am) && hasPorts(b) || fragOnly(bm) && hasPorts(a) {
		return true
	}
	if am.IPVersion != 0 && bm.IPVersion != 0 && am.IPVersion != bm.IPVersion {
		return true
	}
	if rangesDisjoint(a.srcPorts, b.srcPorts) || rangesDisjoint(a.dstPorts, b.dstPorts) {
		return true
	}
	if a.tcpCheck && b.tcpCheck {
		if a.flagsAll&b.flagsNone != 0 || b.flagsAll&a.flagsNone != 0 ||
			a.flagsEmpty && (b.flagsAll != 0 || b.flagsAny != 0) || b.flagsEmpty && (a.flagsAll != 0 || a.flagsAny != 0) {
			return true
		}
	}
	if a.icmpTypes != nil && b.icmpTypes != nil {
		shared := false
		for k := range a.icmpTypes {
			if b.icmpTypes[k] {
				shared = true
				break
			}
		}
		if !shared {
			return true
		}
	}
	if am.MaxPacketSize > 0 && bm.MinPacketSize > am.MaxPacketSize || bm.MaxPacketSize > 0 && am.MinPacketSize > bm.MaxPacketSize {
		return true
	}
	return false
}

// rangesDisjoint: both constrained and no range of a overlaps a range of b.
func rangesDisjoint(a, b []portRange) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	for _, r := range a {
		for _, q := range b {
			if r.lo <= q.hi && q.lo <= r.hi {
				return false
			}
		}
	}
	return true
}

// within is a conservative subset test of match conditions: true only when
// every constraint of b is implied by a's constraints. Unknown or partially
// overlapping cases return false, so a vector is never hidden by an
// unrelated one (a duplicate report is preferred over a missed vector).
func (a *Compiled) within(b *Compiled) bool {
	if a.Direction != b.Direction {
		return false
	}
	inA := func(p int) bool { return (a.anyProto || a.protos[p]) && !a.notProtos[p] }
	inB := func(p int) bool { return (b.anyProto || b.protos[p]) && !b.notProtos[p] }
	for p := 0; p < 256; p++ {
		if inA(p) && !inB(p) {
			return false
		}
	}
	am, bm := &a.Match, &b.Match
	if bm.IPVersion != 0 && am.IPVersion != bm.IPVersion {
		return false
	}
	if bm.Fragment != nil && (am.Fragment == nil || *am.Fragment != *bm.Fragment) {
		return false
	}
	if !portsWithin(a.srcPorts, b.srcPorts) || !portsWithin(a.dstPorts, b.dstPorts) {
		return false
	}
	if b.tcpCheck {
		if !a.tcpCheck || b.flagsAll&^a.flagsAll != 0 || b.flagsNone&^a.flagsNone != 0 || (b.flagsEmpty && !a.flagsEmpty) {
			return false
		}
		if b.flagsAny != 0 && a.flagsAll&b.flagsAny == 0 && (a.flagsAny == 0 || a.flagsAny&^b.flagsAny != 0) {
			return false
		}
	}
	if !setWithin(a.icmpTypes, b.icmpTypes) || !setWithin(a.icmpCodes, b.icmpCodes) {
		return false
	}
	if bm.MinPacketSize > 0 && am.MinPacketSize < bm.MinPacketSize {
		return false
	}
	if bm.MaxPacketSize > 0 && (am.MaxPacketSize == 0 || am.MaxPacketSize > bm.MaxPacketSize) {
		return false
	}
	return true
}

// portsWithin: b unconstrained, or every range of a lies inside some range of b.
func portsWithin(a, b []portRange) bool {
	if len(b) == 0 {
		return true
	}
	if len(a) == 0 {
		return false
	}
	for _, r := range a {
		ok := false
		for _, q := range b {
			if r.lo >= q.lo && r.hi <= q.hi {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func setWithin(a, b map[uint8]bool) bool {
	if b == nil {
		return true
	}
	if a == nil {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

type portRange struct{ lo, hi uint16 }

// Compiled is a rule ready for matching.
type Compiled struct {
	Rule
	Index int

	Active      bool // enabled after overrides
	T           Thresholds
	SustainSec  int
	HoldDownSec int

	anyProto   bool
	protos     [256]bool
	notProtos  [256]bool
	srcPorts   []portRange
	dstPorts   []portRange
	flagsAll   uint8
	flagsNone  uint8
	flagsAny   uint8
	flagsEmpty bool
	tcpCheck   bool
	icmpTypes  map[uint8]bool
	icmpCodes  map[uint8]bool
	ProtoNums  []uint8 // for FlowSpec rendering
}

func compile(r *Rule, idx int) (*Compiled, error) {
	c := &Compiled{Rule: *r, Index: idx}
	if r.ID == "" || r.Name == "" {
		return nil, fmt.Errorf("id and name are required")
	}
	switch r.Direction {
	case "inbound", "outbound":
	case "":
		c.Direction = "inbound"
	default:
		return nil, fmt.Errorf("invalid direction %q", r.Direction)
	}
	switch r.Scope {
	case "host", "prefix", "object":
	case "":
		c.Scope = "host"
	default:
		return nil, fmt.Errorf("invalid scope %q", r.Scope)
	}
	switch r.Severity {
	case "low", "medium", "high", "critical":
	case "":
		c.Severity = "medium"
	default:
		return nil, fmt.Errorf("invalid severity %q", r.Severity)
	}
	switch r.Mitigation.Action {
	case "", "alert":
		c.Mitigation.Action = "alert"
	case "flowspec-discard", "flowspec-rate-limit", "rtbh", "scrub":
	default:
		return nil, fmt.Errorf("invalid mitigation action %q", r.Mitigation.Action)
	}
	if r.Mitigation.Action == "flowspec-rate-limit" && r.Mitigation.Rate <= 0 {
		return nil, fmt.Errorf("flowspec-rate-limit requires mitigation.rate")
	}
	if r.Thresholds.PPS == 0 && r.Thresholds.BPS == 0 && r.Thresholds.FPS == 0 && !r.Baseline.Enabled {
		return nil, fmt.Errorf("at least one threshold or baseline is required")
	}
	if r.Baseline.Enabled && r.Baseline.Factor <= 1 {
		return nil, fmt.Errorf("baseline.factor must be > 1")
	}
	c.Active = r.Enabled == nil || *r.Enabled
	c.T = r.Thresholds
	c.SustainSec = int(r.Trigger.Sustain.Seconds())
	if c.SustainSec < 1 {
		c.SustainSec = 3
	}
	c.HoldDownSec = int(r.Trigger.HoldDown.Seconds())
	if c.HoldDownSec < 1 {
		c.HoldDownSec = 60
	}

	m := r.Match
	if len(m.Protocols) == 0 {
		c.anyProto = true
	}
	for _, p := range m.Protocols {
		n, ok := flow.ProtoNumber(p)
		if !ok {
			return nil, fmt.Errorf("unknown protocol %q", p)
		}
		c.protos[n] = true
		c.ProtoNums = append(c.ProtoNums, n)
	}
	for _, p := range m.NotProtocols {
		n, ok := flow.ProtoNumber(p)
		if !ok {
			return nil, fmt.Errorf("unknown protocol %q", p)
		}
		c.notProtos[n] = true
	}
	var err error
	if c.srcPorts, err = parsePorts(m.SrcPorts); err != nil {
		return nil, err
	}
	if c.dstPorts, err = parsePorts(m.DstPorts); err != nil {
		return nil, err
	}
	if t := m.TCPFlags; t != nil {
		c.tcpCheck = true
		c.flagsEmpty = t.Empty
		for _, set := range []struct {
			names []string
			dst   *uint8
		}{{t.All, &c.flagsAll}, {t.None, &c.flagsNone}, {t.Any, &c.flagsAny}} {
			for _, n := range set.names {
				b, ok := flow.TCPFlagBit(n)
				if !ok {
					return nil, fmt.Errorf("unknown tcp flag %q", n)
				}
				*set.dst |= b
			}
		}
	}
	if len(m.ICMPTypes) > 0 {
		c.icmpTypes = map[uint8]bool{}
		for _, t := range m.ICMPTypes {
			c.icmpTypes[uint8(t)] = true
		}
	}
	if len(m.ICMPCodes) > 0 {
		c.icmpCodes = map[uint8]bool{}
		for _, t := range m.ICMPCodes {
			c.icmpCodes[uint8(t)] = true
		}
	}
	return c, nil
}

func parsePorts(specs []string) ([]portRange, error) {
	var out []portRange
	for _, s := range specs {
		s = strings.TrimSpace(s)
		lo, hi := s, s
		if i := strings.Index(s, "-"); i > 0 {
			lo, hi = s[:i], s[i+1:]
		}
		l, err1 := strconv.ParseUint(lo, 10, 16)
		h, err2 := strconv.ParseUint(hi, 10, 16)
		if err1 != nil || err2 != nil || l > h {
			return nil, fmt.Errorf("invalid port spec %q", s)
		}
		out = append(out, portRange{uint16(l), uint16(h)})
	}
	return out, nil
}

func inPorts(rs []portRange, p uint16) bool {
	for _, r := range rs {
		if p >= r.lo && p <= r.hi {
			return true
		}
	}
	return false
}

func (c *Compiled) applyOverride(o Override) {
	if o.Enabled != nil {
		c.Active = *o.Enabled
	}
	if o.PPS != nil {
		c.T.PPS = *o.PPS
	}
	if o.BPS != nil {
		c.T.BPS = *o.BPS
	}
	if o.FPS != nil {
		c.T.FPS = *o.FPS
	}
}

// DirectionCode returns the flow.Direction this rule applies to.
func (c *Compiled) DirectionCode() flow.Direction {
	if c.Direction == "outbound" {
		return flow.DirOutbound
	}
	return flow.DirInbound
}

// Matches reports whether a record matches the rule's packet criteria
// (direction is checked by the caller).
func (c *Compiled) Matches(r *flow.Record) bool {
	if !c.anyProto && !c.protos[r.Protocol] {
		return false
	}
	if c.notProtos[r.Protocol] {
		return false
	}
	m := &c.Match
	if m.IPVersion == 4 && !r.Dst.Is4() || m.IPVersion == 6 && !r.Dst.Is6() {
		return false
	}
	if m.Fragment != nil && *m.Fragment != r.Fragment {
		return false
	}
	if len(c.srcPorts) > 0 && (r.Fragment || !inPorts(c.srcPorts, r.SrcPort)) {
		return false
	}
	if len(c.dstPorts) > 0 && (r.Fragment || !inPorts(c.dstPorts, r.DstPort)) {
		return false
	}
	if c.tcpCheck {
		if r.Protocol != flow.ProtoTCP {
			return false
		}
		f := r.TCPFlags
		if c.flagsEmpty && f != 0 {
			return false
		}
		if f&c.flagsAll != c.flagsAll || f&c.flagsNone != 0 {
			return false
		}
		if c.flagsAny != 0 && f&c.flagsAny == 0 {
			return false
		}
	}
	if c.icmpTypes != nil && !c.icmpTypes[r.ICMPType] {
		return false
	}
	if c.icmpCodes != nil && !c.icmpCodes[r.ICMPCode] {
		return false
	}
	if m.MinPacketSize > 0 || m.MaxPacketSize > 0 {
		s := r.AvgPacketSize()
		if m.MinPacketSize > 0 && s < m.MinPacketSize {
			return false
		}
		if m.MaxPacketSize > 0 && s > m.MaxPacketSize {
			return false
		}
	}
	return true
}

// Effective returns the thresholds for this rule under a profile, and whether
// the rule is enabled for that profile.
func (s *Set) Effective(c *Compiled, profile string) (Thresholds, bool) {
	if !c.Active {
		return Thresholds{}, false
	}
	p := s.Profiles[profile]
	if p == nil {
		p = s.Profiles["default"]
	}
	for _, id := range p.Disable {
		if id == c.ID {
			return Thresholds{}, false
		}
	}
	scale := p.Scale
	t := c.T
	if o, ok := p.Overrides[c.ID]; ok {
		if o.Scale > 0 {
			scale *= o.Scale
		}
		if o.PPS > 0 {
			t.PPS = o.PPS / config.Rate(scale)
		}
		if o.BPS > 0 {
			t.BPS = o.BPS / config.Rate(scale)
		}
		if o.FPS > 0 {
			t.FPS = o.FPS / config.Rate(scale)
		}
	}
	t.PPS *= config.Rate(scale)
	t.BPS *= config.Rate(scale)
	t.FPS *= config.Rate(scale)
	return t, true
}

// MatchSummary renders the match criteria as a short human readable string.
func (c *Compiled) MatchSummary() string {
	var parts []string
	m := c.Match
	if len(m.Protocols) > 0 {
		parts = append(parts, "proto="+strings.Join(m.Protocols, ","))
	}
	if len(m.NotProtocols) > 0 {
		parts = append(parts, "proto!="+strings.Join(m.NotProtocols, ","))
	}
	if len(m.SrcPorts) > 0 {
		parts = append(parts, "sport="+strings.Join(m.SrcPorts, ","))
	}
	if len(m.DstPorts) > 0 {
		parts = append(parts, "dport="+strings.Join(m.DstPorts, ","))
	}
	if t := m.TCPFlags; t != nil {
		f := ""
		if t.Empty {
			f = "none"
		}
		if len(t.All) > 0 {
			f += "+" + strings.Join(t.All, "+")
		}
		if len(t.None) > 0 {
			f += " !" + strings.Join(t.None, "!")
		}
		if len(t.Any) > 0 {
			f += " any(" + strings.Join(t.Any, ",") + ")"
		}
		parts = append(parts, "tcp="+strings.TrimSpace(f))
	}
	if len(m.ICMPTypes) > 0 {
		parts = append(parts, fmt.Sprintf("icmp_type=%v", m.ICMPTypes))
	}
	if m.Fragment != nil {
		parts = append(parts, fmt.Sprintf("fragment=%v", *m.Fragment))
	}
	if m.MinPacketSize > 0 {
		parts = append(parts, fmt.Sprintf("pkt>=%.0f", m.MinPacketSize))
	}
	if m.MaxPacketSize > 0 {
		parts = append(parts, fmt.Sprintf("pkt<=%.0f", m.MaxPacketSize))
	}
	if len(parts) == 0 {
		return "all traffic"
	}
	return strings.Join(parts, " ")
}
