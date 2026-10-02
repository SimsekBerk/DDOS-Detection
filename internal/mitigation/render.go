package mitigation

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/SimsekBerk/DDOS-Detection/internal/flow"
)

// FlowSpec is a BGP FlowSpec (RFC 8955/8956) rule.
type FlowSpec struct {
	Destination  string   `json:"destination,omitempty"`
	Source       string   `json:"source,omitempty"`
	Protocols    []string `json:"protocols,omitempty"`
	SrcPorts     []string `json:"src_ports,omitempty"` // "53" or "1024-65535"
	DstPorts     []string `json:"dst_ports,omitempty"`
	PacketLength string   `json:"packet_length,omitempty"` // ">=512"
	Fragment     bool     `json:"fragment,omitempty"`
	TCPSet       []string `json:"tcp_flags_set,omitempty"`
	TCPNotSet    []string `json:"tcp_flags_not_set,omitempty"`
	ICMPTypes    []int    `json:"icmp_types,omitempty"`
	Action       string   `json:"action"` // discard | rate-limit
	RateBps      float64  `json:"rate_bps,omitempty"`
}

// RTBH is a remotely triggered black hole announcement.
type RTBH struct {
	Prefix    string `json:"prefix"`
	NextHop   string `json:"next_hop"`
	Community string `json:"community"`
}

// Validate checks the FlowSpec rule is well-formed.
func (f *FlowSpec) Validate() error {
	if f.Destination == "" && f.Source == "" {
		return fmt.Errorf("flowspec needs a destination or source prefix")
	}
	for _, p := range []string{f.Destination, f.Source} {
		if p == "" {
			continue
		}
		if _, err := netip.ParsePrefix(p); err != nil {
			return fmt.Errorf("invalid prefix %q", p)
		}
	}
	for _, p := range f.Protocols {
		if _, ok := flow.ProtoNumber(p); !ok {
			return fmt.Errorf("invalid protocol %q", p)
		}
	}
	for _, list := range [][]string{f.SrcPorts, f.DstPorts} {
		for _, p := range list {
			lo, hi, err := portBounds(p)
			if err != nil || lo > hi || lo < 0 || hi > 65535 {
				return fmt.Errorf("invalid port %q", p)
			}
		}
	}
	if f.PacketLength != "" {
		if _, _, err := lengthBounds(f.PacketLength); err != nil {
			return err
		}
	}
	switch f.Action {
	case "discard":
	case "rate-limit":
		if f.RateBps <= 0 {
			return fmt.Errorf("rate-limit requires rate_bps > 0")
		}
	default:
		return fmt.Errorf("invalid action %q", f.Action)
	}
	return nil
}

func portBounds(p string) (int, int, error) {
	var lo, hi int
	if strings.Contains(p, "-") {
		if _, err := fmt.Sscanf(p, "%d-%d", &lo, &hi); err != nil {
			return 0, 0, err
		}
		return lo, hi, nil
	}
	if _, err := fmt.Sscanf(p, "%d", &lo); err != nil {
		return 0, 0, err
	}
	return lo, lo, nil
}

// lengthBounds parses ">=512" / "<=1000" / "100-200".
func lengthBounds(s string) (int, int, error) {
	var lo, hi int
	switch {
	case strings.HasPrefix(s, ">="):
		_, err := fmt.Sscanf(s[2:], "%d", &lo)
		return lo, 65535, err
	case strings.HasPrefix(s, "<="):
		_, err := fmt.Sscanf(s[2:], "%d", &hi)
		return 0, hi, err
	case strings.Contains(s, "-"):
		_, err := fmt.Sscanf(s, "%d-%d", &lo, &hi)
		return lo, hi, err
	}
	return 0, 0, fmt.Errorf("invalid packet length %q", s)
}

func exaPorts(ps []string) string {
	var out []string
	for _, p := range ps {
		lo, hi, _ := portBounds(p)
		if lo == hi {
			out = append(out, fmt.Sprintf("=%d", lo))
		} else {
			out = append(out, fmt.Sprintf(">=%d&<=%d", lo, hi))
		}
	}
	return strings.Join(out, " ")
}

func exaLength(s string) string {
	lo, hi, _ := lengthBounds(s)
	switch {
	case hi == 65535:
		return fmt.Sprintf(">=%d", lo)
	case lo == 0:
		return fmt.Sprintf("<=%d", hi)
	}
	return fmt.Sprintf(">=%d&<=%d", lo, hi)
}

// rateBytes converts bps to the FlowSpec traffic-rate unit (bytes/s).
func rateBytes(bps float64) int64 { return int64(bps / 8) }

func (f *FlowSpec) exabgpMatch() string {
	var m []string
	if f.Source != "" {
		m = append(m, "source "+f.Source+";")
	}
	if f.Destination != "" {
		m = append(m, "destination "+f.Destination+";")
	}
	if len(f.Protocols) == 1 {
		m = append(m, "protocol "+f.Protocols[0]+";")
	} else if len(f.Protocols) > 1 {
		m = append(m, "protocol [ "+strings.Join(f.Protocols, " ")+" ];")
	}
	if len(f.SrcPorts) > 0 {
		m = append(m, "source-port "+exaPorts(f.SrcPorts)+";")
	}
	if len(f.DstPorts) > 0 {
		m = append(m, "destination-port "+exaPorts(f.DstPorts)+";")
	}
	if f.PacketLength != "" {
		m = append(m, "packet-length "+exaLength(f.PacketLength)+";")
	}
	if f.Fragment {
		m = append(m, "fragment [ is-fragment ];")
	}
	if len(f.TCPSet) > 0 || len(f.TCPNotSet) > 0 {
		var parts []string
		for _, s := range f.TCPSet {
			parts = append(parts, strings.ToLower(s))
		}
		for _, s := range f.TCPNotSet {
			parts = append(parts, "!"+strings.ToLower(s))
		}
		m = append(m, "tcp-flags [ "+strings.Join(parts, "&")+" ];")
	}
	if len(f.ICMPTypes) > 0 {
		var t []string
		for _, i := range f.ICMPTypes {
			t = append(t, fmt.Sprintf("=%d", i))
		}
		m = append(m, "icmp-type "+strings.Join(t, " ")+";")
	}
	return strings.Join(m, " ")
}

func (f *FlowSpec) exabgpThen() string {
	if f.Action == "rate-limit" {
		return fmt.Sprintf("rate-limit %d;", rateBytes(f.RateBps))
	}
	return "discard;"
}

// ExaBGPAnnounce renders the ExaBGP API command.
func (f *FlowSpec) ExaBGPAnnounce() string {
	return fmt.Sprintf("announce flow route { match { %s } then { %s } }", f.exabgpMatch(), f.exabgpThen())
}

// ExaBGPWithdraw renders the matching withdraw command.
func (f *FlowSpec) ExaBGPWithdraw() string {
	return fmt.Sprintf("withdraw flow route { match { %s } then { %s } }", f.exabgpMatch(), f.exabgpThen())
}

// GoBGP renders a gobgp CLI command.
func (f *FlowSpec) GoBGP() string {
	fam := "ipv4-flowspec"
	if strings.Contains(f.Destination+f.Source, ":") {
		fam = "ipv6-flowspec"
	}
	var m []string
	if f.Destination != "" {
		m = append(m, "destination "+f.Destination)
	}
	if f.Source != "" {
		m = append(m, "source "+f.Source)
	}
	if len(f.Protocols) > 0 {
		m = append(m, "protocol "+strings.Join(f.Protocols, " "))
	}
	ports := func(name string, ps []string) {
		if len(ps) == 0 {
			return
		}
		var parts []string
		for _, p := range ps {
			lo, hi, _ := portBounds(p)
			if lo == hi {
				parts = append(parts, fmt.Sprintf("==%d", lo))
			} else {
				parts = append(parts, fmt.Sprintf(">=%d&<=%d", lo, hi))
			}
		}
		m = append(m, fmt.Sprintf("%s '%s'", name, strings.Join(parts, " ")))
	}
	ports("source-port", f.SrcPorts)
	ports("destination-port", f.DstPorts)
	if f.PacketLength != "" {
		m = append(m, fmt.Sprintf("packet-length '%s'", exaLength(f.PacketLength)))
	}
	if f.Fragment {
		m = append(m, "fragment is-fragment")
	}
	then := "discard"
	if f.Action == "rate-limit" {
		then = fmt.Sprintf("rate-limit %d", rateBytes(f.RateBps))
	}
	return fmt.Sprintf("gobgp global rib -a %s add match %s then %s", fam, strings.Join(m, " "), then)
}

// Junos renders Junos "routing-options flow" set commands.
func (f *FlowSpec) Junos(name string) string {
	p := "set routing-options flow route " + name
	if strings.Contains(f.Destination+f.Source, ":") {
		p = "set routing-options rib inet6.0 flow route " + name
	}
	var out []string
	if f.Destination != "" {
		out = append(out, p+" match destination "+f.Destination)
	}
	if f.Source != "" {
		out = append(out, p+" match source "+f.Source)
	}
	for _, pr := range f.Protocols {
		out = append(out, p+" match protocol "+pr)
	}
	for _, sp := range f.SrcPorts {
		out = append(out, p+" match source-port "+sp)
	}
	for _, dp := range f.DstPorts {
		out = append(out, p+" match destination-port "+dp)
	}
	if f.PacketLength != "" {
		lo, hi, _ := lengthBounds(f.PacketLength)
		out = append(out, fmt.Sprintf("%s match packet-length %d-%d", p, lo, hi))
	}
	if f.Fragment {
		out = append(out, p+" match fragment is-fragment")
	}
	if len(f.TCPSet) > 0 || len(f.TCPNotSet) > 0 {
		var parts []string
		for _, s := range f.TCPSet {
			parts = append(parts, strings.ToLower(s))
		}
		for _, s := range f.TCPNotSet {
			parts = append(parts, "!"+strings.ToLower(s))
		}
		out = append(out, fmt.Sprintf("%s match tcp-flags \"%s\"", p, strings.Join(parts, " & ")))
	}
	for _, t := range f.ICMPTypes {
		out = append(out, fmt.Sprintf("%s match icmp-type %d", p, t))
	}
	if f.Action == "rate-limit" {
		out = append(out, fmt.Sprintf("%s then rate-limit %dk", p, int64(f.RateBps/1000)))
	} else {
		out = append(out, p+" then discard")
	}
	return strings.Join(out, "\n")
}

// IOSXR renders a Cisco IOS-XR flowspec policy.
func (f *FlowSpec) IOSXR(name string) string {
	cls := strings.ToUpper(name)
	afi := "ipv4"
	if strings.Contains(f.Destination+f.Source, ":") {
		afi = "ipv6"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "class-map type traffic match-all %s\n", cls)
	if f.Destination != "" {
		fmt.Fprintf(&b, " match destination-address %s %s\n", afi, f.Destination)
	}
	if f.Source != "" {
		fmt.Fprintf(&b, " match source-address %s %s\n", afi, f.Source)
	}
	for _, pr := range f.Protocols {
		n, _ := flow.ProtoNumber(pr)
		fmt.Fprintf(&b, " match protocol %d\n", n)
	}
	if len(f.SrcPorts) > 0 {
		fmt.Fprintf(&b, " match source-port %s\n", strings.Join(f.SrcPorts, " "))
	}
	if len(f.DstPorts) > 0 {
		fmt.Fprintf(&b, " match destination-port %s\n", strings.Join(f.DstPorts, " "))
	}
	if f.PacketLength != "" {
		lo, hi, _ := lengthBounds(f.PacketLength)
		fmt.Fprintf(&b, " match packet length %d-%d\n", lo, hi)
	}
	if f.Fragment {
		b.WriteString(" match fragment-type is-fragment\n")
	}
	b.WriteString(" end-class-map\n!\npolicy-map type pbr DDOS-MITIGATION\n")
	fmt.Fprintf(&b, " class type traffic %s\n", cls)
	if f.Action == "rate-limit" {
		fmt.Fprintf(&b, "  police rate %d kbps\n", int64(f.RateBps/1000))
	} else {
		b.WriteString("  drop\n")
	}
	fmt.Fprintf(&b, " !\n end-policy-map\n!\nflowspec\n address-family %s\n  service-policy type pbr DDOS-MITIGATION\n", afi)
	return b.String()
}

// Summary is a one-line description.
func (f *FlowSpec) Summary() string {
	s := f.exabgpMatch() + " → " + f.exabgpThen()
	return strings.ReplaceAll(s, ";", "")
}

// ExaBGPAnnounce renders the RTBH announcement.
func (r *RTBH) ExaBGPAnnounce() string {
	return fmt.Sprintf("announce route %s next-hop %s community [%s]", r.Prefix, r.NextHop, r.Community)
}

// ExaBGPWithdraw renders the RTBH withdrawal.
func (r *RTBH) ExaBGPWithdraw() string {
	return fmt.Sprintf("withdraw route %s next-hop %s", r.Prefix, r.NextHop)
}

// Render returns vendor-specific representations.
func (m *Mitigation) render() map[string]string {
	name := "ddos-" + strings.ToLower(m.ID)
	switch {
	case m.FlowSpec != nil:
		return map[string]string{
			"exabgp":   m.FlowSpec.ExaBGPAnnounce(),
			"gobgp":    m.FlowSpec.GoBGP(),
			"junos":    m.FlowSpec.Junos(name),
			"iosxr":    m.FlowSpec.IOSXR(name),
			"withdraw": m.FlowSpec.ExaBGPWithdraw(),
		}
	case m.RTBH != nil:
		return map[string]string{
			"exabgp":   m.RTBH.ExaBGPAnnounce(),
			"gobgp":    fmt.Sprintf("gobgp global rib add %s nexthop %s community %s", m.RTBH.Prefix, m.RTBH.NextHop, m.RTBH.Community),
			"junos":    fmt.Sprintf("set routing-options static route %s discard community %s tag 666", m.RTBH.Prefix, m.RTBH.Community),
			"iosxr":    fmt.Sprintf("router static\n address-family ipv4 unicast\n  %s Null0 tag 666\n! export with community %s via route-policy", m.RTBH.Prefix, m.RTBH.Community),
			"withdraw": m.RTBH.ExaBGPWithdraw(),
		}
	}
	return nil
}
