package rules

import (
	"net/netip"
	"testing"

	"github.com/SimsekBerk/DDOS-Detection/internal/flow"
)

func load(t *testing.T) *Set {
	t.Helper()
	s, err := Load("../../rules", nil)
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	return s
}

func rec(proto uint8, sport, dport uint16, flags uint8, pkts, bytes uint64) *flow.Record {
	return &flow.Record{
		Src: netip.MustParseAddr("192.0.2.1"), Dst: netip.MustParseAddr("198.51.100.1"),
		Protocol: proto, SrcPort: sport, DstPort: dport, TCPFlags: flags, Packets: pkts, Bytes: bytes,
	}
}

func TestShippedRuleSetLoads(t *testing.T) {
	s := load(t)
	if len(s.Rules) < 40 {
		t.Errorf("expected a comprehensive rule set, got %d rules", len(s.Rules))
	}
	for _, r := range s.Rules {
		if r.Description == "" || r.Category == "" {
			t.Errorf("rule %s: description and category are required", r.ID)
		}
	}
}

func TestMatching(t *testing.T) {
	s := load(t)
	cases := []struct {
		rule string
		r    *flow.Record
		want bool
	}{
		{"amp_dns", rec(flow.ProtoUDP, 53, 40000, 0, 10, 14000), true},
		{"amp_dns", rec(flow.ProtoUDP, 53, 40000, 0, 10, 1000), false}, // small legit responses
		{"amp_dns", rec(flow.ProtoTCP, 53, 40000, 0, 10, 14000), false},
		{"amp_ntp", rec(flow.ProtoUDP, 123, 1000, 0, 10, 4680), true},
		{"amp_ntp", rec(flow.ProtoUDP, 123, 1000, 0, 10, 760), false},
		{"tcp_syn_flood", rec(flow.ProtoTCP, 1000, 80, flow.TCPSyn, 10, 600), true},
		{"tcp_syn_flood", rec(flow.ProtoTCP, 1000, 80, flow.TCPSyn|flow.TCPAck, 10, 600), false},
		{"tcp_synack_reflection", rec(flow.ProtoTCP, 80, 1000, flow.TCPSyn|flow.TCPAck, 10, 600), true},
		{"tcp_invalid_flags", rec(flow.ProtoTCP, 1, 2, 0, 1, 40), true},
		{"tcp_xmas_synfin", rec(flow.ProtoTCP, 1, 2, flow.TCPSyn|flow.TCPFin, 1, 40), true},
		{"tcp_xmas_synfin", rec(flow.ProtoTCP, 1, 2, flow.TCPFin|flow.TCPAck, 1, 40), false},
		{"udp_small_packet_flood", rec(flow.ProtoUDP, 1, 2, 0, 10, 640), true},
		{"udp_small_packet_flood", rec(flow.ProtoUDP, 1, 2, 0, 10, 6400), false},
		{"gre_flood", rec(flow.ProtoGRE, 0, 0, 0, 1, 100), true},
		{"ipproto_unusual", rec(flow.ProtoIPIP, 0, 0, 0, 1, 100), true},
		{"ipproto_unusual", rec(flow.ProtoGRE, 0, 0, 0, 1, 100), false},
		{"total_host", rec(flow.ProtoTCP, 1, 2, 0, 1, 100), true},
	}
	for _, c := range cases {
		r := s.ByID[c.rule]
		if r == nil {
			t.Fatalf("rule %s not found", c.rule)
		}
		if got := r.Matches(c.r); got != c.want {
			t.Errorf("%s matches %+v = %v, want %v", c.rule, c.r, got, c.want)
		}
	}

	frag := rec(flow.ProtoUDP, 0, 0, 0, 10, 15000)
	frag.Fragment = true
	if !s.ByID["udp_fragment_flood"].Matches(frag) {
		t.Error("udp fragment not matched")
	}
	if s.ByID["amp_dns"].Matches(frag) {
		t.Error("fragment must not match a port-based rule")
	}
	icmp := rec(flow.ProtoICMP, 0, 0, 0, 10, 840)
	icmp.ICMPType = 8
	if !s.ByID["icmp_echo_flood"].Matches(icmp) || s.ByID["icmp_echo_reply_flood"].Matches(icmp) {
		t.Error("icmp type matching wrong")
	}
}

func TestProfileScaling(t *testing.T) {
	s := load(t)
	dns := s.ByID["amp_dns"]
	def, ok := s.Effective(dns, "default")
	if !ok {
		t.Fatal("amp_dns disabled in default")
	}
	srv, _ := s.Effective(dns, "dns_server")
	if srv.PPS != def.PPS*30 { // 1.5 profile scale × 20 override
		t.Errorf("dns_server pps = %v, want %v", srv.PPS, def.PPS*30)
	}
	if _, ok := s.Effective(s.ByID["gre_flood"], "vpn_gateway"); ok {
		t.Error("gre_flood should be disabled for vpn_gateway")
	}
	off := false
	s2, err := Load("../../rules", map[string]Override{"amp_dns": {Enabled: &off}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.Effective(s2.ByID["amp_dns"], "default"); ok {
		t.Error("override did not disable rule")
	}
}
