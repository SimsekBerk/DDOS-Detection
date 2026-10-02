package mitigation

import (
	"strings"
	"testing"
)

func TestFlowSpecRendering(t *testing.T) {
	fs := &FlowSpec{Destination: "198.51.100.10/32", Protocols: []string{"udp"}, SrcPorts: []string{"53"}, PacketLength: ">=512", Action: "discard"}
	if err := fs.Validate(); err != nil {
		t.Fatal(err)
	}
	want := "announce flow route { match { destination 198.51.100.10/32; protocol udp; source-port =53; packet-length >=512; } then { discard; } }"
	if got := fs.ExaBGPAnnounce(); got != want {
		t.Errorf("exabgp:\n got %s\nwant %s", got, want)
	}
	if got := fs.GoBGP(); !strings.Contains(got, "match destination 198.51.100.10/32 protocol udp source-port '==53' packet-length '>=512' then discard") {
		t.Errorf("gobgp: %s", got)
	}
	j := fs.Junos("r1")
	for _, s := range []string{"match destination 198.51.100.10/32", "match protocol udp", "match source-port 53", "match packet-length 512-65535", "then discard"} {
		if !strings.Contains(j, s) {
			t.Errorf("junos missing %q in\n%s", s, j)
		}
	}
	rl := &FlowSpec{Destination: "198.51.100.0/24", Protocols: []string{"udp"}, Fragment: true, Action: "rate-limit", RateBps: 80e6}
	if got := rl.ExaBGPAnnounce(); !strings.Contains(got, "fragment [ is-fragment ];") || !strings.Contains(got, "rate-limit 10000000;") {
		t.Errorf("rate-limit rendering: %s", got)
	}
}

func TestFlowSpecValidation(t *testing.T) {
	bad := []*FlowSpec{
		{Action: "discard"},
		{Destination: "nope", Action: "discard"},
		{Destination: "198.51.100.1/32", Protocols: []string{"xyz"}, Action: "discard"},
		{Destination: "198.51.100.1/32", Action: "rate-limit"},
		{Destination: "198.51.100.1/32", SrcPorts: []string{"70000"}, Action: "discard"},
	}
	for i, f := range bad {
		if f.Validate() == nil {
			t.Errorf("case %d should fail validation", i)
		}
	}
}

func TestFlowSpecFromHint(t *testing.T) {
	fs, err := FlowSpecFromHint("203.0.113.5", "outbound", "udp", []int{123}, nil, 200, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if fs.Source != "203.0.113.5/32" || fs.Destination != "" || fs.PacketLength != ">=200" || fs.Action != "discard" {
		t.Errorf("unexpected flowspec %+v", fs)
	}
}
