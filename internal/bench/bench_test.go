package bench

import (
	"testing"

	"github.com/SimsekBerk/DDOS-Detection/internal/sim"
)

// TestScenarioRegression replays representative scenarios through decoder and
// engine on a simulated clock and asserts detection without false targets.
func TestScenarioRegression(t *testing.T) {
	if testing.Short() {
		t.Skip("long scenario replay")
	}
	o := Options{RulesDir: "../../rules", Warmup: 360, Attack: 60, Cooldown: 30}
	ids := []string{"dns_amp", "carpet_ntp", "syn_flood", "stealth_dns", "out_reflector"}
	for _, tel := range []Telemetry{DefaultTelemetry[0], DefaultTelemetry[1]} {
		for _, id := range ids {
			sc, _ := sim.Lookup(id)
			r := RunScenario(o, tel, sc)
			if !r.Pass {
				t.Errorf("%s / %s failed: %+v", tel.Name, id, r)
			}
		}
	}
}

func TestBaselineNoFalsePositives(t *testing.T) {
	if testing.Short() {
		t.Skip("long baseline replay")
	}
	r := RunBaseline(Options{RulesDir: "../../rules"}, DefaultTelemetry[0], 1800)
	if len(r.Incidents) > 0 {
		t.Fatalf("false positive incidents: %v", r.Incidents)
	}
}
