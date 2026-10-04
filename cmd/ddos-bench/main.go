// Command ddos-bench measures detection accuracy, time-to-detect, false
// positives and throughput. Scenarios run on a simulated clock through the
// real decoder and engine, with router flow-cache timeouts emulated.
//
//	ddos-bench detect      # every scenario × every telemetry mode
//	ddos-bench baseline    # background traffic only → false positives
//	ddos-bench throughput  # decode / engine / UDP end-to-end capacity
//	ddos-bench all -json results.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/bench"
	"github.com/SimsekBerk/DDOS-Detection/internal/sim"
)

type report struct {
	Generated  string                   `json:"generated"`
	Host       string                   `json:"host"`
	Detection  []bench.Result           `json:"detection,omitempty"`
	Baseline   []bench.BaselineResult   `json:"baseline,omitempty"`
	Throughput []bench.ThroughputResult `json:"throughput,omitempty"`
	Sizing     []bench.SizingResult     `json:"sizing,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "kullanım: ddos-bench detect|baseline|throughput|sizing|all [-rules dir] [-json out.json] [-only ids] [-tel names]")
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	rules := fs.String("rules", "rules", "rules directory")
	jsonOut := fs.String("json", "", "write JSON results")
	only := fs.String("only", "", "comma separated scenario ids")
	telFilter := fs.String("tel", "", "comma separated telemetry name prefixes (e.g. sflow,ipfix)")
	baselineMin := fs.Int("baseline-minutes", 60, "simulated minutes for the false-positive run")
	workers := fs.Int("workers", runtime.NumCPU(), "parallel scenario workers")
	phases := fs.Int("phases", 1, "false-positive run: repeat with this many start phases of the traffic wave")
	rates := fs.String("rate", "150000,350000,1000000", "sizing: flow records per second (comma separated)")
	prefixes := fs.Int("prefixes", 2000, "sizing: protected customer prefixes")
	hosts := fs.Int("hosts", 100000, "sizing: distinct active destination hosts")
	exporters := fs.Int("exporters", 9, "sizing: routers exporting flows")
	sampling := fs.Int("sampling", 1000, "sizing: packet sampling rate (1:N)")
	seconds := fs.Int("seconds", 30, "sizing: simulated seconds per rate")
	flowSeconds := fs.Int("flow-seconds", 30, "sizing: seconds of flow history kept for forensics")
	maxSeries := fs.Int("max-series", 2_000_000, "sizing: engine.max_series")
	networkPPS := fs.Float64("network-pps", 0, "sizing: real packets/s described by the records (e.g. 330e6); 0 = 1-3 sampled packets per record")
	attackPPS := fs.Float64("attack-pps", 0, "sizing: additional attack packets/s (real, before sampling)")
	attackTargets := fs.Int("attack-targets", 20, "sizing: hosts hit by the attack")
	_ = fs.Parse(os.Args[2:])

	opts := bench.Options{RulesDir: *rules}
	tels := bench.DefaultTelemetry
	if *telFilter != "" {
		var sel []bench.Telemetry
		for _, t := range tels {
			for _, f := range strings.Split(*telFilter, ",") {
				if strings.HasPrefix(strings.ToLower(t.Name), strings.ToLower(strings.TrimSpace(f))) {
					sel = append(sel, t)
				}
			}
		}
		tels = sel
	}
	host, _ := os.Hostname()
	rep := report{Generated: time.Now().Format(time.RFC3339), Host: fmt.Sprintf("%s %s/%s %d CPU", host, runtime.GOOS, runtime.GOARCH, runtime.NumCPU())}

	if cmd == "detect" || cmd == "all" {
		rep.Detection = detect(opts, tels, *only, *workers)
		printDetection(rep.Detection)
	}
	if cmd == "baseline" || cmd == "all" {
		for _, t := range tels {
			for ph := 0; ph < *phases; ph++ {
				o := opts
				o.StartPhase = ph * 600 / *phases
				baselineRun(&rep, o, t, *baselineMin, *phases)
			}
		}
	}
	if cmd == "throughput" || cmd == "all" {
		for _, enc := range []string{"netflow9", "ipfix", "sflow"} {
			r := bench.DecodeThroughput(opts, enc, 3*time.Second)
			rep.Throughput = append(rep.Throughput, r)
			fmt.Printf("decode   %-9s %12.0f kayıt/sn  %s\n", enc, r.RecordsPerSec, r.Note)
		}
		r := bench.EngineThroughput(opts, 5*time.Second)
		rep.Throughput = append(rep.Throughput, r)
		fmt.Printf("engine   %-9s %12.0f kayıt/sn  %s\n", r.Encoder, r.RecordsPerSec, r.Note)
		for _, rate := range []float64{500_000, 1_000_000, 2_000_000, 3_000_000, 4_000_000} {
			r := bench.EndToEnd(opts, "ipfix", rate, 5*time.Second)
			rep.Throughput = append(rep.Throughput, r)
			fmt.Printf("e2e-udp  %-9s %12.0f kayıt/sn  kayıp %%%.2f  %s\n", r.Encoder, r.RecordsPerSec, r.LossPct, r.Note)
		}
	}
	if cmd == "sizing" {
		fmt.Printf("sizing: %d prefix, %d aktif host, %d exporter, örnekleme 1:%d, %d sn flow geçmişi\n", *prefixes, *hosts, *exporters, *sampling, *flowSeconds)
		for _, rs := range strings.Split(*rates, ",") {
			var rate int
			fmt.Sscan(strings.TrimSpace(rs), &rate)
			r := bench.Sizing(opts, bench.SizingOptions{RecordsPerSec: rate, Prefixes: *prefixes, Hosts: *hosts, Exporters: *exporters,
				Sampling: uint32(*sampling), Seconds: *seconds, FlowSeconds: *flowSeconds, MaxSeries: *maxSeries,
				NetworkPPS: *networkPPS, AttackPPS: *attackPPS, AttackTargets: *attackTargets})
			rep.Sizing = append(rep.Sizing, r)
			if r.Note != "" {
				fmt.Println("  hata:", r.Note)
				continue
			}
			fmt.Printf("  %8d kayıt/sn → motor doluluğu %%%5.1f (kapasite %8.0f kayıt/sn) | değerlendirme %5.1f ms/sn | sınıflandırma %8.0f kayıt/sn/çekirdek | seri %7d (taşma %d) | olay %d | bellek %6.0f MB (flow deposu %5.0f, nesne/kural %4.0f, seriler %5.0f)\n",
				r.TotalRecords, 100*r.Utilization, r.EngineCapacity, r.EvalMillis, r.ClassifyPerCore, r.Series, r.SeriesOverflow, r.Incidents, r.HeapMB, r.FlowstoreMB, r.BaseMB, r.SeriesMB)
		}
	}
	if *jsonOut != "" {
		b, _ := json.MarshalIndent(rep, "", "  ")
		if err := os.WriteFile(*jsonOut, b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}

func detect(opts bench.Options, tels []bench.Telemetry, only string, workers int) []bench.Result {
	var scs []sim.Scenario
	for _, s := range sim.Scenarios() {
		if only == "" || contains(strings.Split(only, ","), s.ID) {
			scs = append(scs, s)
		}
	}
	type job struct {
		t  bench.Telemetry
		sc sim.Scenario
	}
	jobs := make(chan job)
	var mu sync.Mutex
	var out []bench.Result
	var wg sync.WaitGroup
	for i := 0; i < max(1, workers); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				r := bench.RunScenario(opts, j.t, j.sc)
				mu.Lock()
				out = append(out, r)
				fmt.Fprintf(os.Stderr, ".")
				mu.Unlock()
			}
		}()
	}
	for _, t := range tels {
		for _, sc := range scs {
			jobs <- job{t, sc}
		}
	}
	close(jobs)
	wg.Wait()
	fmt.Fprintln(os.Stderr)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Telemetry != out[j].Telemetry {
			return out[i].Telemetry < out[j].Telemetry
		}
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Scenario < out[j].Scenario
	})
	return out
}

func printDetection(rs []bench.Result) {
	cur := ""
	pass, total := 0, 0
	for _, r := range rs {
		if r.Telemetry != cur {
			cur = r.Telemetry
			fmt.Printf("\n== %s ==\n%-18s %-6s %5s %6s  %-40s %s\n", cur, "senaryo", "sonuç", "TTD", "bitiş", "eşleşen / eksik", "ek / yanlış hedef")
		}
		total++
		st := "FAIL"
		if r.Pass {
			st = "ok"
			pass++
		}
		ttd := "-"
		if r.TTD >= 0 {
			ttd = fmt.Sprintf("%ds", r.TTD)
		}
		if r.ExpectSignal != "" {
			ttd = map[bool]string{true: "sinyal", false: "yok"}[r.SignalOK]
		}
		end := "-"
		if r.EndAfter >= 0 {
			end = fmt.Sprintf("%ds", r.EndAfter)
		}
		fmt.Printf("%-18s %-6s %5s %6s  %-40s %s %s\n", r.Scenario, st, ttd, end,
			trim(strings.Join(r.Hit, ",")+" / "+strings.Join(r.Missed, ","), 40),
			strings.Join(r.Extra, ","), strings.Join(r.OtherTargets, "; "))
	}
	fmt.Printf("\nToplam: %d/%d geçti\n", pass, total)
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if strings.TrimSpace(x) == s {
			return true
		}
	}
	return false
}

// baselineRun measures false positives on background traffic only.
func baselineRun(rep *report, o bench.Options, t bench.Telemetry, minutes, phases int) {
	start := time.Now()
	r := bench.RunBaseline(o, t, minutes*60)
	rep.Baseline = append(rep.Baseline, r)
	phase := ""
	if phases > 1 {
		phase = fmt.Sprintf(" faz %3ds", o.StartPhase)
	}
	fmt.Printf("baseline %-28s%s %4d dk → %d olay, %d sinyal (%s) [%s]\n", t.Name, phase, minutes, len(r.Incidents), r.Signals, strings.Join(r.SignalIDs, " "), time.Since(start).Round(time.Millisecond))
	for _, i := range r.Incidents {
		fmt.Println("   FP:", i)
	}
}
