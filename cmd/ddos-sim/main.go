// Command ddos-sim sends synthetic NetFlow v5/v9, IPFIX or sFlow traffic with
// DDoS attack scenarios to a flow collector. Use it to test ddosd (or any
// other flow-based detector) without generating real attack traffic.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/config"
	"github.com/SimsekBerk/DDOS-Detection/internal/sim"
)

func main() {
	collector := flag.String("collector", "127.0.0.1:2055", "collector address host:port")
	encoder := flag.String("encoder", "netflow9", "netflow5 | netflow9 | ipfix | sflow")
	sampling := flag.Uint("sampling", 1, "sampling rate (1:N)")
	prefixes := flag.String("prefixes", "198.51.100.0/24", "comma separated protected prefixes (baseline targets, default attack target)")
	baseline := flag.String("baseline", "400Mbps", "baseline traffic rate (0 to disable)")
	scenario := flag.String("scenario", "", "comma separated scenario ids (see -list)")
	target := flag.String("target", "", "attack target IP (or prefix for carpet scenarios)")
	pps := flag.Float64("pps", 0, "attack rate in packets/s (0 = scenario default)")
	sources := flag.Int("sources", 0, "number of attack sources (0 = scenario default)")
	duration := flag.Duration("duration", 2*time.Minute, "attack duration (0 = until Ctrl+C)")
	list := flag.Bool("list", false, "list scenarios")
	flag.Parse()

	if *list {
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tKATEGORİ\tVARSAYILAN PPS\tAÇIKLAMA")
		for _, s := range sim.Scenarios() {
			fmt.Fprintf(tw, "%s\t%s\t%.0f\t%s\n", s.ID, s.Category, s.DefaultPPS, s.Description)
		}
		tw.Flush()
		return
	}
	var pfx []netip.Prefix
	for _, p := range strings.Split(*prefixes, ",") {
		pp, err := netip.ParsePrefix(strings.TrimSpace(p))
		if err != nil {
			fail("invalid prefix %q: %v", p, err)
		}
		pfx = append(pfx, pp.Masked())
	}
	bps, err := config.ParseRate(*baseline)
	if err != nil {
		fail("%v", err)
	}
	s, err := sim.New(*encoder, uint32(*sampling), *collector, pfx, bps)
	if err != nil {
		fail("%v", err)
	}
	s.SetBaseline(bps > 0, bps)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	dur := int(duration.Seconds())
	if dur == 0 {
		dur = 365 * 24 * 3600
	}
	if *scenario != "" {
		for _, id := range strings.Split(*scenario, ",") {
			run, err := s.Start(sim.StartRequest{Scenario: strings.TrimSpace(id), Target: *target, PPS: *pps, Sources: *sources, Duration: dur})
			if err != nil {
				fail("%v", err)
			}
			fmt.Printf("▶ %s (%s) hedef=%s pps=%.0f kaynak=%d süre=%s\n", run.Name, run.ID, run.Target, run.PPS, run.Sources, *duration)
		}
	}
	fmt.Printf("→ %s %s 1:%d gönderiliyor (baseline %s). Durdurmak için Ctrl+C.\n", *encoder, *collector, *sampling, *baseline)
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				st := s.Status()
				fmt.Printf("  datagram=%d kayıt=%d aktif senaryo=%d\n", st.Datagrams, st.Specs, len(st.Runs))
				if *scenario != "" && *duration > 0 && len(st.Runs) == 0 {
					fmt.Println("■ senaryolar tamamlandı")
					stop()
				}
			}
		}
	}()
	s.Loop(ctx)
}

func fail(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "ddos-sim: "+f+"\n", a...)
	os.Exit(1)
}
