// Command ddos-probe is a passive packet sensor. It captures packets on a
// local interface, builds flows like a router's flow cache and exports them
// as IPFIX to ddosd. Use it where no router flow export is available, e.g.
// to monitor a single server or a workstation.
//
//	ddos-probe -i en0 -collector 127.0.0.1:9995
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/SimsekBerk/DDOS-Detection/internal/probe"
)

func main() {
	var o probe.Options
	flag.StringVar(&o.Interface, "i", "en0", "capture interface")
	flag.StringVar(&o.Collector, "collector", "127.0.0.1:2055", "ddosd collector (host:port)")
	flag.DurationVar(&o.Active, "active", 0, "active timeout (default 10s)")
	flag.DurationVar(&o.Inactive, "inactive", 0, "inactive timeout (default 5s)")
	flag.IntVar(&o.MaxFlows, "max-flows", 0, "flow cache size (default 200000)")
	flag.BoolVar(&o.Promisc, "promisc", false, "promiscuous capture (only on a mirror port you are authorized to monitor)")
	jsonLog := flag.Bool("log-json", false, "JSON log output")
	flag.Parse()

	var h slog.Handler = slog.NewTextHandler(os.Stderr, nil)
	if *jsonLog {
		h = slog.NewJSONHandler(os.Stderr, nil)
	}
	log := slog.New(h)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := probe.Run(ctx, o, log); err != nil {
		log.Error("probe", "err", err)
		os.Exit(1)
	}
}
