// Command ddosd is the DDoS detection daemon: flow collector, detection
// engine, mitigation orchestrator, AI analyst and web UI in one binary.
package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/SimsekBerk/DDOS-Detection/internal/analyst"
	"github.com/SimsekBerk/DDOS-Detection/internal/api"
	"github.com/SimsekBerk/DDOS-Detection/internal/collector"
	"github.com/SimsekBerk/DDOS-Detection/internal/config"
	"github.com/SimsekBerk/DDOS-Detection/internal/engine"
	"github.com/SimsekBerk/DDOS-Detection/internal/flowstore"
	"github.com/SimsekBerk/DDOS-Detection/internal/mitigation"
	"github.com/SimsekBerk/DDOS-Detection/internal/sim"
	"github.com/SimsekBerk/DDOS-Detection/web"
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "configuration file")
	debug := flag.Bool("debug", false, "debug logging")
	version := flag.Bool("version", false, "print version")
	flag.Parse()
	if *version {
		fmt.Println(api.Version)
		return
	}
	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	if err := run(*cfgPath, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(cfgPath string, log *slog.Logger) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st := flowstore.New(cfg.Engine.RecentFlows)
	eng, err := engine.New(cfg, st, log)
	if err != nil {
		return err
	}
	col := collector.New(cfg, eng.Submit, log)
	mit, err := mitigation.New(cfg, eng, log)
	if err != nil {
		return err
	}
	eng.SetHooks(mit)
	ana := analyst.New(cfg, eng, col, log)

	var simulator *sim.Simulator
	if cfg.Demo.Enabled {
		var prefixes []netip.Prefix
		for _, o := range cfg.Objects {
			prefixes = append(prefixes, o.Parsed...)
		}
		simulator, err = sim.New(cfg.Demo.Encoder, cfg.Demo.SamplingRate, cfg.Demo.Target, prefixes, float64(cfg.Demo.BaselineBPS))
		if err != nil {
			return fmt.Errorf("demo simulator: %w", err)
		}
		simulator.SetBaseline(cfg.Demo.Baseline, 0)
		log.Info("demo simulator enabled", "encoder", cfg.Demo.Encoder, "target", cfg.Demo.Target, "baseline", cfg.Demo.Baseline)
	}

	var ui fs.FS
	if sub, err := fs.Sub(web.Dist, "dist"); err == nil {
		ui = sub
	}
	srv := api.New(cfg, eng, col, mit, ana, simulator, ui, log)

	var wg sync.WaitGroup
	errc := make(chan error, 2)
	start := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f() }()
	}
	start(func() { eng.Run(ctx) })
	start(func() { mit.Run(ctx) })
	start(func() { ana.Loop(ctx) })
	start(func() {
		if err := col.Run(ctx); err != nil {
			errc <- fmt.Errorf("collector: %w", err)
		}
	})
	start(func() {
		if err := srv.Run(ctx); err != nil {
			errc <- fmt.Errorf("api: %w", err)
		}
	})
	if simulator != nil {
		start(func() { simulator.Loop(ctx) })
	}

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errc:
		stop()
		wg.Wait()
		return err
	}
	wg.Wait()
	return nil
}
