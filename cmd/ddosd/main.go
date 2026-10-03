// Command ddosd is the DDoS detection daemon: flow collector, detection
// engine, mitigation orchestrator, AI analyst, notifications and web UI.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/SimsekBerk/DDOS-Detection/internal/api"
	"github.com/SimsekBerk/DDOS-Detection/internal/app"
	"github.com/SimsekBerk/DDOS-Detection/internal/auth"
	"github.com/SimsekBerk/DDOS-Detection/internal/config"
	"github.com/SimsekBerk/DDOS-Detection/web"
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "configuration file")
	debug := flag.Bool("debug", false, "debug logging")
	jsonLog := flag.Bool("log-json", false, "JSON log output")
	version := flag.Bool("version", false, "print version")
	uiDir := flag.String("ui-dir", "", "serve the web UI from this directory instead of the embedded build (UI development)")
	resetAdmin := flag.String("reset-admin", "", "set a new random password for this admin user and exit (run while ddosd is stopped)")
	flag.Parse()
	if *version {
		fmt.Println(api.Version)
		return
	}
	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler = slog.NewTextHandler(os.Stderr, opts)
	if *jsonLog {
		h = slog.NewJSONHandler(os.Stderr, opts)
	}
	log := slog.New(h)
	if *resetAdmin != "" {
		if err := reset(*cfgPath, *resetAdmin, log); err != nil {
			log.Error("reset-admin", "err", err)
			os.Exit(1)
		}
		return
	}
	if err := run(*cfgPath, *uiDir, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// reset sets a new password for an admin account (recovery path when the
// only admin password is lost). The password is printed once and written to
// <data_dir>/initial-admin-password.txt with 0600 permissions.
func reset(cfgPath, user string, log *slog.Logger) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	users, err := auth.Open(cfg.DataDir, cfg.API.SessionTTL.Duration, user, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		return err
	}
	pass, err := users.ResetAdmin(user)
	if err != nil {
		return err
	}
	file := filepath.Join(cfg.DataDir, "initial-admin-password.txt")
	if err := os.WriteFile(file, []byte(user+":"+pass+"\n"), 0o600); err != nil {
		log.Warn("could not write password file", "err", err)
	}
	fmt.Printf("Kullanıcı: %s\nYeni parola: %s\n(%s dosyasına da yazıldı)\n", user, pass, file)
	return nil
}

func run(cfgPath, uiDir string, log *slog.Logger) error {
	a, err := app.New(cfgPath, log)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var ui fs.FS
	if uiDir != "" {
		ui = os.DirFS(uiDir)
	} else if sub, err := fs.Sub(web.Dist, "dist"); err == nil {
		ui = sub
	}
	srv := api.New(a, ui)
	errc := make(chan error, 2)
	go func() { errc <- srv.Run(ctx) }()
	go func() { errc <- a.Run(ctx) }()
	select {
	case <-ctx.Done():
		log.Info("shutting down")
		<-errc
		<-errc
		return nil
	case err := <-errc:
		stop()
		<-errc
		return err
	}
}
