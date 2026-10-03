package notify

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/config"
)

func TestChannelsDeliverAndFilter(t *testing.T) {
	var mu sync.Mutex
	got := map[string][]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got[r.URL.Path] = append(got[r.URL.Path], string(b)+"§§"+r.Header.Get("X-DDoS-Signature"))
		mu.Unlock()
	}))
	defer srv.Close()
	udp, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer udp.Close()

	cfg := &config.Config{}
	cfg.API.BaseURL = "https://ddos.example.net"
	cfg.Notifications.Channels = []config.ChannelConfig{
		{Name: "hook", Type: "webhook", Enabled: true, URL: srv.URL + "/hook", Secret: "k", MinSeverity: "low"},
		{Name: "slack", Type: "slack", Enabled: true, URL: srv.URL + "/slack", MinSeverity: "high"},
		{Name: "teams", Type: "teams", Enabled: true, URL: srv.URL + "/teams", MinSeverity: "critical"},
		{Name: "sys", Type: "syslog", Enabled: true, Address: udp.LocalAddr().String(), Protocol: "udp", MinSeverity: "low"},
		{Name: "off", Type: "webhook", Enabled: false, URL: srv.URL + "/off", MinSeverity: "low"},
	}
	n := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)
	n.Notify(Event{Type: "incident.started", Severity: "high", Title: "Saldırı", Text: "198.51.100.10", IncidentID: "INC-1"})
	n.Notify(Event{Type: "incident.started", Severity: "high", Title: "dup", IncidentID: "INC-1"}) // de-duplicated
	n.Notify(Event{Type: "vector.added", Severity: "critical", Title: "not in default events", IncidentID: "INC-1"})

	buf := make([]byte, 2048)
	_ = udp.SetReadDeadline(time.Now().Add(3 * time.Second))
	k, _, err := udp.ReadFrom(buf)
	if err != nil || !strings.Contains(string(buf[:k]), "incident.started") || !strings.HasPrefix(string(buf[:k]), "<131>1 ") {
		t.Fatalf("syslog message: %q %v", buf[:k], err)
	}
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(got["/hook"]) != 1 || !strings.Contains(got["/hook"][0], "sha256=") || !strings.Contains(got["/hook"][0], "/#/incidents/INC-1") {
		t.Errorf("webhook: %v", got["/hook"])
	}
	if len(got["/slack"]) != 1 {
		t.Errorf("slack should get high severity: %v", got["/slack"])
	}
	if len(got["/teams"]) != 0 || len(got["/off"]) != 0 {
		t.Errorf("filtering failed: teams=%v off=%v", got["/teams"], got["/off"])
	}
	var card map[string]any
	_ = json.Unmarshal([]byte(strings.Split(got["/slack"][0], "§§")[0]), &card)
	if !strings.Contains(card["text"].(string), "Ayrıntılar") {
		t.Errorf("slack text: %v", card)
	}
}
