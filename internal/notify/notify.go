// Package notify delivers alerts to webhook, Slack, Microsoft Teams,
// Telegram, syslog and e-mail channels with filtering, de-duplication and
// retries.
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/config"
)

// Event is an alert.
type Event struct {
	Type         string `json:"type"` // incident.started, incident.ended, vector.added, mitigation.*, finding.created, system.test
	Severity     string `json:"severity"`
	Title        string `json:"title"`
	Text         string `json:"text"`
	Time         int64  `json:"time"`
	URL          string `json:"url,omitempty"`
	IncidentID   string `json:"incident_id,omitempty"`
	MitigationID string `json:"mitigation_id,omitempty"`
	FindingID    string `json:"finding_id,omitempty"`
	Target       string `json:"target,omitempty"`
	Object       string `json:"object,omitempty"`
}

// DefaultEvents are sent when a channel lists no events.
var DefaultEvents = []string{"incident.started", "incident.ended", "mitigation.pending", "mitigation.failed", "finding.created"}

// ChannelStatus reports delivery health.
type ChannelStatus struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Enabled   bool   `json:"enabled"`
	Sent      int    `json:"sent"`
	Failed    int    `json:"failed"`
	LastSent  int64  `json:"last_sent,omitempty"`
	LastError string `json:"last_error,omitempty"`
}

type Notifier struct {
	log    *slog.Logger
	client *http.Client
	queue  chan Event

	mu       sync.Mutex
	channels []config.ChannelConfig
	baseURL  string
	seen     map[string]int64
	status   map[string]*ChannelStatus
}

func New(cfg *config.Config, log *slog.Logger) *Notifier {
	n := &Notifier{
		log: log, client: &http.Client{Timeout: 10 * time.Second}, queue: make(chan Event, 1024),
		seen: map[string]int64{}, status: map[string]*ChannelStatus{},
	}
	n.Update(cfg)
	return n
}

// Update replaces channels at runtime.
func (n *Notifier) Update(cfg *config.Config) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.channels = append([]config.ChannelConfig(nil), cfg.Notifications.Channels...)
	n.baseURL = strings.TrimRight(cfg.API.BaseURL, "/")
	next := map[string]*ChannelStatus{}
	for _, ch := range n.channels {
		st := n.status[ch.Name]
		if st == nil {
			st = &ChannelStatus{}
		}
		st.Name, st.Type, st.Enabled = ch.Name, ch.Type, ch.Enabled
		next[ch.Name] = st
	}
	n.status = next
}

// Status returns per-channel delivery statistics.
func (n *Notifier) Status() []ChannelStatus {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := []ChannelStatus{}
	for _, ch := range n.channels {
		if st := n.status[ch.Name]; st != nil {
			out = append(out, *st)
		}
	}
	return out
}

// Notify queues an event (never blocks).
func (n *Notifier) Notify(ev Event) {
	if ev.Time == 0 {
		ev.Time = time.Now().Unix()
	}
	n.mu.Lock()
	if ev.URL == "" && n.baseURL != "" {
		switch {
		case ev.IncidentID != "":
			ev.URL = n.baseURL + "/#/incidents/" + ev.IncidentID
		case ev.FindingID != "":
			ev.URL = n.baseURL + "/#/analyst/" + ev.FindingID
		case ev.MitigationID != "":
			ev.URL = n.baseURL + "/#/mitigations"
		}
	}
	// De-duplicate bursts (e.g. several vectors of one incident).
	key := ev.Type + "|" + ev.IncidentID + "|" + ev.MitigationID + "|" + ev.FindingID
	if t, ok := n.seen[key]; ok && ev.Time-t < 30 {
		n.mu.Unlock()
		return
	}
	n.seen[key] = ev.Time
	if len(n.seen) > 10000 {
		n.seen = map[string]int64{}
	}
	n.mu.Unlock()
	select {
	case n.queue <- ev:
	default:
		n.log.Warn("notification queue full; event dropped", "type", ev.Type)
	}
}

// Run delivers queued events until ctx is done.
func (n *Notifier) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-n.queue:
			n.mu.Lock()
			chans := append([]config.ChannelConfig(nil), n.channels...)
			n.mu.Unlock()
			for _, ch := range chans {
				if !ch.Enabled || !wants(ch, ev) {
					continue
				}
				err := retry(ctx, func() error { return n.send(ctx, ch, ev) })
				n.record(ch.Name, err)
			}
		}
	}
}

// Test sends a test event to a channel definition (saved or not).
func (n *Notifier) Test(ctx context.Context, ch config.ChannelConfig) error {
	ev := Event{Type: "system.test", Severity: "low", Title: "ddosd test bildirimi", Text: "Bu kanal ddosd bildirimlerini başarıyla alıyor.", Time: time.Now().Unix()}
	err := n.send(ctx, ch, ev)
	n.record(ch.Name, err)
	return err
}

func (n *Notifier) record(name string, err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	st := n.status[name]
	if st == nil {
		return
	}
	if err != nil {
		st.Failed++
		st.LastError = err.Error()
		n.log.Warn("notification failed", "channel", name, "err", err)
		return
	}
	st.Sent++
	st.LastSent = time.Now().Unix()
	st.LastError = ""
}

var sevRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

func wants(ch config.ChannelConfig, ev Event) bool {
	if sevRank[ev.Severity] < sevRank[ch.MinSeverity] {
		return false
	}
	events := ch.Events
	if len(events) == 0 {
		events = DefaultEvents
	}
	for _, e := range events {
		if e == ev.Type {
			return true
		}
	}
	return false
}

func retry(ctx context.Context, f func() error) error {
	var err error
	for i, wait := range []time.Duration{0, 2 * time.Second, 5 * time.Second} {
		if i > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}
		if err = f(); err == nil {
			return nil
		}
	}
	return err
}

func plain(ev Event) string {
	s := ev.Title
	if ev.Text != "" {
		s += "\n" + ev.Text
	}
	if ev.URL != "" {
		s += "\n" + ev.URL
	}
	return s
}

func (n *Notifier) send(ctx context.Context, ch config.ChannelConfig, ev Event) error {
	switch ch.Type {
	case "webhook":
		body, _ := json.Marshal(map[string]any{"event": ev})
		h := map[string]string{}
		if ch.Secret != "" {
			mac := hmac.New(sha256.New, []byte(ch.Secret))
			mac.Write(body)
			h["X-DDoS-Signature"] = "sha256=" + hex.EncodeToString(mac.Sum(nil))
		}
		return n.post(ctx, ch.URL, body, h)
	case "slack":
		text := "*" + ev.Title + "*"
		if ev.Text != "" {
			text += "\n" + ev.Text
		}
		if ev.URL != "" {
			text += "\n<" + ev.URL + "|Ayrıntılar>"
		}
		body, _ := json.Marshal(map[string]string{"text": text})
		return n.post(ctx, ch.URL, body, nil)
	case "teams":
		blocks := []map[string]any{{"type": "TextBlock", "text": ev.Title, "weight": "bolder", "size": "medium", "wrap": true}}
		if ev.Text != "" {
			blocks = append(blocks, map[string]any{"type": "TextBlock", "text": ev.Text, "wrap": true})
		}
		card := map[string]any{"type": "AdaptiveCard", "version": "1.4", "body": blocks}
		if ev.URL != "" {
			card["actions"] = []map[string]any{{"type": "Action.OpenUrl", "title": "Ayrıntılar", "url": ev.URL}}
		}
		body, _ := json.Marshal(map[string]any{"type": "message", "attachments": []map[string]any{{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}}})
		return n.post(ctx, ch.URL, body, nil)
	case "telegram":
		body, _ := json.Marshal(map[string]any{"chat_id": ch.ChatID, "text": plain(ev), "disable_web_page_preview": true})
		return n.post(ctx, "https://api.telegram.org/bot"+ch.BotToken+"/sendMessage", body, nil)
	case "syslog":
		return sendSyslog(ch, ev)
	case "email":
		return sendMail(ch, ev)
	}
	return fmt.Errorf("bilinmeyen kanal tipi %q", ch.Type)
}

func (n *Notifier) post(ctx context.Context, url string, body []byte, headers map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return fmt.Errorf("HTTP %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

// sendSyslog writes an RFC 5424 message (facility local0).
func sendSyslog(ch config.ChannelConfig, ev Event) error {
	sev := map[string]int{"critical": 2, "high": 3, "medium": 4, "low": 5}[ev.Severity]
	if sev == 0 {
		sev = 6
	}
	host, _ := os.Hostname()
	msg := fmt.Sprintf("<%d>1 %s %s ddosd - %s - %s", 16*8+sev, time.Unix(ev.Time, 0).UTC().Format(time.RFC3339), host, ev.Type,
		strings.ReplaceAll(plain(ev), "\n", " | "))
	conn, err := net.DialTimeout(ch.Protocol, ch.Address, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if ch.Protocol == "tcp" {
		msg += "\n"
	}
	_, err = conn.Write([]byte(msg))
	return err
}

func sendMail(ch config.ChannelConfig, ev Event) error {
	addr := fmt.Sprintf("%s:%d", ch.SMTPHost, ch.SMTPPort)
	c, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: ch.SMTPHost, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	} else if ch.Username != "" {
		return errors.New("SMTP sunucusu STARTTLS desteklemiyor; kimlik bilgileri şifresiz gönderilmez")
	}
	if ch.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", ch.Username, ch.Password, ch.SMTPHost)); err != nil {
			return err
		}
	}
	if err := c.Mail(ch.From); err != nil {
		return err
	}
	for _, to := range ch.To {
		if err := c.Rcpt(to); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	msg := "From: " + ch.From + "\r\nTo: " + strings.Join(ch.To, ", ") + "\r\nSubject: [ddosd] " + ev.Title +
		"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + strings.ReplaceAll(plain(ev), "\n", "\r\n") + "\r\n"
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
