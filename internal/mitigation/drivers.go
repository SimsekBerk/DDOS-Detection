package mitigation

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// dryRunDriver only logs; it is the safe default for evaluations.
type dryRunDriver struct{ log *slog.Logger }

func (d *dryRunDriver) Name() string { return "dryrun" }

func (d *dryRunDriver) Announce(m *Mitigation) error {
	d.log.Info("[dry-run] announce", "id", m.ID, "kind", m.Kind, "cmd", m.Rendered["exabgp"])
	return nil
}

func (d *dryRunDriver) Withdraw(m *Mitigation) error {
	d.log.Info("[dry-run] withdraw", "id", m.ID, "cmd", m.Rendered["withdraw"])
	return nil
}

// exabgpDriver appends API commands to a file that ExaBGP reads through a
// process stanza, e.g. `run /usr/bin/tail -n0 -F /var/run/ddosd/exabgp.cmd;`.
type exabgpDriver struct {
	mu   sync.Mutex
	path string
}

func (d *exabgpDriver) Name() string { return "exabgp" }

func (d *exabgpDriver) write(line string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(d.path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(d.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line + "\n")
	return err
}

func (d *exabgpDriver) Announce(m *Mitigation) error {
	switch m.Kind {
	case "flowspec", "rtbh":
		return d.write(m.Rendered["exabgp"])
	}
	return nil // scrubbing needs an external integration (webhook)
}

func (d *exabgpDriver) Withdraw(m *Mitigation) error {
	switch m.Kind {
	case "flowspec", "rtbh":
		return d.write(m.Rendered["withdraw"])
	}
	return nil
}

// webhookDriver posts JSON events, signed with HMAC-SHA256 when a secret is set.
type webhookDriver struct {
	url    string
	secret string
	client http.Client
}

func (d *webhookDriver) Name() string { return "webhook" }

func (d *webhookDriver) send(event string, m *Mitigation) error {
	body, err := json.Marshal(map[string]any{"event": event, "time": time.Now().Unix(), "mitigation": m})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, d.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if d.secret != "" {
		mac := hmac.New(sha256.New, []byte(d.secret))
		mac.Write(body)
		req.Header.Set("X-DDoS-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	d.client.Timeout = 5 * time.Second
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}

func (d *webhookDriver) Announce(m *Mitigation) error { return d.send("announce", m) }
func (d *webhookDriver) Withdraw(m *Mitigation) error { return d.send("withdraw", m) }
