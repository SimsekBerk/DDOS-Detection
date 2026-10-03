package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/app"
	"github.com/SimsekBerk/DDOS-Detection/internal/auth"
)

const testConfig = `
collector:
  listen: ["127.0.0.1:0"]
protected_objects:
  - name: Musteri-A
    prefixes: ["198.51.100.0/24"]
    profile: datacenter
  - name: Musteri-B
    prefixes: ["203.0.113.0/24"]
rules_dir: %RULES%
data_dir: %DATA%
api:
  listen: "127.0.0.1:0"
  username: admin
  password: admin-password-123
`

type client struct {
	t      *testing.T
	h      http.Handler
	cookie *http.Cookie
	token  string
}

func (c *client) do(method, path string, body any, csrf bool) (int, map[string]any, string) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	if c.cookie != nil {
		req.AddCookie(c.cookie)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if csrf {
		req.Header.Set("X-Requested-With", "ddosd")
	}
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == sessionCookie {
			c.cookie = ck
		}
	}
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return rec.Code, m, rec.Body.String()
}

func setup(t *testing.T) (*app.App, http.Handler) {
	t.Helper()
	dir := t.TempDir()
	rules, _ := filepath.Abs("../../rules")
	cfg := strings.NewReplacer("%RULES%", rules, "%DATA%", filepath.Join(dir, "data")).Replace(testConfig)
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := app.New(path, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return a, New(a, nil).Handler()
}

func TestAuthRBACAndCSRF(t *testing.T) {
	a, h := setup(t)
	anon := &client{t: t, h: h}
	if code, _, _ := anon.do("GET", "/api/v1/overview", nil, false); code != 401 {
		t.Fatalf("anonymous overview = %d", code)
	}
	admin := &client{t: t, h: h}
	if code, _, body := admin.do("POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": "wrong"}, false); code != 401 {
		t.Fatalf("bad login = %d %s", code, body)
	}
	if code, m, _ := admin.do("POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": "admin-password-123"}, false); code != 200 || m["can_admin"] != true {
		t.Fatalf("login = %d %v", code, m)
	}
	if code, _, _ := admin.do("GET", "/api/v1/overview", nil, false); code != 200 {
		t.Fatalf("overview = %d", code)
	}
	// CSRF: mutation without header is refused.
	if code, _, _ := admin.do("PUT", "/api/v1/users/noc", map[string]any{"role": "operator", "password": "operator-pass-1"}, false); code != 403 {
		t.Fatalf("csrf not enforced: %d", code)
	}
	if code, _, body := admin.do("PUT", "/api/v1/users/noc", map[string]any{"role": "viewer", "password": "viewer-pass-12"}, true); code != 200 {
		t.Fatalf("create user = %d %s", code, body)
	}
	viewer := &client{t: t, h: h}
	viewer.do("POST", "/api/v1/auth/login", map[string]string{"username": "noc", "password": "viewer-pass-12"}, false)
	if code, _, _ := viewer.do("GET", "/api/v1/incidents", nil, false); code != 200 {
		t.Fatalf("viewer read = %d", code)
	}
	if code, _, _ := viewer.do("POST", "/api/v1/mitigations", map[string]any{"kind": "flowspec"}, true); code != 403 {
		t.Fatalf("viewer mutation = %d", code)
	}
	if code, _, _ := viewer.do("GET", "/api/v1/config", nil, false); code != 403 {
		t.Fatalf("viewer config = %d", code)
	}
	// audit has the user creation and the failed login
	_, _, body := admin.do("GET", "/api/v1/audit", nil, false)
	if !strings.Contains(body, "user.save") || !strings.Contains(body, "auth.login") {
		t.Errorf("audit missing entries: %s", body)
	}
	_ = a
}

func TestTenantScopeAndTokens(t *testing.T) {
	a, h := setup(t)
	if err := a.Users.Upsert(auth.UserInput{Username: "musteri", Role: auth.RoleOperator, Objects: []string{"Musteri-A"}, Password: "tenant-pass-12"}); err != nil {
		t.Fatal(err)
	}
	raw, err := a.Users.CreateToken("musteri", "grafana")
	if err != nil {
		t.Fatal(err)
	}
	c := &client{t: t, h: h, token: raw}
	code, m, _ := c.do("GET", "/api/v1/overview", nil, false)
	if code != 200 {
		t.Fatalf("token overview = %d", code)
	}
	objs := m["engine"].(map[string]any)["objects"].([]any)
	if len(objs) != 1 || objs[0].(map[string]any)["name"] != "Musteri-A" {
		t.Fatalf("scope not applied: %v", objs)
	}
	if _, ok := m["exporters_total"]; ok {
		t.Error("scoped user must not see infrastructure counters")
	}
	if code, _, _ := c.do("GET", "/api/v1/exporters", nil, false); code != 403 {
		t.Errorf("scoped exporters = %d", code)
	}
	if code, _, _ := c.do("GET", "/api/v1/target?ip=203.0.113.5", nil, false); code != 403 {
		t.Errorf("out-of-scope target = %d", code)
	}
	if code, _, _ := c.do("GET", "/metrics", nil, false); code != 401 {
		t.Errorf("scoped metrics = %d", code)
	}
	if code, _, _ := c.do("POST", "/api/v1/mitigations", map[string]any{"kind": "flowspec", "flowspec": map[string]any{"destination": "203.0.113.5/32", "protocols": []string{"udp"}, "action": "discard"}}, false); code != 403 {
		t.Errorf("out-of-scope mitigation = %d", code)
	}
}

func TestConfigEditApplyAndRestore(t *testing.T) {
	a, h := setup(t)
	admin := &client{t: t, h: h}
	admin.do("POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": "admin-password-123"}, false)
	_, m, _ := admin.do("GET", "/api/v1/config", nil, false)
	cfg := m["config"].(map[string]any)
	if cfg["api"].(map[string]any)["password"] != "********" {
		t.Fatalf("password not masked: %v", cfg["api"])
	}
	objs := cfg["protected_objects"].([]any)
	objs = append(objs, map[string]any{"name": "Yeni-Musteri", "prefixes": []string{"192.0.2.0/24"}, "profile": "web", "link_capacity": "1G"})
	cfg["protected_objects"] = objs
	cfg["mitigation"].(map[string]any)["mode"] = "auto"
	// invalid change is rejected and nothing is applied
	bad := map[string]any{}
	b, _ := json.Marshal(cfg)
	_ = json.Unmarshal(b, &bad)
	bad["mitigation"].(map[string]any)["mode"] = "yolo"
	if code, _, _ := admin.do("PUT", "/api/v1/config", map[string]any{"config": bad}, true); code != 400 {
		t.Fatalf("invalid config accepted: %d", code)
	}
	code, res, body := admin.do("PUT", "/api/v1/config", map[string]any{"config": cfg, "comment": "yeni müşteri"}, true)
	if code != 200 {
		t.Fatalf("apply = %d %s", code, body)
	}
	if a.Eng.ObjectByName("Yeni-Musteri") == nil || a.Mit.Mode() != "auto" {
		t.Fatal("config not hot-applied")
	}
	if len(res["restart_required"].([]any)) != 0 {
		t.Errorf("unexpected restart requirement: %v", res["restart_required"])
	}
	// persisted file keeps the real password and the new object
	saved, _ := os.ReadFile(a.Path)
	if !strings.Contains(string(saved), "Yeni-Musteri") || !strings.Contains(string(saved), "admin-password-123") {
		t.Fatalf("persisted config wrong:\n%s", saved)
	}
	_, _, hist := admin.do("GET", "/api/v1/config/history", nil, false)
	var entries []map[string]any
	_ = json.Unmarshal([]byte(hist), &entries)
	if len(entries) != 1 || entries[0]["comment"] != "yeni müşteri" {
		t.Fatalf("history: %s", hist)
	}
	// restore the previous file
	prev := entries[0]["id"].(string) + "-onceki"
	if code, _, body := admin.do("POST", "/api/v1/config/history/"+prev+"/restore", nil, true); code != 200 {
		t.Fatalf("restore = %d %s", code, body)
	}
	if a.Eng.ObjectByName("Yeni-Musteri") != nil || a.Mit.Mode() != "manual" {
		t.Fatal("restore did not apply")
	}
}

func TestMetricsAndExports(t *testing.T) {
	a, h := setup(t)
	raw, _ := a.Users.CreateToken("admin", "prometheus")
	c := &client{t: t, h: h, token: raw}
	code, _, body := c.do("GET", "/metrics", nil, false)
	if code != 200 || !strings.Contains(body, "ddosd_flow_records_total") || !strings.Contains(body, `object="Musteri-A"`) {
		t.Fatalf("metrics = %d\n%s", code, body)
	}
	code, _, body = c.do("GET", "/api/v1/incidents/export.csv", nil, false)
	if code != 200 || !strings.Contains(body, "olay;durum;önem") {
		t.Fatalf("csv = %d %q", code, body)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 {
		t.Fatal("healthz")
	}
}

// A channel tested from the UI before saving has no defaults applied yet;
// the handler must fill them (syslog protocol) and reject invalid input.
func TestNotificationTestAppliesDefaults(t *testing.T) {
	_, h := setup(t)
	admin := &client{t: t, h: h}
	admin.do("POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": "admin-password-123"}, false)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	ch := map[string]any{"name": "siem", "type": "syslog", "enabled": true, "address": pc.LocalAddr().String()}
	if code, _, body := admin.do("POST", "/api/v1/notifications/test", ch, true); code != 200 {
		t.Fatalf("syslog test without protocol: %d %s", code, body)
	}
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := pc.ReadFrom(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "ddosd") {
		t.Fatalf("no syslog datagram: %v %q", err, buf[:n])
	}
	bad := map[string]any{"name": "x", "type": "webhook", "url": "ftp://nope"}
	if code, _, _ := admin.do("POST", "/api/v1/notifications/test", bad, true); code != 400 {
		t.Fatalf("invalid channel accepted: %d", code)
	}
}

// Restart-only settings are reported as pending until they match the values
// the process started with again.
func TestRestartPendingClearsOnRevert(t *testing.T) {
	a, h := setup(t)
	admin := &client{t: t, h: h}
	admin.do("POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": "admin-password-123"}, false)
	put := func(workers float64) map[string]any {
		_, m, _ := admin.do("GET", "/api/v1/config", nil, false)
		cfg := m["config"].(map[string]any)
		cfg["collector"].(map[string]any)["workers"] = workers
		code, res, body := admin.do("PUT", "/api/v1/config", map[string]any{"config": cfg}, true)
		if code != 200 {
			t.Fatalf("apply = %d %s", code, body)
		}
		return res
	}
	orig := float64(a.Config().Collector.Workers)
	if res := put(orig + 3); len(res["restart_required"].([]any)) != 1 || len(a.RestartPending()) != 1 {
		t.Fatalf("workers change not pending: %v %v", res["restart_required"], a.RestartPending())
	}
	put(orig)
	if p := a.RestartPending(); len(p) != 0 {
		t.Fatalf("pending after revert: %v", p)
	}
}
