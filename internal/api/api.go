// Package api exposes the REST API (sessions, API tokens, RBAC, tenant
// scoping, audit) and serves the embedded web UI.
package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/app"
	"github.com/SimsekBerk/DDOS-Detection/internal/audit"
	"github.com/SimsekBerk/DDOS-Detection/internal/auth"
)

// Version is set at build time.
var Version = "dev"

const sessionCookie = "ddosd_session"

type Server struct {
	app *app.App
	ui  fs.FS
	ctx context.Context
	mux *http.ServeMux
}

func New(a *app.App, ui fs.FS) *Server {
	s := &Server{app: a, ui: ui, mux: http.NewServeMux(), ctx: context.Background()}
	s.routes()
	return s
}

// Handler returns the HTTP handler (used by tests).
func (s *Server) Handler() http.Handler { return securityHeaders(s.mux) }

// Run serves HTTP(S) until ctx is done.
func (s *Server) Run(ctx context.Context) error {
	s.ctx = ctx
	cfg := s.app.Config().API
	srv := &http.Server{
		Addr: cfg.Listen, Handler: s.Handler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sh)
	}()
	s.app.Log.Info("web UI and API listening", "addr", cfg.Listen, "tls", cfg.TLSCert != "")
	var err error
	if cfg.TLSCert != "" {
		err = srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// ---------------------------------------------------------------- plumbing

type httpError struct {
	code int
	msg  string
}

func (e httpError) Error() string { return e.msg }

func errCode(code int, msg string) error { return httpError{code, msg} }
func notFound(msg string) error          { return httpError{http.StatusNotFound, msg} }
func forbidden(msg string) error         { return httpError{http.StatusForbidden, msg} }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 2<<20))
	if err := dec.Decode(v); err != nil {
		return errCode(http.StatusBadRequest, "geçersiz JSON gövdesi: "+err.Error())
	}
	return nil
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// authenticate resolves the caller from the session cookie or a Bearer token.
func (s *Server) authenticate(r *http.Request) (*auth.User, bool) {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		u, ok := s.app.Users.TokenUser(strings.TrimPrefix(h, "Bearer "))
		return u, ok && u != nil
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		if u, ok := s.app.Users.Session(c.Value); ok {
			return u, true
		}
	}
	return nil, false
}

// access describes who may call a route.
type access struct {
	role     string
	unscoped bool   // tenant-scoped users are rejected
	action   string // audit action name for mutating calls ("" = not audited)
}

var (
	readAny      = access{role: auth.RoleViewer}
	readInfra    = access{role: auth.RoleViewer, unscoped: true}
	operate      = access{role: auth.RoleOperator}
	operateInfra = access{role: auth.RoleOperator, unscoped: true}
	adminOnly    = access{role: auth.RoleAdmin, unscoped: true}
)

func (a access) with(action string) access { a.action = action; return a }

type handler func(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error)

// auditDetail lets responses add context to audit entries.
type auditDetail interface{ auditDetail() string }

// route registers an authenticated, authorized and (for mutations) audited
// JSON endpoint.
func (s *Server) route(pattern string, acc access, h handler) {
	s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		u, ok := s.authenticate(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "oturum gerekli"})
			return
		}
		mutating := r.Method != http.MethodGet && r.Method != http.MethodHead
		// CSRF: cookie-authenticated mutations must carry a custom header,
		// which browsers do not send cross-site without a CORS preflight.
		if mutating && !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") && r.Header.Get("X-Requested-With") != "ddosd" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "CSRF koruması: X-Requested-With başlığı eksik"})
			return
		}
		if !u.Can(acc.role) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "bu işlem için yetkiniz yok (" + acc.role + " gerekli)"})
			return
		}
		if acc.unscoped && u.Scoped() {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "müşteri kapsamlı hesaplar bu işlemi yapamaz"})
			return
		}
		v, err := h(w, r, u)
		if acc.action != "" && mutating {
			e := audit.Entry{User: u.Username, Role: u.Role, Client: clientIP(r), Action: acc.action, Target: strings.TrimPrefix(r.URL.Path, "/api/v1/"), OK: err == nil, Error: errString(err)}
			if d, ok := v.(auditDetail); ok {
				e.Detail = d.auditDetail()
			}
			s.app.Audit.Record(e)
		}
		if err != nil {
			code := http.StatusBadRequest
			var he httpError
			if errors.As(err, &he) {
				code = he.code
			}
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		if v == nil {
			return // handler wrote the response itself
		}
		writeJSON(w, http.StatusOK, v)
	})
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func qInt(r *http.Request, k string, def int) int {
	if v, err := strconv.Atoi(r.URL.Query().Get(k)); err == nil {
		return v
	}
	return def
}

func spaHandler(ui fs.FS) http.Handler {
	files := http.FileServer(http.FS(ui))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(ui, p); err != nil {
			if _, err := fs.Stat(ui, "index.html"); err != nil {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				_, _ = w.Write([]byte("UI derlenmemiş. 'make ui' çalıştırın."))
				return
			}
			r.URL.Path = "/"
		}
		if strings.HasPrefix(p, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}

// ------------------------------------------------------------------ routes

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	m.HandleFunc("GET /readyz", s.ready)
	m.HandleFunc("GET /metrics", s.metrics)
	m.HandleFunc("POST /api/v1/auth/login", s.login)
	m.HandleFunc("POST /api/v1/auth/logout", s.logout)

	s.route("GET /api/v1/auth/me", readAny, s.me)
	s.route("POST /api/v1/auth/password", readAny.with("auth.password"), s.changePassword)

	// monitoring
	s.route("GET /api/v1/overview", readAny, s.overview)
	s.route("GET /api/v1/timeseries", readAny, s.timeseries)
	s.route("GET /api/v1/incidents", readAny, s.incidents)
	s.route("GET /api/v1/incidents/export.csv", readAny, s.incidentsCSV)
	s.route("GET /api/v1/incidents/{id}", readAny, s.incident)
	s.route("GET /api/v1/incidents/{id}/report.md", readAny, s.incidentReport)
	s.route("GET /api/v1/incidents/{id}/top", readAny, s.incidentTop)
	s.route("GET /api/v1/signals", readAny, s.signals)
	s.route("GET /api/v1/series/top", readAny, s.seriesTop)
	s.route("GET /api/v1/target", readAny, s.target)
	s.route("POST /api/v1/flows/top", readAny, s.flowsTop)
	s.route("POST /api/v1/flows/breakdown", readAny, s.flowsBreakdown)
	s.route("POST /api/v1/flows/samples", readAny, s.flowsSamples)
	s.route("GET /api/v1/exporters", readInfra, s.exporters)
	s.route("GET /api/v1/rules", readAny, s.rules)

	// actions
	s.route("GET /api/v1/mitigations", readAny, s.mitigations)
	s.route("GET /api/v1/mitigations/{id}", readAny, s.mitigationGet)
	s.route("POST /api/v1/mitigations", operate.with("mitigation.create"), s.mitigationCreate)
	s.route("POST /api/v1/mitigations/{id}/{action}", operate.with("mitigation.action"), s.mitigationAction)
	s.route("GET /api/v1/analyst/status", readAny, s.analystStatus)
	s.route("GET /api/v1/analyst/findings", readAny, s.findings)
	s.route("GET /api/v1/analyst/findings/{id}", readAny, s.finding)
	s.route("POST /api/v1/analyst/run", operateInfra.with("analyst.run"), s.analystRun)
	s.route("POST /api/v1/analyst/incident/{id}", operateInfra.with("analyst.incident"), s.analystIncident)
	s.route("POST /api/v1/analyst/ask", operateInfra.with("analyst.ask"), s.analystAsk)
	s.route("POST /api/v1/analyst/findings/{id}/apply/{idx}", operateInfra.with("analyst.apply"), s.applyRecommendation)
	s.route("GET /api/v1/sim", readInfra, s.simStatus)
	s.route("POST /api/v1/sim/start", operateInfra.with("sim.start"), s.simStart)
	s.route("POST /api/v1/sim/stop", operateInfra.with("sim.stop"), s.simStop)
	s.route("POST /api/v1/sim/baseline", operateInfra.with("sim.baseline"), s.simBaseline)

	// administration
	s.route("PATCH /api/v1/rules/{id}", adminOnly.with("rule.update"), s.patchRule)
	s.route("POST /api/v1/rules/reload", adminOnly.with("rule.reload"), s.reloadRules)
	s.route("GET /api/v1/config", adminOnly, s.configGet)
	s.route("PUT /api/v1/config", adminOnly.with("config.update"), s.configPut)
	s.route("POST /api/v1/config/validate", adminOnly, s.configValidate)
	s.route("GET /api/v1/config/history", adminOnly, s.configHistory)
	s.route("GET /api/v1/config/history/{id}", adminOnly, s.configVersion)
	s.route("POST /api/v1/config/history/{id}/restore", adminOnly.with("config.restore"), s.configRestore)
	s.route("GET /api/v1/users", adminOnly, s.users)
	s.route("PUT /api/v1/users/{name}", adminOnly.with("user.save"), s.userPut)
	s.route("DELETE /api/v1/users/{name}", adminOnly.with("user.delete"), s.userDelete)
	s.route("POST /api/v1/users/{name}/tokens", adminOnly.with("token.create"), s.tokenCreate)
	s.route("DELETE /api/v1/users/{name}/tokens/{id}", adminOnly.with("token.delete"), s.tokenDelete)
	s.route("GET /api/v1/audit", adminOnly, s.audit)
	s.route("GET /api/v1/notifications", adminOnly, s.notifications)
	s.route("POST /api/v1/notifications/test", adminOnly.with("notification.test"), s.notificationTest)
	s.route("GET /api/v1/system", readInfra, s.system)

	if s.ui != nil {
		m.Handle("/", spaHandler(s.ui))
	}
}

// ------------------------------------------------------------------ auth

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	id, u, err := s.app.Users.Login(req.Username, req.Password, clientIP(r))
	s.app.Audit.Record(audit.Entry{User: req.Username, Client: clientIP(r), Action: "auth.login", OK: err == nil, Error: errString(err)})
	if err != nil {
		code := http.StatusUnauthorized
		if errors.Is(err, auth.ErrBlocked) {
			code = http.StatusTooManyRequests
		}
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
	})
	writeJSON(w, http.StatusOK, s.meView(u))
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.app.Users.Logout(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type meResponse struct {
	auth.User
	CanOperate bool `json:"can_operate"`
	CanAdmin   bool `json:"can_admin"`
	Demo       bool `json:"demo"`
}

func (s *Server) meView(u *auth.User) meResponse {
	return meResponse{User: *u, CanOperate: u.Can(auth.RoleOperator), CanAdmin: u.Can(auth.RoleAdmin) && !u.Scoped(), Demo: s.app.Sim != nil}
}

func (s *Server) me(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	return s.meView(u), nil
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	var req struct {
		Current string `json:"current"`
		Next    string `json:"next"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	if err := s.app.Users.ChangePassword(u.Username, req.Current, req.Next); err != nil {
		return nil, err
	}
	return map[string]string{"status": "ok"}, nil
}
