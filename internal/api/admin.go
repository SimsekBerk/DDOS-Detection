package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/SimsekBerk/DDOS-Detection/internal/app"
	"github.com/SimsekBerk/DDOS-Detection/internal/auth"
	"github.com/SimsekBerk/DDOS-Detection/internal/config"
)

// ------------------------------------------------------------- config

type configResponse struct {
	Config          *config.Config `json:"config"`
	RestartPending  []string       `json:"restart_pending"`
	Profiles        []string       `json:"profiles"`
	ConfigPath      string         `json:"config_path"`
	Writable        bool           `json:"writable"`
	NotificationEvt []string       `json:"notification_events"`
}

func (s *Server) configGet(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	var profiles []string
	for name := range s.app.Eng.Rules().Profiles {
		profiles = append(profiles, name)
	}
	return configResponse{
		Config: s.app.Config().Masked(), RestartPending: s.app.RestartPending(), Profiles: profiles, ConfigPath: s.app.Path, Writable: s.app.ConfigWritable(),
		NotificationEvt: []string{"incident.started", "incident.ended", "vector.added", "mitigation.pending", "mitigation.active", "mitigation.withdrawn", "mitigation.failed", "finding.created"},
	}, nil
}

type configPutRequest struct {
	Config  json.RawMessage `json:"config"`
	Comment string          `json:"comment"`
}

type applyResult struct {
	app.ApplyResult
	comment string
}

func (a applyResult) auditDetail() string {
	d := "sürüm " + a.Version
	if a.comment != "" {
		d += ": " + a.comment
	}
	if len(a.RestartRequired) > 0 {
		d += " (yeniden başlatma: " + strings.Join(a.RestartRequired, ", ") + ")"
	}
	return d
}

func (s *Server) decodeConfig(raw json.RawMessage) (*config.Config, error) {
	var next config.Config
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&next); err != nil {
		return nil, errCode(http.StatusBadRequest, "yapılandırma çözümlenemedi: "+err.Error())
	}
	return &next, nil
}

func (s *Server) configPut(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	var req configPutRequest
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	next, err := s.decodeConfig(req.Config)
	if err != nil {
		return nil, err
	}
	res, err := s.app.Apply(next, u.Username, req.Comment)
	if err != nil {
		return nil, err
	}
	return applyResult{res, req.Comment}, nil
}

func (s *Server) configValidate(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	var req configPutRequest
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	next, err := s.decodeConfig(req.Config)
	if err != nil {
		return nil, err
	}
	cur := s.app.Config()
	next.RestoreSecrets(cur)
	if err := next.Normalize(); err != nil {
		return nil, err
	}
	return map[string]any{"valid": true, "restart_required": config.RestartRequired(cur, next)}, nil
}

func (s *Server) configHistory(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	return s.app.History(), nil
}

func (s *Server) configVersion(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	b, err := s.app.Version(r.PathValue("id"))
	if err != nil {
		return nil, notFound("sürüm bulunamadı")
	}
	// Do not leak secrets stored in the YAML file.
	c, err := config.Parse(b)
	if err == nil {
		if masked, err := config.Marshal(c.Masked(), ""); err == nil {
			b = masked
		}
	}
	return map[string]string{"id": r.PathValue("id"), "yaml": string(b)}, nil
}

func (s *Server) configRestore(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	res, err := s.app.Restore(r.PathValue("id"), u.Username)
	if err != nil {
		return nil, err
	}
	return applyResult{res, "geri yükleme"}, nil
}

// ------------------------------------------------------------- users

func (s *Server) users(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	return s.app.Users.List(), nil
}

type userResult struct{ name, detail string }

func (u userResult) auditDetail() string { return u.name + " " + u.detail }

func (s *Server) userPut(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	var in auth.UserInput
	if err := readJSON(r, &in); err != nil {
		return nil, err
	}
	in.Username = r.PathValue("name")
	for _, o := range in.Objects {
		if s.app.Eng.ObjectByName(o) == nil {
			return nil, errCode(http.StatusBadRequest, "bilinmeyen nesne: "+o)
		}
	}
	if err := s.app.Users.Upsert(in); err != nil {
		return nil, err
	}
	detail := "rol=" + in.Role
	if len(in.Objects) > 0 {
		detail += " kapsam=" + strings.Join(in.Objects, ",")
	}
	if in.Password != "" {
		detail += " parola değişti"
	}
	return userResult{in.Username, detail}, nil
}

func (s *Server) userDelete(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	name := r.PathValue("name")
	if name == u.Username {
		return nil, errCode(http.StatusBadRequest, "kendi hesabınızı silemezsiniz")
	}
	if err := s.app.Users.Delete(name); err != nil {
		return nil, err
	}
	return userResult{name, "silindi"}, nil
}

type tokenResult struct {
	Token string `json:"token"`
	Note  string `json:"note"`
	name  string
}

func (t tokenResult) auditDetail() string { return t.name }

func (s *Server) tokenCreate(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	var req struct {
		Name string `json:"name"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	raw, err := s.app.Users.CreateToken(r.PathValue("name"), req.Name)
	if err != nil {
		return nil, err
	}
	return tokenResult{Token: raw, Note: "Token yalnızca bir kez gösterilir; güvenli bir yerde saklayın.", name: r.PathValue("name") + "/" + req.Name}, nil
}

func (s *Server) tokenDelete(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	if err := s.app.Users.DeleteToken(r.PathValue("name"), r.PathValue("id")); err != nil {
		return nil, err
	}
	return map[string]string{"status": "ok"}, nil
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	q := r.URL.Query()
	return s.app.Audit.Query(q.Get("user"), q.Get("action"), qInt(r, "limit", 300)), nil
}

// ------------------------------------------------------------- notifications

func (s *Server) notifications(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	return s.app.Notif.Status(), nil
}

func (s *Server) notificationTest(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	var ch config.ChannelConfig
	if err := readJSON(r, &ch); err != nil {
		return nil, err
	}
	// Unsaved forms carry masked secrets: fill them from the saved channel.
	for _, saved := range s.app.Config().Notifications.Channels {
		if saved.Name == ch.Name {
			tmp := config.Config{Notifications: config.NotificationsConfig{Channels: []config.ChannelConfig{ch}}}
			tmp.RestoreSecrets(&config.Config{Notifications: config.NotificationsConfig{Channels: []config.ChannelConfig{saved}}})
			ch = tmp.Notifications.Channels[0]
		}
	}
	if ch.Name == "" {
		ch.Name = "test"
	}
	if err := config.NormalizeChannel(&ch); err != nil {
		return nil, errCode(http.StatusBadRequest, err.Error())
	}
	if err := s.app.Notif.Test(r.Context(), ch); err != nil {
		return nil, errCode(http.StatusBadGateway, "gönderilemedi: "+err.Error())
	}
	return map[string]string{"status": "ok"}, nil
}
