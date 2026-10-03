package auth

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func open(t *testing.T, pass string) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir, time.Hour, "admin", pass, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func TestBootstrapAndLogin(t *testing.T) {
	s, dir := open(t, "")
	b, err := os.ReadFile(filepath.Join(dir, "initial-admin-password.txt"))
	if err != nil {
		t.Fatal("initial password file missing")
	}
	pass := strings.TrimSpace(strings.SplitN(string(b), ":", 2)[1])
	id, u, err := s.Login("admin", pass, "c1")
	if err != nil || u.Role != RoleAdmin || u.PasswordHash != "" {
		t.Fatalf("login failed: %v %+v", err, u)
	}
	if got, ok := s.Session(id); !ok || got.Username != "admin" {
		t.Fatal("session lookup failed")
	}
	s.Logout(id)
	if _, ok := s.Session(id); ok {
		t.Fatal("session still valid after logout")
	}
	fi, _ := os.Stat(filepath.Join(dir, "users.json"))
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("users.json mode %v", fi.Mode().Perm())
	}
}

func TestBruteForceBlock(t *testing.T) {
	s, _ := open(t, "correct-horse-battery")
	for i := 0; i < 10; i++ {
		if _, _, err := s.Login("admin", "wrong", "attacker"); err != ErrInvalid {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, _, err := s.Login("admin", "correct-horse-battery", "attacker"); err != ErrBlocked {
		t.Fatalf("expected block, got %v", err)
	}
	if _, _, err := s.Login("admin", "correct-horse-battery", "other-client"); err != nil {
		t.Fatalf("other client should not be blocked: %v", err)
	}
}

func TestRolesScopeTokensAndLastAdmin(t *testing.T) {
	s, _ := open(t, "correct-horse-battery")
	if err := s.Upsert(UserInput{Username: "noc", Role: RoleOperator, Password: "short"}); err == nil {
		t.Fatal("short password accepted")
	}
	if err := s.Upsert(UserInput{Username: "musteri-a", Role: RoleViewer, Objects: []string{"Musteri-A"}, Password: "long-enough-pw"}); err != nil {
		t.Fatal(err)
	}
	_, u, err := s.Login("musteri-a", "long-enough-pw", "c")
	if err != nil || !u.Scoped() || !u.AllowsObject("Musteri-A") || u.AllowsObject("Musteri-B") || u.Can(RoleOperator) {
		t.Fatalf("scope/role wrong: %+v %v", u, err)
	}
	raw, err := s.CreateToken("musteri-a", "grafana")
	if err != nil {
		t.Fatal(err)
	}
	if tu, ok := s.TokenUser(raw); !ok || tu.Username != "musteri-a" {
		t.Fatal("token auth failed")
	}
	if _, ok := s.TokenUser(raw + "x"); ok {
		t.Fatal("bad token accepted")
	}
	if err := s.Delete("admin"); err == nil {
		t.Fatal("last admin deleted")
	}
	if err := s.Upsert(UserInput{Username: "admin", Role: RoleViewer}); err == nil {
		t.Fatal("last admin demoted")
	}
}

func TestResetAdmin(t *testing.T) {
	s, dir := open(t, "correct-horse-battery")
	id, _, err := s.Login("admin", "correct-horse-battery", "c")
	if err != nil {
		t.Fatal(err)
	}
	pass, err := s.ResetAdmin("admin")
	if err != nil || len(pass) < MinPasswordLen {
		t.Fatalf("reset: %q %v", pass, err)
	}
	if _, ok := s.Session(id); ok {
		t.Fatal("old session survived password reset")
	}
	if _, _, err := s.Login("admin", "correct-horse-battery", "c2"); err == nil {
		t.Fatal("old password still valid")
	}
	// The new password must survive a reload from disk.
	s2, err := Open(dir, time.Hour, "", "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if _, u, err := s2.Login("admin", pass, "c3"); err != nil || u.Role != RoleAdmin {
		t.Fatalf("login with reset password: %v", err)
	}
	if _, err := s.ResetAdmin("../x"); err == nil {
		t.Fatal("invalid username accepted")
	}
}
