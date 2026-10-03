// Package auth manages users, roles, sessions and API tokens.
//
// Roles: viewer (read-only), operator (+ mitigation actions, analyst runs,
// simulator), admin (+ configuration, rules, users). A user may be scoped to
// a set of protected objects (multi-tenant / MSSP customers).
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/SimsekBerk/DDOS-Detection/internal/store"
)

const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

var roleRank = map[string]int{RoleViewer: 1, RoleOperator: 2, RoleAdmin: 3}

// ValidRole reports whether r is a known role.
func ValidRole(r string) bool { _, ok := roleRank[r]; return ok }

// Token is an API token (only its hash is stored).
type Token struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Prefix    string `json:"prefix"`
	Hash      string `json:"hash,omitempty"`
	CreatedAt int64  `json:"created_at"`
	LastUsed  int64  `json:"last_used,omitempty"`
}

// User is a stored account.
type User struct {
	Username     string   `json:"username"`
	Role         string   `json:"role"`
	Objects      []string `json:"objects"` // tenant scope; empty = all objects
	PasswordHash string   `json:"password_hash,omitempty"`
	Disabled     bool     `json:"disabled"`
	CreatedAt    int64    `json:"created_at"`
	LastLogin    int64    `json:"last_login,omitempty"`
	Tokens       []Token  `json:"tokens"`
}

// Can reports whether the user has at least the given role.
func (u *User) Can(role string) bool { return roleRank[u.Role] >= roleRank[role] }

// Scoped reports whether the user is restricted to some objects.
func (u *User) Scoped() bool { return len(u.Objects) > 0 }

// AllowsObject reports whether the user may see an object.
func (u *User) AllowsObject(name string) bool {
	if !u.Scoped() {
		return true
	}
	for _, o := range u.Objects {
		if o == name {
			return true
		}
	}
	return false
}

// Public returns a copy without secrets.
func (u *User) Public() User {
	c := *u
	c.PasswordHash = ""
	c.Objects = append([]string{}, u.Objects...)
	c.Tokens = make([]Token, len(u.Tokens))
	for i, t := range u.Tokens {
		t.Hash = ""
		c.Tokens[i] = t
	}
	return c
}

type session struct {
	user    string
	expires int64
}

type failure struct {
	count int
	first int64
	until int64
}

// Store holds users (persisted) and sessions (in memory).
type Store struct {
	mu       sync.Mutex
	path     string
	users    map[string]*User
	sessions map[string]*session
	fails    map[string]*failure
	ttl      time.Duration
	log      *slog.Logger
}

var (
	dummyOnce sync.Once
	dummy     []byte
)

// dummyHash is compared for unknown users so timing does not reveal them.
func dummyHash() []byte {
	dummyOnce.Do(func() { dummy, _ = bcrypt.GenerateFromPassword([]byte(randomString(16)), bcrypt.DefaultCost) })
	return dummy
}

var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9._@-]{2,64}$`)

// MinPasswordLen is enforced for passwords set through the API.
const MinPasswordLen = 10

// Open loads the user store. If it is empty, an admin account is created
// from the bootstrap credentials or, if none, a random password that is
// written to <dataDir>/initial-admin-password.txt (0600).
func Open(dataDir string, ttl time.Duration, bootUser, bootPass string, log *slog.Logger) (*Store, error) {
	s := &Store{path: filepath.Join(dataDir, "users.json"), users: map[string]*User{}, sessions: map[string]*session{}, fails: map[string]*failure{}, ttl: ttl, log: log}
	var list []*User
	if err := store.Load(s.path, &list); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("users: %w", err)
	}
	for _, u := range list {
		s.users[u.Username] = u
	}
	if len(s.users) == 0 {
		if bootUser == "" {
			bootUser = "admin"
		}
		pass := bootPass
		if pass == "" {
			pass = randomString(18)
			file := filepath.Join(dataDir, "initial-admin-password.txt")
			if err := os.MkdirAll(dataDir, 0o755); err == nil {
				_ = os.WriteFile(file, []byte(bootUser+":"+pass+"\n"), 0o600)
			}
			log.Warn("created initial admin account; password written to file", "user", bootUser, "file", file)
		}
		h, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		s.users[bootUser] = &User{Username: bootUser, Role: RoleAdmin, PasswordHash: string(h), CreatedAt: time.Now().Unix(), Tokens: []Token{}}
		if err := s.saveLocked(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// ResetAdmin sets a new random password for username, creating the account
// if needed, and makes it an enabled, unrestricted admin. It backs the
// offline recovery command (ddosd -reset-admin); run it while ddosd is stopped.
func (s *Store) ResetAdmin(username string) (string, error) {
	if !usernameRe.MatchString(username) {
		return "", errors.New("kullanıcı adı 2-64 karakter olmalı (harf, rakam, . _ @ -)")
	}
	pass := randomString(18)
	h, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.users[username]
	if u == nil {
		u = &User{Username: username, CreatedAt: time.Now().Unix(), Tokens: []Token{}}
		s.users[username] = u
	}
	u.Role, u.Objects, u.Disabled, u.PasswordHash = RoleAdmin, nil, false, string(h)
	for id, ss := range s.sessions {
		if ss.user == username {
			delete(s.sessions, id)
		}
	}
	return pass, s.saveLocked()
}

// SetTTL updates the session lifetime.
func (s *Store) SetTTL(d time.Duration) {
	s.mu.Lock()
	s.ttl = d
	s.mu.Unlock()
}

func (s *Store) saveLocked() error {
	list := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		list = append(list, u)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Username < list[j].Username })
	if err := store.Save(s.path, list); err != nil {
		return err
	}
	return os.Chmod(s.path, 0o600)
}

func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)[:n]
}

func hashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

var (
	ErrInvalid = errors.New("kullanıcı adı veya parola hatalı")
	ErrBlocked = errors.New("çok fazla başarısız deneme; 10 dakika sonra tekrar deneyin")
)

// Login verifies credentials and returns a new session id. Repeated
// failures from one client are blocked for 10 minutes.
func (s *Store) Login(username, password, client string) (string, *User, error) {
	now := time.Now().Unix()
	s.mu.Lock()
	f := s.fails[client]
	if f != nil && f.until > now {
		s.mu.Unlock()
		return "", nil, ErrBlocked
	}
	u := s.users[username]
	hash := ""
	if u != nil && !u.Disabled {
		hash = u.PasswordHash
	}
	s.mu.Unlock()
	if hash == "" {
		// Constant work for unknown users.
		_ = bcrypt.CompareHashAndPassword(dummyHash(), []byte(password))
		s.fail(client, now)
		return "", nil, ErrInvalid
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		s.fail(client, now)
		return "", nil, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.fails, client)
	id := randomString(43)
	s.sessions[hashToken(id)] = &session{user: username, expires: now + int64(s.ttl.Seconds())}
	u.LastLogin = now
	_ = s.saveLocked()
	c := u.Public()
	return id, &c, nil
}

func (s *Store) fail(client string, now int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.fails[client]
	if f == nil || now-f.first > 600 {
		f = &failure{first: now}
		s.fails[client] = f
	}
	f.count++
	if f.count >= 10 {
		f.until = now + 600
	}
	if len(s.fails) > 10000 {
		s.fails = map[string]*failure{}
	}
}

// Session resolves a session id (sliding expiration).
func (s *Store) Session(id string) (*User, bool) {
	if id == "" {
		return nil, false
	}
	now := time.Now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	k := hashToken(id)
	ss := s.sessions[k]
	if ss == nil || ss.expires < now {
		delete(s.sessions, k)
		return nil, false
	}
	u := s.users[ss.user]
	if u == nil || u.Disabled {
		delete(s.sessions, k)
		return nil, false
	}
	ss.expires = now + int64(s.ttl.Seconds())
	c := u.Public()
	return &c, true
}

// Logout ends a session.
func (s *Store) Logout(id string) {
	s.mu.Lock()
	delete(s.sessions, hashToken(id))
	s.mu.Unlock()
}

// TokenUser resolves an API token ("ddosd_...").
func (s *Store) TokenUser(raw string) (*User, bool) {
	if !strings.HasPrefix(raw, "ddosd_") {
		return nil, false
	}
	h := hashToken(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.Disabled {
			continue
		}
		for i := range u.Tokens {
			if subtle.ConstantTimeCompare([]byte(u.Tokens[i].Hash), []byte(h)) == 1 {
				u.Tokens[i].LastUsed = time.Now().Unix()
				c := u.Public()
				return &c, true
			}
		}
	}
	return nil, false
}

// List returns all users without secrets.
func (s *Store) List() []User {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, u.Public())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

// UserInput is an admin create/update request.
type UserInput struct {
	Username string   `json:"username"`
	Role     string   `json:"role"`
	Objects  []string `json:"objects"`
	Password string   `json:"password,omitempty"`
	Disabled bool     `json:"disabled"`
}

func (s *Store) adminsLocked(except string) int {
	n := 0
	for _, u := range s.users {
		if u.Username != except && u.Role == RoleAdmin && !u.Disabled && !u.Scoped() {
			n++
		}
	}
	return n
}

// Upsert creates or updates a user.
func (s *Store) Upsert(in UserInput) error {
	if !usernameRe.MatchString(in.Username) {
		return errors.New("kullanıcı adı 2-64 karakter olmalı (harf, rakam, . _ @ -)")
	}
	if !ValidRole(in.Role) {
		return errors.New("rol viewer, operator veya admin olmalı")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.users[in.Username]
	if u == nil {
		if len(in.Password) < MinPasswordLen {
			return fmt.Errorf("parola en az %d karakter olmalı", MinPasswordLen)
		}
		u = &User{Username: in.Username, CreatedAt: time.Now().Unix(), Tokens: []Token{}}
	}
	demote := u.Role == RoleAdmin && (in.Role != RoleAdmin || in.Disabled || len(in.Objects) > 0)
	if demote && s.adminsLocked(u.Username) == 0 && s.users[in.Username] != nil {
		return errors.New("son yönetici hesabı devre dışı bırakılamaz veya yetkisi düşürülemez")
	}
	if in.Password != "" {
		if len(in.Password) < MinPasswordLen {
			return fmt.Errorf("parola en az %d karakter olmalı", MinPasswordLen)
		}
		h, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		u.PasswordHash = string(h)
		s.dropSessionsLocked(u.Username)
	}
	u.Role, u.Objects, u.Disabled = in.Role, in.Objects, in.Disabled
	if u.Disabled {
		s.dropSessionsLocked(u.Username)
	}
	s.users[u.Username] = u
	return s.saveLocked()
}

func (s *Store) dropSessionsLocked(user string) {
	for k, ss := range s.sessions {
		if ss.user == user {
			delete(s.sessions, k)
		}
	}
}

// Delete removes a user (never the last unscoped admin).
func (s *Store) Delete(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.users[username]
	if u == nil {
		return errors.New("kullanıcı bulunamadı")
	}
	if u.Role == RoleAdmin && s.adminsLocked(username) == 0 {
		return errors.New("son yönetici hesabı silinemez")
	}
	delete(s.users, username)
	s.dropSessionsLocked(username)
	return s.saveLocked()
}

// ChangePassword lets a user change their own password.
func (s *Store) ChangePassword(username, current, next string) error {
	if len(next) < MinPasswordLen {
		return fmt.Errorf("parola en az %d karakter olmalı", MinPasswordLen)
	}
	s.mu.Lock()
	u := s.users[username]
	s.mu.Unlock()
	if u == nil || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(current)) != nil {
		return errors.New("mevcut parola hatalı")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(next), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u.PasswordHash = string(h)
	return s.saveLocked()
}

// CreateToken issues an API token and returns the raw value (shown once).
func (s *Store) CreateToken(username, name string) (string, error) {
	if name == "" || len(name) > 64 {
		return "", errors.New("token adı 1-64 karakter olmalı")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.users[username]
	if u == nil {
		return "", errors.New("kullanıcı bulunamadı")
	}
	if len(u.Tokens) >= 20 {
		return "", errors.New("kullanıcı başına en fazla 20 token")
	}
	raw := "ddosd_" + randomString(40)
	u.Tokens = append(u.Tokens, Token{ID: randomString(8), Name: name, Prefix: raw[:12], Hash: hashToken(raw), CreatedAt: time.Now().Unix()})
	return raw, s.saveLocked()
}

// DeleteToken revokes a token.
func (s *Store) DeleteToken(username, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.users[username]
	if u == nil {
		return errors.New("kullanıcı bulunamadı")
	}
	for i, t := range u.Tokens {
		if t.ID == id {
			u.Tokens = append(u.Tokens[:i], u.Tokens[i+1:]...)
			return s.saveLocked()
		}
	}
	return errors.New("token bulunamadı")
}
