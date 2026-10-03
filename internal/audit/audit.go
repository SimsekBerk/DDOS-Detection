// Package audit records who changed what (append-only JSON lines).
package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Entry is one audited action.
type Entry struct {
	T      int64  `json:"t"`
	User   string `json:"user"`
	Role   string `json:"role"`
	Client string `json:"client"`
	Action string `json:"action"` // e.g. mitigation.approve, config.update, user.create
	Target string `json:"target,omitempty"`
	Detail string `json:"detail,omitempty"`
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
}

const keep = 5000

// Log appends entries to <dataDir>/audit.jsonl and keeps the newest in memory.
type Log struct {
	mu   sync.Mutex
	f    *os.File
	ring []Entry
}

// Open opens (or creates) the audit log.
func Open(dataDir string) (*Log, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(dataDir, "audit.jsonl")
	l := &Log{}
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			var e Entry
			if json.Unmarshal(sc.Bytes(), &e) == nil {
				l.ring = append(l.ring, e)
				if len(l.ring) > keep {
					l.ring = l.ring[len(l.ring)-keep:]
				}
			}
		}
		f.Close()
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	l.f = f
	return l, nil
}

// Record appends an entry.
func (l *Log) Record(e Entry) {
	if e.T == 0 {
		e.T = time.Now().Unix()
	}
	b, _ := json.Marshal(e)
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.f.Write(append(b, '\n'))
	l.ring = append(l.ring, e)
	if len(l.ring) > keep {
		l.ring = l.ring[len(l.ring)-keep:]
	}
}

// Query returns newest-first entries filtered by user and action prefix.
func (l *Log) Query(user, action string, limit int) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	if limit <= 0 || limit > keep {
		limit = 200
	}
	out := []Entry{}
	for i := len(l.ring) - 1; i >= 0 && len(out) < limit; i-- {
		e := l.ring[i]
		if user != "" && e.User != user {
			continue
		}
		if action != "" && !strings.HasPrefix(e.Action, action) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Close flushes the file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}
