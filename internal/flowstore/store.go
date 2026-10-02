// Package flowstore keeps the most recent flow records in a ring buffer and
// answers forensic queries (top-N, breakdowns, samples) over them.
package flowstore

import (
	"sync"

	"github.com/SimsekBerk/DDOS-Detection/internal/flow"
)

// Store is a fixed-size ring buffer of normalized flow records.
type Store struct {
	mu    sync.RWMutex
	buf   []flow.Record
	next  int
	full  bool
	total uint64
}

func New(size int) *Store {
	if size < 1000 {
		size = 1000
	}
	return &Store{buf: make([]flow.Record, size)}
}

// Append adds records, overwriting the oldest when full.
func (s *Store) Append(rs []flow.Record) {
	s.mu.Lock()
	for i := range rs {
		s.buf[s.next] = rs[i]
		s.next++
		if s.next == len(s.buf) {
			s.next = 0
			s.full = true
		}
	}
	s.total += uint64(len(rs))
	s.mu.Unlock()
}

// Len returns the number of records currently stored and the capacity.
func (s *Store) Len() (int, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.full {
		return len(s.buf), len(s.buf)
	}
	return s.next, len(s.buf)
}

// OldestUnix returns the receive time of the oldest stored record.
func (s *Store) OldestUnix() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.full {
		return s.buf[s.next].ReceivedUnix
	}
	if s.next == 0 {
		return 0
	}
	return s.buf[0].ReceivedUnix
}

// Scan visits records newest-first whose receive time is >= since.
// fn returns false to stop early. fn must not retain the pointer.
func (s *Store) Scan(since int64, fn func(*flow.Record) bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := s.next
	if !s.full && n == 0 {
		return
	}
	count := len(s.buf)
	if !s.full {
		count = n
	}
	i := n
	for k := 0; k < count; k++ {
		i--
		if i < 0 {
			i = len(s.buf) - 1
		}
		r := &s.buf[i]
		if r.ReceivedUnix < since {
			return
		}
		if !fn(r) {
			return
		}
	}
}
