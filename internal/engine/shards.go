package engine

import (
	"encoding/binary"
	"net/netip"
	"runtime"
	"sync/atomic"

	"github.com/SimsekBerk/DDOS-Detection/internal/rules"
)

// seriesTable partitions the series into shards so ingest and evaluation
// run on several cores without locks. All host and carpet-prefix series of
// one carpet prefix (default /24) live in the same shard, so a record touches
// a single shard for them; object-scope series are spread by object id.
type seriesTable struct {
	shards []*seriesShard
	count  atomic.Int64
}

type seriesShard struct {
	m map[seriesKey]*series
	// per-rule cache of the last series touched (records of one flow burst
	// usually hit the same target back to back)
	lastKey    [rules.MaxRules]seriesKey
	lastSeries [rules.MaxRules]*series
}

// maxShards bounds parallelism; more shards than cores only adds overhead.
const maxShards = 16

func defaultShards() int {
	return max(1, min(runtime.GOMAXPROCS(0), maxShards))
}

func newSeriesTable(n int) *seriesTable {
	t := &seriesTable{shards: make([]*seriesShard, n)}
	for i := range t.shards {
		t.shards[i] = &seriesShard{m: map[seriesKey]*series{}}
	}
	return t
}

func (t *seriesTable) len() int { return int(t.count.Load()) }

// each visits every series (callers run on the engine goroutine).
func (t *seriesTable) each(fn func(seriesKey, *series)) {
	for _, sh := range t.shards {
		for k, s := range sh.m {
			fn(k, s)
		}
	}
}

func (t *seriesTable) remove(key seriesKey, s *series) {
	if _, ok := t.shards[s.shard].m[key]; ok {
		delete(t.shards[s.shard].m, key)
		t.count.Add(-1)
	}
}

func (t *seriesTable) resetCache() {
	for _, sh := range t.shards {
		sh.lastSeries = [rules.MaxRules]*series{}
	}
}

// rebuild re-keys every series after the rules or objects changed: remap
// returns the new key or false to drop the series; shardOf places it.
func (t *seriesTable) rebuild(remap func(seriesKey, *series) (seriesKey, bool), shardOf func(seriesKey) int) {
	old := t.shards
	t.shards = make([]*seriesShard, len(old))
	for i := range t.shards {
		t.shards[i] = &seriesShard{m: map[seriesKey]*series{}}
	}
	var n int64
	for _, sh := range old {
		for k, s := range sh.m {
			nk, ok := remap(k, s)
			if !ok {
				continue
			}
			s.shard = uint16(shardOf(nk))
			t.shards[s.shard].m[nk] = s
			n++
		}
	}
	t.count.Store(n)
}

// prefixHash spreads carpet prefixes over shards.
func prefixHash(p netip.Prefix) uint32 {
	a := p.Addr()
	var x uint64
	if a.Is4() {
		b := a.As4()
		x = uint64(binary.BigEndian.Uint32(b[:]))
	} else {
		b := a.As16()
		x = binary.BigEndian.Uint64(b[:8]) ^ binary.BigEndian.Uint64(b[8:])
	}
	x = (x ^ uint64(p.Bits())) * 0x9E3779B97F4A7C15
	return uint32(x >> 32)
}

// shardOfKey returns the shard a series belongs to under the object table t.
func shardOfKey(key seriesKey, t *objectTable, n int) int {
	if n == 1 {
		return 0
	}
	if key.obj < 0 {
		return 0
	}
	if !key.pfx.IsValid() || int(key.obj) >= len(t.objects) {
		return int(key.obj) % n // object scope
	}
	return int(prefixHash(t.objects[key.obj].carpetPrefix(key.pfx.Addr())) % uint32(n))
}
