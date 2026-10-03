// Package collector receives flow telemetry over UDP, decodes it and hands
// normalized records to the engine. It also tracks per-exporter health.
package collector

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/config"
	"github.com/SimsekBerk/DDOS-Detection/internal/decoder"
	"github.com/SimsekBerk/DDOS-Detection/internal/flow"
)

// ExporterStats describes one telemetry source.
type ExporterStats struct {
	Address          string            `json:"address"`
	Name             string            `json:"name"`
	Protocols        map[string]uint64 `json:"protocols"`
	Datagrams        uint64            `json:"datagrams"`
	Records          uint64            `json:"records"`
	Errors           uint64            `json:"errors"`
	MissingTemplate  uint64            `json:"missing_template"`
	LostEstimate     uint64            `json:"lost_estimate"`
	FirstSeen        int64             `json:"first_seen"`
	LastSeen         int64             `json:"last_seen"`
	SamplingReported uint32            `json:"sampling_reported"`
	SamplingOverride uint32            `json:"sampling_override"`
	SamplingLearned  uint32            `json:"sampling_learned"`
	Templates        int               `json:"templates"`
	RecordsPerSec    float64           `json:"records_per_sec"`
	LastError        string            `json:"last_error,omitempty"`
	Listener         string            `json:"listener"`

	seq       map[uint64]uint32
	lastCount uint64
}

// Sink receives decoded record batches. It returns false if the batch was dropped.
type Sink func([]flow.Record) bool

// Classifier annotates records (object, direction, matching rules) in the
// worker goroutines, off the engine's critical path. May be nil.
type Classifier func([]flow.Record)

type datagram struct {
	exp      netip.Addr
	data     []byte
	listener string
}

type Collector struct {
	cfg       *config.Config // restart-only settings (listen, workers, buffers)
	dec       *decoder.Decoder
	sink      Sink
	classify  Classifier
	log       *slog.Logger
	workers   []chan datagram
	dropped   atomic.Uint64
	rejected  atomic.Uint64 // datagrams from exporters outside the allowlist
	policy    atomic.Pointer[policy]
	forward   []net.Conn
	overrides map[netip.Addr]config.ExporterConfig

	mu        sync.Mutex
	exporters map[netip.Addr]*ExporterStats
	listening []string
}

func New(cfg *config.Config, sink Sink, classify Classifier, log *slog.Logger) *Collector {
	c := &Collector{
		cfg: cfg, dec: decoder.New(), sink: sink, classify: classify, log: log,
		exporters: map[netip.Addr]*ExporterStats{},
	}
	c.Update(cfg)
	for _, f := range cfg.Collector.Forward {
		conn, err := net.Dial("udp", f)
		if err != nil {
			log.Warn("flow forward target unavailable", "target", f, "err", err)
			continue
		}
		c.forward = append(c.forward, conn)
	}
	return c
}

// policy holds the hot-reloadable exporter settings.
type policy struct {
	overrides map[netip.Addr]config.ExporterConfig
	allow     []netip.Prefix
	defRate   uint32
}

// Update applies exporter overrides and the allowlist at runtime.
func (c *Collector) Update(cfg *config.Config) {
	p := &policy{overrides: map[netip.Addr]config.ExporterConfig{}, allow: cfg.Collector.AllowParsed, defRate: cfg.Collector.DefaultSamplingRate}
	for _, e := range cfg.Exporters {
		if a, err := netip.ParseAddr(e.Address); err == nil {
			p.overrides[a.Unmap()] = e
		}
	}
	c.policy.Store(p)
	c.mu.Lock()
	for a, st := range c.exporters {
		o := p.overrides[a]
		st.Name, st.SamplingOverride = o.Name, o.SamplingRate
	}
	c.mu.Unlock()
}

// maxExporters bounds per-exporter state (protection against spoofed sources).
const maxExporters = 4096

func (c *Collector) allowed(a netip.Addr) bool {
	allow := c.policy.Load().allow
	if len(allow) == 0 {
		return true
	}
	for _, p := range allow {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Rejected returns datagrams dropped by the exporter allowlist or limits.
func (c *Collector) Rejected() uint64 { return c.rejected.Load() }

// Run starts all listeners and blocks until ctx is done.
func (c *Collector) Run(ctx context.Context) error {
	var conns []*net.UDPConn
	for _, addr := range c.cfg.Collector.Listen {
		ua, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return err
		}
		conn, err := net.ListenUDP("udp", ua)
		if err != nil {
			for _, c := range conns {
				c.Close()
			}
			return err
		}
		if err := conn.SetReadBuffer(c.cfg.Collector.ReadBufferBytes); err != nil {
			c.log.Warn("could not set UDP read buffer", "addr", addr, "err", err)
		}
		conns = append(conns, conn)
		c.mu.Lock()
		c.listening = append(c.listening, conn.LocalAddr().String())
		c.mu.Unlock()
		c.log.Info("flow collector listening", "addr", conn.LocalAddr().String())
	}
	// Decode/classify workers. Datagrams of one exporter always go to the same
	// worker so per-exporter ordering (sequence/loss accounting, templates)
	// is preserved while different routers are processed in parallel.
	n := c.cfg.Collector.Workers
	c.workers = make([]chan datagram, n)
	var wwg sync.WaitGroup
	for i := range c.workers {
		ch := make(chan datagram, 16384)
		c.workers[i] = ch
		wwg.Add(1)
		go func() {
			defer wwg.Done()
			c.worker(ch)
		}()
	}
	var wg sync.WaitGroup
	for _, conn := range conns {
		wg.Add(1)
		go func(conn *net.UDPConn) {
			defer wg.Done()
			c.readLoop(conn)
		}(conn)
	}
	go c.rateLoop(ctx)
	<-ctx.Done()
	for _, conn := range conns {
		conn.Close()
	}
	wg.Wait()
	for _, ch := range c.workers {
		close(ch)
	}
	wwg.Wait()
	return nil
}

// coalesce: records are handed to the engine in batches of up to this many
// records (or every flushEvery) to amortize channel and lock costs.
const (
	coalesce   = 1024
	flushEvery = 20 * time.Millisecond
)

func (c *Collector) worker(ch chan datagram) {
	var batch []flow.Record
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if c.classify != nil {
			c.classify(batch)
		}
		c.sink(batch)
		batch = nil
	}
	t := time.NewTicker(flushEvery)
	defer t.Stop()
	for {
		select {
		case d, ok := <-ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, c.handle(d.exp, d.data, d.listener)...)
			if len(batch) >= coalesce {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

// Dropped returns datagrams dropped because a worker queue was full.
func (c *Collector) Dropped() uint64 { return c.dropped.Load() }

// Listening returns the bound listener addresses.
func (c *Collector) Listening() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string{}, c.listening...)
}

func (c *Collector) readLoop(conn *net.UDPConn) {
	buf := make([]byte, 65535)
	local := conn.LocalAddr().String()
	for {
		n, src, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		exp := src.Addr().Unmap()
		if !c.allowed(exp) {
			c.rejected.Add(1)
			continue
		}
		for _, f := range c.forward {
			_, _ = f.Write(buf[:n]) // best effort replication
		}
		d := datagram{exp: exp, data: append([]byte(nil), buf[:n]...), listener: local}
		w := c.workers[addrHash(exp)%uint32(len(c.workers))]
		select {
		case w <- d:
		default:
			c.dropped.Add(1)
		}
	}
}

// handle decodes one datagram, updates exporter statistics and returns the
// sampling-normalized records.
func (c *Collector) handle(exp netip.Addr, data []byte, listener string) []flow.Record {
	now := time.Now().Unix()
	res, err := c.dec.Decode(exp, data, now)

	c.mu.Lock()
	st := c.exporters[exp]
	if st == nil && len(c.exporters) >= maxExporters {
		c.mu.Unlock()
		c.rejected.Add(1)
		return nil
	}
	if st == nil {
		st = &ExporterStats{Address: exp.String(), Protocols: map[string]uint64{}, FirstSeen: now, seq: map[uint64]uint32{}, Listener: listener}
		if o, ok := c.policy.Load().overrides[exp]; ok {
			st.Name = o.Name
			st.SamplingOverride = o.SamplingRate
		}
		c.exporters[exp] = st
	}
	st.Datagrams++
	st.LastSeen = now
	if err != nil {
		st.Errors++
		st.LastError = err.Error()
		c.mu.Unlock()
		return nil
	}
	st.Protocols[res.Source.String()]++
	st.Records += uint64(len(res.Records))
	st.MissingTemplate += uint64(res.MissingTemplate)
	if exp, ok := st.seq[res.SeqKey]; ok && res.Seq != exp {
		if gap := res.Seq - exp; gap < 1<<20 {
			st.LostEstimate += uint64(gap)
		}
	}
	st.seq[res.SeqKey] = res.SeqNext
	override := st.SamplingOverride
	c.mu.Unlock()

	if len(res.Records) == 0 {
		return nil
	}
	reported := uint32(0)
	for i := range res.Records {
		r := &res.Records[i]
		if r.SamplingRate > reported {
			reported = r.SamplingRate
		}
		switch {
		case override > 0:
			r.SamplingRate = override
		case r.SamplingRate == 0:
			r.SamplingRate = c.policy.Load().defRate
		}
	}
	if reported > 0 {
		c.mu.Lock()
		st.SamplingReported = reported
		c.mu.Unlock()
	}
	return res.Records
}

func addrHash(a netip.Addr) uint32 {
	b := a.As16()
	h := uint32(2166136261)
	for _, x := range b {
		h = (h ^ uint32(x)) * 16777619
	}
	return h
}

func (c *Collector) rateLoop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.mu.Lock()
			for _, st := range c.exporters {
				d := float64(st.Records - st.lastCount)
				st.RecordsPerSec = 0.7*st.RecordsPerSec + 0.3*d
				st.lastCount = st.Records
			}
			c.mu.Unlock()
		}
	}
}

// Exporters returns a snapshot of exporter statistics.
func (c *Collector) Exporters() []ExporterStats {
	c.mu.Lock()
	addrs := make([]netip.Addr, 0, len(c.exporters))
	for a := range c.exporters {
		addrs = append(addrs, a)
	}
	c.mu.Unlock()
	out := make([]ExporterStats, 0, len(addrs))
	for _, a := range addrs {
		templates := c.dec.TemplateCount(a)
		learned := c.dec.LearnedSampling(a)
		c.mu.Lock()
		st := *c.exporters[a]
		st.Protocols = map[string]uint64{}
		for k, v := range c.exporters[a].Protocols {
			st.Protocols[k] = v
		}
		c.mu.Unlock()
		st.seq = nil
		st.Templates = templates
		st.SamplingLearned = learned
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Records > out[j].Records })
	return out
}
