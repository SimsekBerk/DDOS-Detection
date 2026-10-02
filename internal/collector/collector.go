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

type Collector struct {
	cfg       *config.Config
	dec       *decoder.Decoder
	sink      Sink
	log       *slog.Logger
	overrides map[netip.Addr]config.ExporterConfig

	mu        sync.Mutex
	exporters map[netip.Addr]*ExporterStats
	listening []string
}

func New(cfg *config.Config, sink Sink, log *slog.Logger) *Collector {
	c := &Collector{
		cfg: cfg, dec: decoder.New(), sink: sink, log: log,
		overrides: map[netip.Addr]config.ExporterConfig{},
		exporters: map[netip.Addr]*ExporterStats{},
	}
	for _, e := range cfg.Exporters {
		a, _ := netip.ParseAddr(e.Address)
		c.overrides[a.Unmap()] = e
	}
	return c
}

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
	return nil
}

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
		c.handle(src.Addr().Unmap(), buf[:n], local)
	}
}

func (c *Collector) handle(exp netip.Addr, data []byte, listener string) {
	now := time.Now().Unix()
	res, err := c.dec.Decode(exp, data, now)

	c.mu.Lock()
	st := c.exporters[exp]
	if st == nil {
		st = &ExporterStats{Address: exp.String(), Protocols: map[string]uint64{}, FirstSeen: now, seq: map[uint64]uint32{}, Listener: listener}
		if o, ok := c.overrides[exp]; ok {
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
		return
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
		return
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
			r.SamplingRate = c.cfg.Collector.DefaultSamplingRate
		}
	}
	if reported > 0 {
		c.mu.Lock()
		st.SamplingReported = reported
		c.mu.Unlock()
	}
	c.sink(res.Records)
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
