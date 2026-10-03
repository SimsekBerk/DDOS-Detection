package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/decoder"
	"github.com/SimsekBerk/DDOS-Detection/internal/flow"
	"github.com/SimsekBerk/DDOS-Detection/internal/sim"
)

// Options configure a probe.
type Options struct {
	Interface string        // e.g. en0
	Collector string        // host:port of the IPFIX collector
	Active    time.Duration // export long-lived flows at least this often
	Inactive  time.Duration // export flows idle for this long
	MaxFlows  int           // flush the cache when it holds this many flows
	Snaplen   int           // captured bytes per packet (headers only)
	// Promisc also captures frames not addressed to this host. On switched
	// and Wi-Fi networks this adds little; only enable it on a mirror (SPAN)
	// port you are authorized to monitor.
	Promisc bool
}

func (o *Options) defaults() {
	if o.Active <= 0 {
		o.Active = 10 * time.Second
	}
	if o.Inactive <= 0 {
		o.Inactive = 5 * time.Second
	}
	if o.MaxFlows <= 0 {
		o.MaxFlows = 200_000
	}
	if o.Snaplen <= 0 {
		o.Snaplen = 128
	}
}

// Stats are cumulative counters.
type Stats struct {
	Packets, Bytes, Ignored uint64
	Flows, Datagrams        uint64
	Open                    int
	KernelDrops             uint64
}

// Run captures until ctx is done. Open flows are exported before returning.
func Run(ctx context.Context, o Options, log *slog.Logger) error {
	o.defaults()
	sensor, err := openCapture(o.Interface, o.Snaplen, o.Promisc)
	if err != nil {
		return err
	}
	defer sensor.close()
	ua, err := net.ResolveUDPAddr("udp", o.Collector)
	if err != nil {
		return fmt.Errorf("collector: %w", err)
	}
	conn, err := net.DialUDP("udp", nil, ua)
	if err != nil {
		return fmt.Errorf("collector: %w", err)
	}
	defer conn.Close()
	coll := ua.AddrPort()

	enc := sim.NewEncoder("ipfix", 1)
	cache := NewCache(o.Active, o.Inactive, o.MaxFlows)
	var st Stats
	export := func(specs []sim.Spec, now time.Time) {
		if len(specs) == 0 {
			return
		}
		st.Flows += uint64(len(specs))
		for _, d := range enc.Encode(specs, now) {
			if _, err := conn.Write(d); err != nil {
				log.Warn("export failed", "err", err)
				continue
			}
			st.Datagrams++
		}
	}
	log.Info("probe started", "interface", o.Interface, "collector", o.Collector, "active", o.Active, "inactive", o.Inactive, "promisc", o.Promisc)

	lastExpire, lastLog := time.Now(), time.Now()
	onFrame := func(frame []byte, origLen int, ts time.Time) {
		var r flow.Record
		if !decoder.ParseEthernet(&r, frame) || !r.Src.IsValid() || !r.Dst.IsValid() {
			st.Ignored++ // ARP, LLDP and other non-IP frames
			return
		}
		// Never account the probe's own exports (remote collector case).
		if r.Protocol == flow.ProtoUDP && r.Dst.Unmap() == coll.Addr().Unmap() && r.DstPort == coll.Port() {
			return
		}
		size := origLen - l2Len(frame)
		if size < 20 {
			size = 20
		}
		st.Packets++
		st.Bytes += uint64(size)
		if !cache.Add(&r, size, ts) {
			export(cache.Expire(ts, true), ts) // cache full: flush everything
			cache.Add(&r, size, ts)
		}
	}
	for ctx.Err() == nil {
		if err := sensor.read(onFrame); err != nil {
			return fmt.Errorf("capture: %w", err)
		}
		now := time.Now()
		if now.Sub(lastExpire) >= time.Second {
			lastExpire = now
			export(cache.Expire(now, false), now)
		}
		if now.Sub(lastLog) >= time.Minute {
			lastLog = now
			st.Open, st.KernelDrops = cache.Len(), sensor.drops()
			log.Info("probe stats", "packets", st.Packets, "bytes", st.Bytes, "flows_exported", st.Flows,
				"datagrams", st.Datagrams, "open_flows", st.Open, "ignored_frames", st.Ignored, "kernel_drops", st.KernelDrops)
		}
	}
	export(cache.Expire(time.Now(), true), time.Now())
	return nil
}

// l2Len is the Ethernet header length including VLAN tags.
func l2Len(frame []byte) int {
	n := 14
	for len(frame) >= n && n < 30 {
		t := binary.BigEndian.Uint16(frame[n-2 : n])
		if t != 0x8100 && t != 0x88A8 && t != 0x9100 {
			break
		}
		n += 4
	}
	return n
}
