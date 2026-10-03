package sim

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/flow"
)

// Scenario describes a synthetic attack pattern.
type Scenario struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	TargetKind  string   `json:"target_kind"` // host | prefix | outbound
	DefaultPPS  float64  `json:"default_pps"`
	Sources     int      `json:"sources"`
	Expect      []string `json:"expected_rules"`
	// RelativeRule/RelativeFactor size the attack relative to the target's
	// effective threshold (used by near-miss scenarios); PktSize is the
	// average packet size used for that calculation.
	RelativeRule   string  `json:"relative_rule,omitempty"`
	RelativeFactor float64 `json:"relative_factor,omitempty"`
	PktSize        float64 `json:"packet_size,omitempty"`

	gen func(c *genCtx) []Spec
}

// genCtx is passed to scenario generators each second.
type genCtx struct {
	run     *Run
	pps     float64
	sources []netip.Addr
	target  netip.Addr
	prefix  netip.Prefix
	elapsed float64
}

// Run is an active scenario.
type Run struct {
	ID        string  `json:"id"`
	Scenario  string  `json:"scenario"`
	Name      string  `json:"name"`
	Target    string  `json:"target"`
	PPS       float64 `json:"pps"`
	Sources   int     `json:"sources"`
	StartedAt int64   `json:"started_at"`
	EndsAt    int64   `json:"ends_at"`

	sc      *Scenario
	srcPool []netip.Addr
	target  netip.Addr
	prefix  netip.Prefix
}

// StartRequest starts a scenario.
type StartRequest struct {
	Scenario string  `json:"scenario"`
	Target   string  `json:"target,omitempty"`
	PPS      float64 `json:"pps,omitempty"`
	Duration int     `json:"duration_seconds,omitempty"`
	Sources  int     `json:"sources,omitempty"`
}

// Status of the simulator.
type Status struct {
	Encoder      string  `json:"encoder"`
	SamplingRate uint32  `json:"sampling_rate"`
	Target       string  `json:"collector"`
	Baseline     bool    `json:"baseline"`
	BaselineBPS  float64 `json:"baseline_bps"`
	Datagrams    uint64  `json:"datagrams_sent"`
	Specs        uint64  `json:"specs_generated"`
	Runs         []Run   `json:"runs"`
}

// Simulator generates baseline traffic and attack scenarios.
type Simulator struct {
	mu          sync.Mutex
	enc         Encoder
	rate        uint32
	collector   string
	conn        net.Conn
	protected   []netip.Prefix
	servers     []netip.Addr
	clients     []netip.Addr
	baseline    bool
	baselineBPS float64
	runs        map[string]*Run
	seq         int
	datagrams   uint64
	specs       uint64
}

// New creates a simulator that sends to collector (host:port). An empty
// collector creates an in-process generator (see Generate) without a socket.
func New(encoder string, samplingRate uint32, collector string, protected []netip.Prefix, baselineBPS float64) (*Simulator, error) {
	if len(protected) == 0 {
		return nil, errors.New("sim: no protected prefixes")
	}
	var conn net.Conn
	if collector != "" {
		c, err := net.Dial("udp", collector)
		if err != nil {
			return nil, err
		}
		conn = c
	}
	s := &Simulator{
		enc: NewEncoder(encoder, samplingRate), rate: samplingRate, collector: collector, conn: conn,
		protected: protected, baselineBPS: baselineBPS, runs: map[string]*Run{},
	}
	// Pick a stable set of "server" addresses in the protected space.
	for _, p := range protected {
		for i := 0; i < 12; i++ {
			s.servers = append(s.servers, hostIn(p, 10+i*7))
		}
	}
	for i := 0; i < 400; i++ {
		s.clients = append(s.clients, s.randomExternal())
	}
	return s, nil
}

// SetBaseline toggles background traffic.
func (s *Simulator) SetBaseline(on bool, bps float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.baseline = on
	if bps > 0 {
		s.baselineBPS = bps
	}
}

// hostIn returns the n-th host address of a prefix.
func hostIn(p netip.Prefix, n int) netip.Addr {
	a := p.Masked().Addr()
	b := a.AsSlice()
	carry := n
	for i := len(b) - 1; i >= 0 && carry > 0; i-- {
		v := int(b[i]) + carry
		b[i] = byte(v & 0xFF)
		carry = v >> 8
	}
	out, _ := netip.AddrFromSlice(b)
	if !p.Contains(out) {
		return p.Masked().Addr().Next()
	}
	return out
}

var externalV4 = []byte{31, 37, 45, 62, 77, 91, 103, 109, 151, 176, 185, 188, 193, 194, 212, 213}

func (s *Simulator) isProtected(a netip.Addr) bool {
	for _, p := range s.protected {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (s *Simulator) randomExternal() netip.Addr {
	for {
		a := netip.AddrFrom4([4]byte{externalV4[rand.IntN(len(externalV4))], byte(rand.IntN(256)), byte(rand.IntN(256)), byte(1 + rand.IntN(254))})
		if !s.isProtected(a) {
			return a
		}
	}
}

func (s *Simulator) randomExternalV6() netip.Addr {
	var b [16]byte
	b[0], b[1], b[2], b[3] = 0x2a, 0x02, byte(rand.IntN(256)), byte(rand.IntN(256))
	for i := 8; i < 16; i++ {
		b[i] = byte(rand.IntN(256))
	}
	return netip.AddrFrom16(b)
}

// RelativePPS sizes a near-miss scenario from the target's effective
// thresholds (packets/s and bits/s; zero = not set).
func (sc Scenario) RelativePPS(tPPS, tBPS float64) float64 {
	pps := tPPS
	if tBPS > 0 && sc.PktSize > 0 {
		if byBPS := tBPS / (sc.PktSize * 8); pps == 0 || byBPS < pps {
			pps = byBPS
		}
	}
	return pps * sc.RelativeFactor
}

// Lookup returns a scenario definition.
func Lookup(id string) (Scenario, bool) {
	sc, ok := catalogue[id]
	if !ok {
		return Scenario{}, false
	}
	return *sc, true
}

// Scenarios returns the catalogue.
func Scenarios() []Scenario {
	out := make([]Scenario, 0, len(catalogue))
	for _, sc := range catalogue {
		out = append(out, *sc)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Start launches a scenario now.
func (s *Simulator) Start(req StartRequest) (*Run, error) { return s.StartAt(req, time.Now()) }

// StartAt launches a scenario at a given (possibly simulated) time.
func (s *Simulator) StartAt(req StartRequest, at time.Time) (*Run, error) {
	sc := catalogue[req.Scenario]
	if sc == nil {
		return nil, fmt.Errorf("unknown scenario %q", req.Scenario)
	}
	r := &Run{Scenario: sc.ID, Name: sc.Name, PPS: req.PPS, Sources: req.Sources, sc: sc}
	if r.PPS <= 0 {
		r.PPS = sc.DefaultPPS
	}
	if r.Sources <= 0 {
		r.Sources = sc.Sources
	}
	dur := req.Duration
	if dur <= 0 {
		dur = 120
	}
	// target selection
	switch {
	case req.Target != "" && sc.TargetKind == "prefix":
		p, err := netip.ParsePrefix(req.Target)
		if err != nil {
			a, err2 := netip.ParseAddr(req.Target)
			if err2 != nil {
				return nil, fmt.Errorf("invalid target %q", req.Target)
			}
			bits := 24
			if a.Is6() {
				bits = 64
			}
			p, _ = a.Prefix(bits)
		}
		r.prefix = p.Masked()
		r.target = r.prefix.Addr()
	case req.Target != "":
		a, err := netip.ParseAddr(req.Target)
		if err != nil {
			return nil, fmt.Errorf("invalid target %q", req.Target)
		}
		r.target = a
	default:
		p := s.protected[0]
		r.target = hostIn(p, 10)
		bits := 24
		if r.target.Is6() {
			bits = 64
		}
		r.prefix, _ = r.target.Prefix(bits)
	}
	if !r.prefix.IsValid() {
		bits := 24
		if r.target.Is6() {
			bits = 64
		}
		r.prefix, _ = r.target.Prefix(bits)
	}
	if sc.TargetKind == "prefix" {
		r.Target = r.prefix.String()
	} else {
		r.Target = r.target.String()
	}
	for i := 0; i < r.Sources; i++ {
		if r.target.Is6() {
			r.srcPool = append(r.srcPool, s.randomExternalV6())
		} else {
			r.srcPool = append(r.srcPool, s.randomExternal())
		}
	}
	now := at.Unix()
	r.StartedAt, r.EndsAt = now, now+int64(dur)
	s.mu.Lock()
	s.seq++
	r.ID = fmt.Sprintf("RUN-%03d", s.seq)
	s.runs[r.ID] = r
	s.mu.Unlock()
	return r, nil
}

// Stop ends a run (or all runs if id is empty).
func (s *Simulator) Stop(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == "" {
		s.runs = map[string]*Run{}
		return
	}
	delete(s.runs, id)
}

// Status returns the simulator status.
func (s *Simulator) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{Encoder: s.enc.Name(), SamplingRate: s.rate, Target: s.collector, Baseline: s.baseline, BaselineBPS: s.baselineBPS, Datagrams: s.datagrams, Specs: s.specs}
	for _, r := range s.runs {
		st.Runs = append(st.Runs, *r)
	}
	sort.Slice(st.Runs, func(i, j int) bool { return st.Runs[i].StartedAt < st.Runs[j].StartedAt })
	return st
}

// Loop generates traffic every second until ctx is done.
func (s *Simulator) Loop(ctx context.Context) {
	if s.conn == nil {
		return
	}
	t := time.NewTicker(time.Second)
	defer t.Stop()
	defer s.conn.Close()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.step(now)
		}
	}
}

// Generate returns one second of traffic (baseline + active runs) at now and
// expires finished runs. It is used by the UDP loop and by in-process
// replay/benchmark harnesses.
func (s *Simulator) Generate(now time.Time) []Spec {
	s.mu.Lock()
	defer s.mu.Unlock()
	var specs []Spec
	if s.baseline {
		specs = append(specs, s.baselineSpecs(now)...)
	}
	for id, r := range s.runs {
		if now.Unix() >= r.EndsAt {
			delete(s.runs, id)
			continue
		}
		c := &genCtx{run: r, pps: r.PPS, sources: r.srcPool, target: r.target, prefix: r.prefix, elapsed: float64(now.Unix() - r.StartedAt)}
		specs = append(specs, r.sc.gen(c)...)
	}
	s.specs += uint64(len(specs))
	return specs
}

func (s *Simulator) step(now time.Time) {
	specs := s.Generate(now)

	// Spread datagrams over the second to avoid micro-bursts on loopback.
	dgs := s.enc.Encode(specs, now)
	s.mu.Lock()
	s.datagrams += uint64(len(dgs))
	s.mu.Unlock()
	pause := time.Duration(0)
	if len(dgs) > 50 {
		pause = 700 * time.Millisecond / time.Duration(len(dgs))
	}
	for _, d := range dgs {
		_, _ = s.conn.Write(d)
		if pause > 0 {
			time.Sleep(pause)
		}
	}
}

// baselineSpecs produces a diurnal-ish mix of normal traffic.
func (s *Simulator) baselineSpecs(now time.Time) []Spec {
	// Smooth variation (±20%) over a 10-minute cycle plus noise.
	f := 1 + 0.2*math.Sin(float64(now.Unix()%600)/600*2*math.Pi) + 0.05*(rand.Float64()-0.5)
	bps := s.baselineBPS * f
	var out []Spec
	type mix struct {
		share   float64
		size    uint16
		proto   uint8
		flags   uint8
		sport   func() uint16
		dport   func() uint16
		inbound bool
	}
	eph := func() uint16 { return uint16(32768 + rand.IntN(28000)) }
	fixed := func(p uint16) func() uint16 { return func() uint16 { return p } }
	mixes := []mix{
		{0.45, 1200, flow.ProtoTCP, flow.TCPAck | flow.TCPPsh, eph, fixed(443), true},  // client uploads/requests
		{0.25, 1400, flow.ProtoTCP, flow.TCPAck | flow.TCPPsh, fixed(443), eph, false}, // server responses
		{0.10, 1200, flow.ProtoUDP, 0, eph, fixed(443), true},                          // QUIC
		{0.05, 80, flow.ProtoUDP, 0, eph, fixed(53), true},                             // DNS queries to our servers
		{0.04, 300, flow.ProtoUDP, 0, fixed(53), eph, true},                            // DNS responses to our clients
		{0.03, 90, flow.ProtoUDP, 0, fixed(123), fixed(123), true},                     // NTP
		{0.03, 64, flow.ProtoTCP, flow.TCPSyn, eph, fixed(443), true},                  // new connections
		{0.03, 84, flow.ProtoICMP, 0, nil, nil, true},                                  // pings
		{0.02, 600, flow.ProtoTCP, flow.TCPAck | flow.TCPPsh, eph, fixed(22), true},    // ssh
	}
	for _, m := range mixes {
		pps := bps * m.share / 8 / float64(m.size)
		n := 25
		for i := 0; i < n; i++ {
			srv := s.servers[rand.IntN(len(s.servers))]
			cli := s.clients[rand.IntN(len(s.clients))]
			if srv.Is6() {
				cli = s.randomExternalV6()
			}
			sp := Spec{Proto: m.proto, TCPFlags: m.flags, PktSize: m.size, Packets: uint64(pps / float64(n) * (0.5 + rand.Float64()))}
			if m.sport != nil {
				sp.SrcPort, sp.DstPort = m.sport(), m.dport()
			}
			if m.proto == flow.ProtoICMP {
				sp.ICMPType = 8
				if srv.Is6() {
					sp.Proto, sp.ICMPType = flow.ProtoICMPv6, 128
				}
			}
			if m.inbound {
				sp.Src, sp.Dst = cli, srv
			} else {
				sp.Src, sp.Dst = srv, cli
			}
			out = append(out, sp)
		}
	}
	return out
}

// ------------------------------------------------------------- scenarios

// spread distributes pps across a random subset of sources.
func spread(c *genCtx, maxPerSec int, mk func(src netip.Addr, pkts uint64) Spec) []Spec {
	n := len(c.sources)
	if n == 0 {
		return nil
	}
	k := min(n, maxPerSec)
	per := c.pps / float64(k)
	out := make([]Spec, 0, k)
	off := rand.IntN(n)
	for i := 0; i < k; i++ {
		src := c.sources[(off+i)%n]
		p := uint64(per * (0.7 + 0.6*rand.Float64()))
		if p == 0 {
			p = 1
		}
		out = append(out, mk(src, p))
	}
	return out
}

func eph() uint16 { return uint16(1024 + rand.IntN(64000)) }

// amp generates reflected UDP responses from a well-known source port.
func amp(port uint16, size uint16) func(c *genCtx) []Spec {
	return func(c *genCtx) []Spec {
		return spread(c, 400, func(src netip.Addr, p uint64) Spec {
			return Spec{Src: src, Dst: c.target, Proto: flow.ProtoUDP, SrcPort: port, DstPort: eph(), Packets: p, PktSize: size}
		})
	}
}

func ampWithFragments(port uint16, size uint16, fragShare float64) func(c *genCtx) []Spec {
	return func(c *genCtx) []Spec {
		base := amp(port, size)(c)
		var out []Spec
		for _, s := range base {
			fp := uint64(float64(s.Packets) * fragShare)
			s.Packets -= fp
			out = append(out, s)
			if fp > 0 {
				out = append(out, Spec{Src: s.Src, Dst: s.Dst, Proto: flow.ProtoUDP, Fragment: true, Packets: fp, PktSize: 1480})
			}
		}
		return out
	}
}

func tcpFlood(flags uint8, size uint16, dport uint16, sport uint16) func(c *genCtx) []Spec {
	return func(c *genCtx) []Spec {
		return spread(c, 600, func(src netip.Addr, p uint64) Spec {
			sp, dp := sport, dport
			if sp == 0 {
				sp = eph()
			}
			if dp == 0 {
				dp = eph()
			}
			return Spec{Src: src, Dst: c.target, Proto: flow.ProtoTCP, TCPFlags: flags, SrcPort: sp, DstPort: dp, Packets: p, PktSize: size}
		})
	}
}

// carpet spreads a generator over every host of the target prefix.
func carpet(inner func(dst netip.Addr) Spec) func(c *genCtx) []Spec {
	return func(c *genCtx) []Spec {
		hosts := 254
		if c.prefix.Addr().Is6() {
			hosts = 200
		}
		var out []Spec
		perHost := c.pps / float64(hosts)
		for i := 1; i <= hosts; i++ {
			dst := hostIn(c.prefix, i)
			for j := 0; j < 3; j++ {
				s := inner(dst)
				s.Src = c.sources[rand.IntN(len(c.sources))]
				s.Packets = uint64(perHost / 3 * (0.7 + 0.6*rand.Float64()))
				if s.Packets == 0 {
					s.Packets = 1
				}
				out = append(out, s)
			}
		}
		return out
	}
}

var catalogue = map[string]*Scenario{}

func add(sc *Scenario) { catalogue[sc.ID] = sc }

func init() {
	add(&Scenario{ID: "dns_amp", Name: "DNS Amplification", Category: "amplification", TargetKind: "host", DefaultPPS: 120_000, Sources: 3000,
		Description: "Açık resolver'lardan büyük DNS cevapları (src/53) + fragment'lar.", Expect: []string{"amp_dns", "udp_fragment_flood", "udp_flood_host"},
		gen: ampWithFragments(53, 1460, 0.3)})
	add(&Scenario{ID: "ntp_amp", Name: "NTP Amplification (monlist)", Category: "amplification", TargetKind: "host", DefaultPPS: 80_000, Sources: 800,
		Description: "src/123, 468 byte monlist cevapları.", Expect: []string{"amp_ntp"}, gen: amp(123, 468)})
	add(&Scenario{ID: "ssdp_amp", Name: "SSDP Amplification", Category: "amplification", TargetKind: "host", DefaultPPS: 60_000, Sources: 4000,
		Description: "src/1900 UPnP cevapları.", Expect: []string{"amp_ssdp"}, gen: amp(1900, 320)})
	add(&Scenario{ID: "memcached_amp", Name: "Memcached Amplification", Category: "amplification", TargetKind: "host", DefaultPPS: 50_000, Sources: 60,
		Description: "src/11211, çok az kaynaktan devasa cevaplar ve fragment'lar.", Expect: []string{"amp_memcached", "udp_fragment_flood"}, gen: ampWithFragments(11211, 1460, 0.5)})
	add(&Scenario{ID: "cldap_amp", Name: "CLDAP Amplification", Category: "amplification", TargetKind: "host", DefaultPPS: 40_000, Sources: 900,
		Description: "src/389 UDP Active Directory cevapları.", Expect: []string{"amp_cldap"}, gen: ampWithFragments(389, 1460, 0.4)})
	add(&Scenario{ID: "wsd_amp", Name: "WS-Discovery Amplification", Category: "amplification", TargetKind: "host", DefaultPPS: 30_000, Sources: 1200,
		Description: "src/3702 IoT keşif cevapları.", Expect: []string{"amp_wsd_arms"}, gen: amp(3702, 1100)})
	add(&Scenario{ID: "syn_flood", Name: "TCP SYN Flood", Category: "tcp", TargetKind: "host", DefaultPPS: 400_000, Sources: 20000,
		Description: "Sahte kaynaklı SYN, hedef TCP/443.", Expect: []string{"tcp_syn_flood"}, gen: tcpFlood(flow.TCPSyn, 60, 443, 0)})
	add(&Scenario{ID: "synack_reflection", Name: "SYN-ACK Reflection", Category: "tcp", TargetKind: "host", DefaultPPS: 150_000, Sources: 3000,
		Description: "Yansıtıcı web sunucularından istenmeyen SYN-ACK'ler.", Expect: []string{"tcp_synack_reflection"}, gen: tcpFlood(flow.TCPSyn|flow.TCPAck, 60, 0, 443)})
	add(&Scenario{ID: "ack_flood", Name: "TCP ACK Flood", Category: "tcp", TargetKind: "host", DefaultPPS: 900_000, Sources: 20000,
		Description: "Saf ACK paketleri, küçük boy.", Expect: []string{"tcp_ack_flood"}, gen: tcpFlood(flow.TCPAck, 52, 443, 0)})
	add(&Scenario{ID: "rst_flood", Name: "TCP RST Flood", Category: "tcp", TargetKind: "host", DefaultPPS: 120_000, Sources: 5000,
		Description: "RST seli.", Expect: []string{"tcp_rst_flood"}, gen: tcpFlood(flow.TCPRst, 40, 443, 0)})
	add(&Scenario{ID: "tcp_null", Name: "TCP NULL Flood", Category: "tcp", TargetKind: "host", DefaultPPS: 30_000, Sources: 2000,
		Description: "Flag'siz TCP paketleri.", Expect: []string{"tcp_invalid_flags"}, gen: tcpFlood(0, 40, 0, 0)})
	add(&Scenario{ID: "tcp_xmas", Name: "TCP XMAS Flood", Category: "tcp", TargetKind: "host", DefaultPPS: 20_000, Sources: 2000,
		Description: "FIN+PSH+URG paketleri.", Expect: []string{"tcp_xmas_synfin", "tcp_fin_flood"}, gen: tcpFlood(flow.TCPFin|flow.TCPPsh|flow.TCPUrg, 40, 0, 0)})
	add(&Scenario{ID: "udp_flood", Name: "UDP Flood (rastgele port)", Category: "udp", TargetKind: "host", DefaultPPS: 600_000, Sources: 5000,
		Description: "Rastgele kaynak/hedef portlu UDP.", Expect: []string{"udp_flood_host"},
		gen: func(c *genCtx) []Spec {
			return spread(c, 600, func(src netip.Addr, p uint64) Spec {
				return Spec{Src: src, Dst: c.target, Proto: flow.ProtoUDP, SrcPort: eph(), DstPort: eph(), Packets: p, PktSize: uint16(512 + rand.IntN(800))}
			})
		}})
	add(&Scenario{ID: "udp_small", Name: "UDP Küçük Paket Flood", Category: "udp", TargetKind: "host", DefaultPPS: 900_000, Sources: 5000,
		Description: "64 byte UDP ile pps saldırısı.", Expect: []string{"udp_small_packet_flood", "udp_flood_host"},
		gen: func(c *genCtx) []Spec {
			return spread(c, 600, func(src netip.Addr, p uint64) Spec {
				return Spec{Src: src, Dst: c.target, Proto: flow.ProtoUDP, SrcPort: eph(), DstPort: eph(), Packets: p, PktSize: 64}
			})
		}})
	add(&Scenario{ID: "quic_flood", Name: "UDP/443 QUIC Flood", Category: "udp", TargetKind: "host", DefaultPPS: 700_000, Sources: 8000,
		Description: "Hedef UDP/443.", Expect: []string{"udp_quic_flood"},
		gen: func(c *genCtx) []Spec {
			return spread(c, 600, func(src netip.Addr, p uint64) Spec {
				return Spec{Src: src, Dst: c.target, Proto: flow.ProtoUDP, SrcPort: eph(), DstPort: 443, Packets: p, PktSize: 1250}
			})
		}})
	add(&Scenario{ID: "icmp_flood", Name: "ICMP Echo Flood", Category: "icmp", TargetKind: "host", DefaultPPS: 80_000, Sources: 2000,
		Description: "Ping flood.", Expect: []string{"icmp_echo_flood"},
		gen: func(c *genCtx) []Spec {
			return spread(c, 400, func(src netip.Addr, p uint64) Spec {
				return Spec{Src: src, Dst: c.target, Proto: flow.ProtoICMP, ICMPType: 8, Packets: p, PktSize: 84}
			})
		}})
	add(&Scenario{ID: "blacknurse", Name: "BlackNurse (ICMP 3/3)", Category: "icmp", TargetKind: "host", DefaultPPS: 40_000, Sources: 50,
		Description: "Destination/port unreachable seli.", Expect: []string{"icmp_unreachable_blacknurse"},
		gen: func(c *genCtx) []Spec {
			return spread(c, 50, func(src netip.Addr, p uint64) Spec {
				return Spec{Src: src, Dst: c.target, Proto: flow.ProtoICMP, ICMPType: 3, ICMPCode: 3, Packets: p, PktSize: 70}
			})
		}})
	add(&Scenario{ID: "fragment_flood", Name: "UDP Fragment Flood", Category: "fragment", TargetKind: "host", DefaultPPS: 60_000, Sources: 1000,
		Description: "Port bilgisi olmayan UDP fragment'ları.", Expect: []string{"udp_fragment_flood", "fragment_flood_any"},
		gen: func(c *genCtx) []Spec {
			return spread(c, 400, func(src netip.Addr, p uint64) Spec {
				return Spec{Src: src, Dst: c.target, Proto: flow.ProtoUDP, Fragment: true, Packets: p, PktSize: 1480}
			})
		}})
	add(&Scenario{ID: "gre_flood", Name: "GRE Flood", Category: "ip_protocol", TargetKind: "host", DefaultPPS: 60_000, Sources: 500,
		Description: "IP protokol 47 seli.", Expect: []string{"gre_flood"},
		gen: func(c *genCtx) []Spec {
			return spread(c, 300, func(src netip.Addr, p uint64) Spec {
				return Spec{Src: src, Dst: c.target, Proto: flow.ProtoGRE, Packets: p, PktSize: 576}
			})
		}})
	add(&Scenario{ID: "ipip_flood", Name: "IP-in-IP / Alışılmadık Protokol", Category: "ip_protocol", TargetKind: "host", DefaultPPS: 20_000, Sources: 300,
		Description: "IP protokol 4 seli.", Expect: []string{"ipproto_unusual"},
		gen: func(c *genCtx) []Spec {
			return spread(c, 300, func(src netip.Addr, p uint64) Spec {
				return Spec{Src: src, Dst: c.target, Proto: flow.ProtoIPIP, Packets: p, PktSize: 400}
			})
		}})
	add(&Scenario{ID: "carpet_ntp", Name: "Carpet Bombing — NTP Amp", Category: "carpet", TargetKind: "prefix", DefaultPPS: 300_000, Sources: 1500,
		Description: "/24'teki her hosta eşik altı NTP amplifikasyonu; host kuralları görmez, prefix kuralı yakalar.", Expect: []string{"carpet_amplification"},
		gen: carpet(func(dst netip.Addr) Spec {
			return Spec{Dst: dst, Proto: flow.ProtoUDP, SrcPort: 123, DstPort: eph(), PktSize: 468}
		})})
	add(&Scenario{ID: "carpet_syn", Name: "Carpet Bombing — SYN", Category: "carpet", TargetKind: "prefix", DefaultPPS: 600_000, Sources: 20000,
		Description: "/24'e yayılmış SYN flood.", Expect: []string{"carpet_syn"},
		gen: carpet(func(dst netip.Addr) Spec {
			return Spec{Dst: dst, Proto: flow.ProtoTCP, TCPFlags: flow.TCPSyn, SrcPort: eph(), DstPort: 443, PktSize: 60}
		})})
	// Near-miss scenarios for the AI analyst.
	add(&Scenario{ID: "stealth_dns", Name: "Eşik Altı DNS Amp (AI için)", Category: "near_miss", TargetKind: "host", DefaultPPS: 12_000, Sources: 600,
		RelativeRule: "amp_dns", RelativeFactor: 0.65, PktSize: 1300,
		Description: "DNS amplifikasyonu eşiğin ~%60'ında; alarm üretmez, aday sinyal üretir.", Expect: []string{"signal: near_threshold amp_dns"},
		gen: amp(53, 1300)})
	add(&Scenario{ID: "few_sources", Name: "Az Kaynaklı Yüksek Hacim (AI için)", Category: "near_miss", TargetKind: "host", DefaultPPS: 40_000, Sources: 6,
		RelativeRule: "amp_dns", RelativeFactor: 1.8, PktSize: 1400,
		Description: "Eşik aşılır ama benzersiz kaynak koşulu sağlanmaz (conditions_unmet).", Expect: []string{"signal: conditions_unmet amp_dns"},
		gen: amp(53, 1400)})
	add(&Scenario{ID: "slow_ramp", Name: "Yavaş Yükselen UDP (AI için)", Category: "near_miss", TargetKind: "host", DefaultPPS: 25_000, Sources: 2000,
		Description: "UDP 5 dakikada kademeli artar; baseline sapması üretir (baseline öğrenilmiş olmalı).", Expect: []string{"signal: baseline_deviation"},
		gen: func(c *genCtx) []Spec {
			c2 := *c
			c2.pps = c.pps * math.Min(1, 0.1+c.elapsed/300)
			return spread(&c2, 300, func(src netip.Addr, p uint64) Spec {
				return Spec{Src: src, Dst: c.target, Proto: flow.ProtoUDP, SrcPort: eph(), DstPort: 27015, Packets: p, PktSize: 900}
			})
		}})
	// Outbound.
	add(&Scenario{ID: "out_reflector", Name: "Outbound: Açık NTP Yansıtıcı", Category: "outbound", TargetKind: "outbound", DefaultPPS: 30_000, Sources: 400,
		Description: "Korunan host dışarıya src/123 monlist cevapları üretiyor.", Expect: []string{"out_reflector_misc"},
		gen: func(c *genCtx) []Spec {
			return spread(c, 300, func(dst netip.Addr, p uint64) Spec {
				return Spec{Src: c.target, Dst: dst, Proto: flow.ProtoUDP, SrcPort: 123, DstPort: eph(), Packets: p, PktSize: 468}
			})
		}})
	add(&Scenario{ID: "out_syn", Name: "Outbound: SYN Flood (botnet)", Category: "outbound", TargetKind: "outbound", DefaultPPS: 60_000, Sources: 50,
		Description: "Korunan host dışarıya SYN flood üretiyor.", Expect: []string{"out_syn_flood"},
		gen: func(c *genCtx) []Spec {
			return spread(c, 50, func(dst netip.Addr, p uint64) Spec {
				return Spec{Src: c.target, Dst: dst, Proto: flow.ProtoTCP, TCPFlags: flow.TCPSyn, SrcPort: eph(), DstPort: 80, Packets: p, PktSize: 60}
			})
		}})
}
