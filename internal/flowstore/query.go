package flowstore

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/flow"
)

// Filter selects records. Zero values mean "any".
type Filter struct {
	Seconds   int    `json:"seconds,omitempty"`
	Direction string `json:"direction,omitempty"`
	Src       string `json:"src,omitempty"` // IP or prefix
	Dst       string `json:"dst,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	SrcPort   *int   `json:"src_port,omitempty"`
	DstPort   *int   `json:"dst_port,omitempty"`
	ObjectID  *int   `json:"object_id,omitempty"`
	Exporter  string `json:"exporter,omitempty"`
	Fragment  *bool  `json:"fragment,omitempty"`
	ICMPType  *int   `json:"icmp_type,omitempty"`
	TCPFlags  string `json:"tcp_flags,omitempty"` // exact combination e.g. "SYN" or "SYN|ACK"
}

// Predicate is an additional match function (e.g. a rule matcher).
type Predicate func(*flow.Record) bool

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Masked(), err
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Compile turns a filter into a predicate and the lookback start time.
func (f Filter) Compile(now int64) (Predicate, int64, error) {
	secs := f.Seconds
	if secs <= 0 {
		secs = 60
	}
	since := now - int64(secs)
	var preds []Predicate
	if f.Direction != "" {
		var d flow.Direction
		switch f.Direction {
		case "inbound":
			d = flow.DirInbound
		case "outbound":
			d = flow.DirOutbound
		case "other":
			d = flow.DirOther
		default:
			return nil, 0, fmt.Errorf("invalid direction %q", f.Direction)
		}
		preds = append(preds, func(r *flow.Record) bool { return r.Direction == d })
	}
	if f.Src != "" {
		p, err := parsePrefix(f.Src)
		if err != nil {
			return nil, 0, fmt.Errorf("src: %w", err)
		}
		preds = append(preds, func(r *flow.Record) bool { return p.Contains(r.Src) })
	}
	if f.Dst != "" {
		p, err := parsePrefix(f.Dst)
		if err != nil {
			return nil, 0, fmt.Errorf("dst: %w", err)
		}
		preds = append(preds, func(r *flow.Record) bool { return p.Contains(r.Dst) })
	}
	if f.Protocol != "" {
		n, ok := flow.ProtoNumber(strings.ToLower(f.Protocol))
		if !ok {
			return nil, 0, fmt.Errorf("invalid protocol %q", f.Protocol)
		}
		preds = append(preds, func(r *flow.Record) bool { return r.Protocol == n })
	}
	if f.SrcPort != nil {
		p := uint16(*f.SrcPort)
		preds = append(preds, func(r *flow.Record) bool { return r.SrcPort == p && !r.Fragment })
	}
	if f.DstPort != nil {
		p := uint16(*f.DstPort)
		preds = append(preds, func(r *flow.Record) bool { return r.DstPort == p && !r.Fragment })
	}
	if f.ObjectID != nil {
		id := int32(*f.ObjectID)
		preds = append(preds, func(r *flow.Record) bool { return r.ObjectID == id })
	}
	if f.Exporter != "" {
		a, err := netip.ParseAddr(f.Exporter)
		if err != nil {
			return nil, 0, fmt.Errorf("exporter: %w", err)
		}
		preds = append(preds, func(r *flow.Record) bool { return r.Exporter == a })
	}
	if f.Fragment != nil {
		v := *f.Fragment
		preds = append(preds, func(r *flow.Record) bool { return r.Fragment == v })
	}
	if f.ICMPType != nil {
		t := uint8(*f.ICMPType)
		preds = append(preds, func(r *flow.Record) bool {
			return (r.Protocol == flow.ProtoICMP || r.Protocol == flow.ProtoICMPv6) && r.ICMPType == t
		})
	}
	if f.TCPFlags != "" {
		var want uint8
		for _, n := range strings.Split(strings.ToUpper(f.TCPFlags), "|") {
			b, ok := flow.TCPFlagBit(strings.TrimSpace(n))
			if !ok && n != "-" {
				return nil, 0, fmt.Errorf("invalid tcp flag %q", n)
			}
			want |= b
		}
		preds = append(preds, func(r *flow.Record) bool { return r.Protocol == flow.ProtoTCP && r.TCPFlags == want })
	}
	return func(r *flow.Record) bool {
		for _, p := range preds {
			if !p(r) {
				return false
			}
		}
		return true
	}, since, nil
}

// Row is an aggregated result row.
type Row struct {
	Key     string  `json:"key"`
	BPS     float64 `json:"bps"`
	PPS     float64 `json:"pps"`
	FPS     float64 `json:"fps"`
	Share   float64 `json:"share"` // share of the chosen metric, 0..1
	Records int     `json:"records"`
}

// Dimensions supported by TopN.
var Dimensions = []string{"src_ip", "dst_ip", "src_port", "dst_port", "protocol", "tcp_flags", "packet_size", "src_net", "dst_net", "exporter", "in_if", "out_if", "src_as", "dst_as", "icmp_type", "direction", "object", "fragment"}

// KeyFunc returns the grouping key for a record.
func KeyFunc(dim string, objectName func(int32) string) (func(*flow.Record) string, error) {
	switch dim {
	case "src_ip":
		return func(r *flow.Record) string { return r.Src.String() }, nil
	case "dst_ip":
		return func(r *flow.Record) string { return r.Dst.String() }, nil
	case "src_port":
		return func(r *flow.Record) string { return portKey(r, r.SrcPort) }, nil
	case "dst_port":
		return func(r *flow.Record) string { return portKey(r, r.DstPort) }, nil
	case "protocol":
		return func(r *flow.Record) string { return flow.ProtoName(r.Protocol) }, nil
	case "tcp_flags":
		return func(r *flow.Record) string {
			if r.Protocol != flow.ProtoTCP {
				return "non-tcp"
			}
			return flow.TCPFlagsString(r.TCPFlags)
		}, nil
	case "packet_size":
		return func(r *flow.Record) string { return SizeBucket(r.AvgPacketSize()) }, nil
	case "src_net":
		return func(r *flow.Record) string { return netKey(r.Src) }, nil
	case "dst_net":
		return func(r *flow.Record) string { return netKey(r.Dst) }, nil
	case "exporter":
		return func(r *flow.Record) string { return r.Exporter.String() }, nil
	case "in_if":
		return func(r *flow.Record) string { return r.Exporter.String() + "#" + strconv.Itoa(int(r.InIf)) }, nil
	case "out_if":
		return func(r *flow.Record) string { return r.Exporter.String() + "#" + strconv.Itoa(int(r.OutIf)) }, nil
	case "src_as":
		return func(r *flow.Record) string { return "AS" + strconv.Itoa(int(r.SrcAS)) }, nil
	case "dst_as":
		return func(r *flow.Record) string { return "AS" + strconv.Itoa(int(r.DstAS)) }, nil
	case "icmp_type":
		return func(r *flow.Record) string {
			if r.Protocol != flow.ProtoICMP && r.Protocol != flow.ProtoICMPv6 {
				return "non-icmp"
			}
			return fmt.Sprintf("%s type %d code %d", flow.ProtoName(r.Protocol), r.ICMPType, r.ICMPCode)
		}, nil
	case "direction":
		return func(r *flow.Record) string { return r.Direction.String() }, nil
	case "object":
		return func(r *flow.Record) string {
			if r.ObjectID < 0 {
				return "-"
			}
			if objectName != nil {
				return objectName(r.ObjectID)
			}
			return strconv.Itoa(int(r.ObjectID))
		}, nil
	case "fragment":
		return func(r *flow.Record) string {
			if r.Fragment {
				return "fragment"
			}
			return "non-fragment"
		}, nil
	}
	return nil, fmt.Errorf("unknown dimension %q", dim)
}

func portKey(r *flow.Record, p uint16) string {
	if r.Fragment {
		return "fragment"
	}
	switch r.Protocol {
	case flow.ProtoTCP, flow.ProtoUDP, flow.ProtoSCTP:
		return flow.ProtoName(r.Protocol) + "/" + strconv.Itoa(int(p))
	}
	return flow.ProtoName(r.Protocol)
}

func netKey(a netip.Addr) string {
	bits := 24
	if a.Is6() {
		bits = 64
	}
	p, _ := a.Prefix(bits)
	return p.String()
}

// SizeBucket returns a packet size histogram bucket label.
func SizeBucket(s float64) string {
	switch {
	case s <= 64:
		return "0-64"
	case s <= 128:
		return "65-128"
	case s <= 256:
		return "129-256"
	case s <= 512:
		return "257-512"
	case s <= 1024:
		return "513-1024"
	case s <= 1500:
		return "1025-1500"
	}
	return ">1500"
}

type agg struct {
	bytes, pkts, flows float64
	records            int
}

func (a *agg) add(r *flow.Record) {
	a.bytes += r.ScaledBytes()
	a.pkts += r.ScaledPackets()
	if r.Source != flow.SourceSFlow {
		a.flows++
	}
	a.records++
}

func toRows(m map[string]*agg, secs float64, metric string, limit int) []Row {
	rows := make([]Row, 0, len(m))
	var total float64
	for k, a := range m {
		r := Row{Key: k, BPS: a.bytes * 8 / secs, PPS: a.pkts / secs, FPS: a.flows / secs, Records: a.records}
		rows = append(rows, r)
		total += metricOf(r, metric)
	}
	sort.Slice(rows, func(i, j int) bool { return metricOf(rows[i], metric) > metricOf(rows[j], metric) })
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	if total > 0 {
		for i := range rows {
			rows[i].Share = metricOf(rows[i], metric) / total
		}
	}
	return rows
}

func metricOf(r Row, metric string) float64 {
	switch metric {
	case "pps":
		return r.PPS
	case "fps":
		return r.FPS
	}
	return r.BPS
}

// TopResult is the response of TopN.
type TopResult struct {
	Dimension string  `json:"dimension"`
	Metric    string  `json:"metric"`
	Seconds   int     `json:"seconds"`
	TotalBPS  float64 `json:"total_bps"`
	TotalPPS  float64 `json:"total_pps"`
	Records   int     `json:"records"`
	Rows      []Row   `json:"rows"`
}

// TopN groups matching records by dim and returns the top rows.
func (s *Store) TopN(f Filter, extra Predicate, dim, metric string, limit int, objectName func(int32) string) (*TopResult, error) {
	key, err := KeyFunc(dim, objectName)
	if err != nil {
		return nil, err
	}
	pred, since, err := f.Compile(time.Now().Unix())
	if err != nil {
		return nil, err
	}
	if metric == "" {
		metric = "bps"
	}
	if limit <= 0 || limit > 1000 {
		limit = 20
	}
	m := map[string]*agg{}
	var tot agg
	s.Scan(since, func(r *flow.Record) bool {
		if !pred(r) || (extra != nil && !extra(r)) {
			return true
		}
		k := key(r)
		a := m[k]
		if a == nil {
			a = &agg{}
			m[k] = a
		}
		a.add(r)
		tot.add(r)
		return true
	})
	secs := float64(seconds(f))
	return &TopResult{
		Dimension: dim, Metric: metric, Seconds: seconds(f),
		TotalBPS: tot.bytes * 8 / secs, TotalPPS: tot.pkts / secs, Records: tot.records,
		Rows: toRows(m, secs, metric, limit),
	}, nil
}

func seconds(f Filter) int {
	if f.Seconds <= 0 {
		return 60
	}
	return f.Seconds
}

// Breakdown summarizes matching traffic along several dimensions.
type Breakdown struct {
	Seconds       int      `json:"seconds"`
	Records       int      `json:"records"`
	TotalBPS      float64  `json:"total_bps"`
	TotalPPS      float64  `json:"total_pps"`
	TotalFPS      float64  `json:"total_fps"`
	AvgPacketSize float64  `json:"avg_packet_size"`
	UniqueSrc     int      `json:"unique_src"`
	UniqueDst     int      `json:"unique_dst"`
	FragmentShare float64  `json:"fragment_share"`
	SamplingRates []uint32 `json:"sampling_rates"`
	Protocols     []Row    `json:"protocols"`
	PacketSizes   []Row    `json:"packet_sizes"`
	TCPFlags      []Row    `json:"tcp_flags"`
	TopSources    []Row    `json:"top_sources"`
	TopDests      []Row    `json:"top_destinations"`
	TopSrcPorts   []Row    `json:"top_src_ports"`
	TopDstPorts   []Row    `json:"top_dst_ports"`
	TopSrcNets    []Row    `json:"top_src_nets"`
	Exporters     []Row    `json:"exporters"`
}

// Breakdown computes a multi-dimensional summary of matching traffic.
func (s *Store) Breakdown(f Filter, extra Predicate, topLimit int) (*Breakdown, error) {
	pred, since, err := f.Compile(time.Now().Unix())
	if err != nil {
		return nil, err
	}
	if topLimit <= 0 {
		topLimit = 10
	}
	dims := []string{"protocol", "packet_size", "tcp_flags", "src_ip", "dst_ip", "src_port", "dst_port", "src_net", "exporter"}
	keys := make([]func(*flow.Record) string, len(dims))
	maps := make([]map[string]*agg, len(dims))
	for i, d := range dims {
		keys[i], _ = KeyFunc(d, nil)
		maps[i] = map[string]*agg{}
	}
	var tot agg
	var fragBytes float64
	rates := map[uint32]bool{}
	s.Scan(since, func(r *flow.Record) bool {
		if !pred(r) || (extra != nil && !extra(r)) {
			return true
		}
		tot.add(r)
		if r.Fragment {
			fragBytes += r.ScaledBytes()
		}
		if len(rates) < 16 {
			rates[r.SamplingRate] = true
		}
		for i := range dims {
			k := keys[i](r)
			a := maps[i][k]
			if a == nil {
				a = &agg{}
				maps[i][k] = a
			}
			a.add(r)
		}
		return true
	})
	secs := float64(seconds(f))
	b := &Breakdown{
		Seconds: seconds(f), Records: tot.records,
		TotalBPS: tot.bytes * 8 / secs, TotalPPS: tot.pkts / secs, TotalFPS: tot.flows / secs,
		UniqueSrc: len(maps[3]), UniqueDst: len(maps[4]),
		Protocols:   toRows(maps[0], secs, "bps", 10),
		PacketSizes: toRows(maps[1], secs, "pps", 10),
		TCPFlags:    toRows(maps[2], secs, "pps", 10),
		TopSources:  toRows(maps[3], secs, "bps", topLimit),
		TopDests:    toRows(maps[4], secs, "bps", topLimit),
		TopSrcPorts: toRows(maps[5], secs, "bps", topLimit),
		TopDstPorts: toRows(maps[6], secs, "bps", topLimit),
		TopSrcNets:  toRows(maps[7], secs, "bps", topLimit),
		Exporters:   toRows(maps[8], secs, "bps", topLimit),
	}
	if tot.pkts > 0 {
		b.AvgPacketSize = tot.bytes / tot.pkts
	}
	if tot.bytes > 0 {
		b.FragmentShare = fragBytes / tot.bytes
	}
	for r := range rates {
		b.SamplingRates = append(b.SamplingRates, r)
	}
	sort.Slice(b.SamplingRates, func(i, j int) bool { return b.SamplingRates[i] < b.SamplingRates[j] })
	sort.Slice(b.PacketSizes, func(i, j int) bool { return sizeOrder(b.PacketSizes[i].Key) < sizeOrder(b.PacketSizes[j].Key) })
	return b, nil
}

func sizeOrder(k string) int {
	for i, b := range []string{"0-64", "65-128", "129-256", "257-512", "513-1024", "1025-1500", ">1500"} {
		if b == k {
			return i
		}
	}
	return 99
}

// SampleFlow is a JSON-friendly flow record.
type SampleFlow struct {
	Time         int64   `json:"time"`
	Exporter     string  `json:"exporter"`
	Source       string  `json:"source"`
	SamplingRate uint32  `json:"sampling_rate"`
	Direction    string  `json:"direction"`
	Src          string  `json:"src"`
	Dst          string  `json:"dst"`
	SrcPort      uint16  `json:"src_port"`
	DstPort      uint16  `json:"dst_port"`
	Protocol     string  `json:"protocol"`
	TCPFlags     string  `json:"tcp_flags,omitempty"`
	ICMP         string  `json:"icmp,omitempty"`
	Fragment     bool    `json:"fragment,omitempty"`
	Packets      uint64  `json:"packets"`
	Bytes        uint64  `json:"bytes"`
	AvgPktSize   float64 `json:"avg_packet_size"`
	DurationMs   uint32  `json:"duration_ms"`
	InIf         uint32  `json:"in_if"`
	OutIf        uint32  `json:"out_if"`
	SrcAS        uint32  `json:"src_as,omitempty"`
	DstAS        uint32  `json:"dst_as,omitempty"`
}

// ToSample converts a record to its JSON representation.
func ToSample(r *flow.Record) SampleFlow {
	s := SampleFlow{
		Time: r.ReceivedUnix, Exporter: r.Exporter.String(), Source: r.Source.String(), SamplingRate: r.SamplingRate,
		Direction: r.Direction.String(), Src: r.Src.String(), Dst: r.Dst.String(), SrcPort: r.SrcPort, DstPort: r.DstPort,
		Protocol: flow.ProtoName(r.Protocol), Fragment: r.Fragment, Packets: r.Packets, Bytes: r.Bytes,
		AvgPktSize: r.AvgPacketSize(), DurationMs: r.DurationMs, InIf: r.InIf, OutIf: r.OutIf, SrcAS: r.SrcAS, DstAS: r.DstAS,
	}
	if r.Protocol == flow.ProtoTCP {
		s.TCPFlags = flow.TCPFlagsString(r.TCPFlags)
	}
	if r.Protocol == flow.ProtoICMP || r.Protocol == flow.ProtoICMPv6 {
		s.ICMP = fmt.Sprintf("type %d code %d", r.ICMPType, r.ICMPCode)
	}
	return s
}

// Samples returns up to limit newest matching records.
func (s *Store) Samples(f Filter, extra Predicate, limit int) ([]SampleFlow, error) {
	pred, since, err := f.Compile(time.Now().Unix())
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	out := []SampleFlow{}
	s.Scan(since, func(r *flow.Record) bool {
		if pred(r) && (extra == nil || extra(r)) {
			out = append(out, ToSample(r))
		}
		return len(out) < limit
	})
	return out, nil
}
