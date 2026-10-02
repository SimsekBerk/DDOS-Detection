package analyst

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/collector"
	"github.com/SimsekBerk/DDOS-Detection/internal/engine"
	"github.com/SimsekBerk/DDOS-Detection/internal/flowstore"
)

const submitTool = "submit_finding"

// filterSchema describes flowstore.Filter for the model.
var filterSchema = map[string]any{
	"type":        "object",
	"description": "Flow filtresi. Boş alanlar 'hepsi' demektir.",
	"properties": map[string]any{
		"seconds":     map[string]any{"type": "integer", "description": "Geriye dönük pencere (saniye). Varsayılan 60; flow tamponunun kapsadığı süreyle sınırlıdır."},
		"direction":   map[string]any{"type": "string", "enum": []string{"inbound", "outbound", "other"}},
		"src":         map[string]any{"type": "string", "description": "Kaynak IP veya prefix"},
		"dst":         map[string]any{"type": "string", "description": "Hedef IP veya prefix"},
		"protocol":    map[string]any{"type": "string", "description": "tcp, udp, icmp, icmpv6, gre, esp veya numara"},
		"src_port":    map[string]any{"type": "integer"},
		"dst_port":    map[string]any{"type": "integer"},
		"fragment":    map[string]any{"type": "boolean"},
		"tcp_flags":   map[string]any{"type": "string", "description": "Tam kombinasyon, ör. SYN veya SYN|ACK"},
		"object_name": map[string]any{"type": "string", "description": "Korunan nesne adı"},
	},
}

type filterIn struct {
	flowstore.Filter
	ObjectName string `json:"object_name"`
}

func (f *filterIn) resolve(eng *engine.Engine) (flowstore.Filter, error) {
	out := f.Filter
	if f.ObjectName != "" {
		o := eng.ObjectByName(f.ObjectName)
		if o == nil {
			return out, fmt.Errorf("bilinmeyen nesne %q", f.ObjectName)
		}
		id := int(o.ID)
		out.ObjectID = &id
	}
	if out.Seconds <= 0 {
		out.Seconds = 60
	}
	if out.Seconds > 3600 {
		out.Seconds = 3600
	}
	return out, nil
}

func decode[T any](raw json.RawMessage) (T, error) {
	var v T
	if len(raw) == 0 || string(raw) == "null" {
		return v, nil
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return v, fmt.Errorf("geçersiz girdi: %w", err)
	}
	return v, nil
}

// buildTools returns the read-only tool set plus submit_finding.
func buildTools(eng *engine.Engine, col *collector.Collector) []Tool {
	return []Tool{
		{
			Name:        "get_overview",
			Description: "Ağın genel durumu: global inbound/outbound oranları (son pencere), korunan nesneler ve bağlantı kullanımı, aktif olay sayısı, bekleyen aday sinyal sayısı, exporter sağlığı (kayıp, şablon, örnekleme). İlk çağrı olarak kullanın.",
			Properties:  map[string]any{},
			Run: func(ctx context.Context, _ json.RawMessage) (any, error) {
				snap := eng.Snapshot()
				type exp struct {
					Address, Name     string
					RecordsPerSec     float64
					LostEstimate      uint64
					MissingTemplate   uint64
					SamplingEffective uint32
					LastSeenAgoSec    int64
				}
				var exps []exp
				now := time.Now().Unix()
				if col != nil {
					for _, e := range col.Exporters() {
						rate := e.SamplingOverride
						if rate == 0 {
							rate = e.SamplingReported
						}
						exps = append(exps, exp{e.Address, e.Name, e.RecordsPerSec, e.LostEstimate, e.MissingTemplate, rate, now - e.LastSeen})
					}
				}
				objs := []map[string]any{}
				for _, o := range snap.Objects {
					objs = append(objs, map[string]any{
						"name": o.Name, "profile": o.Profile, "prefixes": o.Prefixes, "in_bps": o.Rates.InBPS, "in_pps": o.Rates.InPPS,
						"out_bps": o.Rates.OutBPS, "link_capacity_bps": o.LinkCapacity, "utilization": o.Utilization, "active_incidents": o.ActiveIncidents,
					})
				}
				return map[string]any{
					"time": snap.Time, "window_seconds": snap.WindowSeconds,
					"global": snap.Global, "objects": objs, "active_incidents": snap.ActiveIncidents,
					"pending_signals": snap.PendingSignals, "records_per_sec": snap.RecordsPerSec, "dropped_records": snap.Dropped,
					"flow_buffer_seconds": now - snap.OldestFlow, "exporters": exps,
				}, nil
			},
		},
		{
			Name:        "list_candidate_signals",
			Description: "Dedektörün alarm ÜRETMEDİĞİ ama dikkat gerektiren aday sinyaller: near_threshold (eşiğe yakın), baseline_deviation (baseline'dan istatistiksel sapma), conditions_unmet (eşik aşıldı ama ek koşul sağlanmadı). Her sinyal kural, hedef, tepe oranı, z-skoru ve baseline içerir.",
			Properties: map[string]any{
				"only_pending": map[string]any{"type": "boolean", "description": "Sadece analiz edilmemiş ve olaya dönüşmemiş sinyaller (varsayılan true)"},
				"limit":        map[string]any{"type": "integer", "description": "En fazla kaç sinyal (varsayılan 20)"},
			},
			Run: func(ctx context.Context, raw json.RawMessage) (any, error) {
				in, err := decode[struct {
					OnlyPending *bool `json:"only_pending"`
					Limit       int   `json:"limit"`
				}](raw)
				if err != nil {
					return nil, err
				}
				pending := in.OnlyPending == nil || *in.OnlyPending
				if in.Limit <= 0 || in.Limit > 50 {
					in.Limit = 20
				}
				return eng.Signals().List(pending, 2, in.Limit), nil
			},
		},
		{
			Name:        "get_target_state",
			Description: "Bir IP adresi için tüm kuralların canlı durumu: mevcut pps/bps, efektif eşikler, eşiğe oran (ratio), baseline (hazır mı, değeri), ardışık aşım saniyesi, koşul durumu ve son 60 sn + dakikalık geçmiş. 'Dedektör neden tetiklenmedi?' sorusunun cevabı buradadır.",
			Properties: map[string]any{
				"ip":              map[string]any{"type": "string", "description": "Hedef IP (korunan alanda olmalı)"},
				"rule_id":         map[string]any{"type": "string", "description": "Opsiyonel: tek bir kural"},
				"include_history": map[string]any{"type": "boolean", "description": "Saniyelik/dakikalık seriyi ekle (varsayılan false)"},
			},
			Required: []string{"ip"},
			Run: func(ctx context.Context, raw json.RawMessage) (any, error) {
				in, err := decode[struct {
					IP      string `json:"ip"`
					RuleID  string `json:"rule_id"`
					History bool   `json:"include_history"`
				}](raw)
				if err != nil {
					return nil, err
				}
				a, err := netip.ParseAddr(in.IP)
				if err != nil {
					return nil, fmt.Errorf("geçersiz IP %q", in.IP)
				}
				st, err := eng.TargetState(a, in.RuleID, in.History)
				if err != nil {
					return nil, err
				}
				if len(st) == 0 {
					return map[string]any{"note": "Bu hedef için pencere içinde eşleşen kural serisi yok (trafik yok veya korunan alan dışında)."}, nil
				}
				return st, nil
			},
		},
		{
			Name:        "get_timeseries",
			Description: "Global veya nesne bazlı trafik zaman serisi (inbound/outbound bps, pps ve protokol kırılımı). Saldırının ne zaman başladığını ve trendi görmek için kullanın.",
			Properties: map[string]any{
				"object_name":   map[string]any{"type": "string", "description": "Boşsa global"},
				"range_seconds": map[string]any{"type": "integer", "description": "Geriye dönük süre (varsayılan 900, max 86400)"},
				"points":        map[string]any{"type": "integer", "description": "Nokta sayısı (varsayılan 30, max 60)"},
			},
			Run: func(ctx context.Context, raw json.RawMessage) (any, error) {
				in, err := decode[struct {
					Object string `json:"object_name"`
					Range  int64  `json:"range_seconds"`
					Points int64  `json:"points"`
				}](raw)
				if err != nil {
					return nil, err
				}
				if in.Range <= 0 {
					in.Range = 900
				}
				if in.Range > 86400 {
					in.Range = 86400
				}
				if in.Points <= 0 || in.Points > 60 {
					in.Points = 30
				}
				obj := -1
				if in.Object != "" {
					o := eng.ObjectByName(in.Object)
					if o == nil {
						return nil, fmt.Errorf("bilinmeyen nesne %q", in.Object)
					}
					obj = int(o.ID)
				}
				step := in.Range / in.Points
				if step < 1 {
					step = 1
				}
				return eng.Totals().Series(obj, time.Now().Unix(), in.Range, step), nil
			},
		},
		{
			Name:        "top_n",
			Description: "Son flow kayıtlarından seçilen boyuta göre top-N (örnekleme ile ölçeklenmiş bps/pps/fps ve pay). Boyutlar: src_ip, dst_ip, src_port, dst_port, protocol, tcp_flags, packet_size, src_net, dst_net, exporter, in_if, src_as, icmp_type, direction, object, fragment.",
			Properties: map[string]any{
				"dimension": map[string]any{"type": "string", "enum": flowstore.Dimensions},
				"metric":    map[string]any{"type": "string", "enum": []string{"bps", "pps", "fps"}},
				"filter":    filterSchema,
				"limit":     map[string]any{"type": "integer", "description": "Varsayılan 10, max 25"},
			},
			Required: []string{"dimension"},
			Run: func(ctx context.Context, raw json.RawMessage) (any, error) {
				in, err := decode[struct {
					Dimension string   `json:"dimension"`
					Metric    string   `json:"metric"`
					Filter    filterIn `json:"filter"`
					Limit     int      `json:"limit"`
				}](raw)
				if err != nil {
					return nil, err
				}
				f, err := in.Filter.resolve(eng)
				if err != nil {
					return nil, err
				}
				if in.Limit <= 0 || in.Limit > 25 {
					in.Limit = 10
				}
				return eng.Store().TopN(f, nil, in.Dimension, in.Metric, in.Limit, eng.ObjectName)
			},
		},
		{
			Name:        "traffic_breakdown",
			Description: "Filtreye uyan trafiğin çok boyutlu özeti: toplam bps/pps, ortalama paket boyu, benzersiz kaynak/hedef, fragment payı, protokoller, paket boyu histogramı, TCP flag dağılımı, top kaynaklar/hedefler/portlar/kaynak ağları, exporter'lar, örnekleme oranları.",
			Properties:  map[string]any{"filter": filterSchema},
			Run: func(ctx context.Context, raw json.RawMessage) (any, error) {
				in, err := decode[struct {
					Filter filterIn `json:"filter"`
				}](raw)
				if err != nil {
					return nil, err
				}
				f, err := in.Filter.resolve(eng)
				if err != nil {
					return nil, err
				}
				return eng.Store().Breakdown(f, nil, 8)
			},
		},
		{
			Name:        "sample_flows",
			Description: "Filtreye uyan en yeni ham flow kayıtlarından örnek (en fazla 30). Sadece desen doğrulamak için; istatistik için top_n/traffic_breakdown kullanın.",
			Properties: map[string]any{
				"filter": filterSchema,
				"limit":  map[string]any{"type": "integer", "description": "Varsayılan 15, max 30"},
			},
			Run: func(ctx context.Context, raw json.RawMessage) (any, error) {
				in, err := decode[struct {
					Filter filterIn `json:"filter"`
					Limit  int      `json:"limit"`
				}](raw)
				if err != nil {
					return nil, err
				}
				f, err := in.Filter.resolve(eng)
				if err != nil {
					return nil, err
				}
				if in.Limit <= 0 || in.Limit > 30 {
					in.Limit = 15
				}
				return eng.Store().Samples(f, nil, in.Limit)
			},
		},
		{
			Name:        "get_incidents",
			Description: "Olay listesi (özet) veya id verilirse tek olayın detayı (vektörler, tetik nedenleri, kanıt kırılımı, mitigasyon id'leri).",
			Properties: map[string]any{
				"id":     map[string]any{"type": "string"},
				"status": map[string]any{"type": "string", "enum": []string{"active", "ended", ""}},
				"limit":  map[string]any{"type": "integer"},
			},
			Run: func(ctx context.Context, raw json.RawMessage) (any, error) {
				in, err := decode[struct {
					ID     string `json:"id"`
					Status string `json:"status"`
					Limit  int    `json:"limit"`
				}](raw)
				if err != nil {
					return nil, err
				}
				if in.ID != "" {
					inc := eng.Incidents().Get(in.ID)
					if inc == nil {
						return nil, fmt.Errorf("olay bulunamadı")
					}
					inc.Series = downsample(inc.Series, 40)
					if inc.Evidence != nil {
						ev := *inc.Evidence
						if len(ev.Samples) > 10 {
							ev.Samples = ev.Samples[:10]
						}
						inc.Evidence = &ev
					}
					return inc, nil
				}
				if in.Limit <= 0 || in.Limit > 30 {
					in.Limit = 10
				}
				return eng.Incidents().List(in.Status, in.Limit), nil
			},
		},
		{
			Name:        "get_rule",
			Description: "Bir kuralın tanımı (eşleşme kriterleri, eşikler, baseline, koşullar, mitigasyon şablonu, gerekçe, false-positive notları) ve korunan nesnelere göre efektif eşikleri.",
			Properties: map[string]any{
				"rule_id": map[string]any{"type": "string"},
			},
			Required: []string{"rule_id"},
			Run: func(ctx context.Context, raw json.RawMessage) (any, error) {
				in, err := decode[struct {
					RuleID string `json:"rule_id"`
				}](raw)
				if err != nil {
					return nil, err
				}
				c := eng.Rules().ByID[in.RuleID]
				if c == nil {
					return nil, fmt.Errorf("bilinmeyen kural %q", in.RuleID)
				}
				eff := map[string]any{}
				for _, o := range eng.Objects() {
					t, ok := eng.EffectiveThresholds(c.ID, o.ID)
					eff[o.Name] = map[string]any{"enabled": ok, "profile": o.Profile, "pps": t.PPS, "bps": t.BPS, "fps": t.FPS}
				}
				return map[string]any{
					"rule": c.Rule, "match_summary": c.MatchSummary(), "sustain_seconds": c.SustainSec,
					"hold_down_seconds": c.HoldDownSec, "active": c.Active, "effective_by_object": eff,
				}, nil
			},
		},
		{
			Name:        "get_object_context",
			Description: "Korunan nesnenin bağlamı: prefixler, profil (ve profilin kural ayarları), bağlantı kapasitesi, operatör notları, canlı oranlar.",
			Properties: map[string]any{
				"object_name": map[string]any{"type": "string"},
			},
			Required: []string{"object_name"},
			Run: func(ctx context.Context, raw json.RawMessage) (any, error) {
				in, err := decode[struct {
					Object string `json:"object_name"`
				}](raw)
				if err != nil {
					return nil, err
				}
				o := eng.ObjectByName(in.Object)
				if o == nil {
					return nil, fmt.Errorf("bilinmeyen nesne %q", in.Object)
				}
				var live engine.ObjectStatus
				for _, s := range eng.Snapshot().Objects {
					if s.ID == o.ID {
						live = s
					}
				}
				return map[string]any{
					"object": o, "profile": eng.Rules().Profiles[o.Profile],
					"live": live.Rates, "utilization": live.Utilization,
					"notes_untrusted": o.Notes,
				}, nil
			},
		},
		{
			Name: submitTool,
			Description: "Analizi bitirip yapılandırılmış bulguyu gönderir. Her çalışmada TAM OLARAK BİR KEZ, en sonda çağrılmalıdır. " +
				"Bulgudaki her sayısal iddia bir araç çıktısına dayanmalı ve evidence listesinde kaynağıyla yer almalıdır.",
			Properties: map[string]any{
				"title":          map[string]any{"type": "string", "description": "Kısa başlık (hedef + ne oldu)"},
				"summary":        map[string]any{"type": "string", "description": "3-6 cümlelik yönetici özeti"},
				"classification": map[string]any{"type": "string", "enum": []string{"attack", "suspicious", "benign", "misconfiguration", "unknown"}},
				"severity":       map[string]any{"type": "string", "enum": []string{"info", "low", "medium", "high", "critical"}},
				"confidence":     map[string]any{"type": "number", "description": "0..1"},
				"targets":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"hypothesis":     map[string]any{"type": "string", "description": "Ne olduğuna dair en olası açıklama ve alternatifler"},
				"missed_reason":  map[string]any{"type": "string", "description": "Dedektör neden alarm vermedi / geç verdi (eşik, kapsam, koşul, baseline)"},
				"evidence": map[string]any{"type": "array", "items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"claim":  map[string]any{"type": "string"},
						"source": map[string]any{"type": "string", "description": "Hangi araç ve parametre (ör. top_n dimension=src_port dst=198.51.100.10)"},
					},
					"required": []string{"claim", "source"},
				}},
				"recommendations": map[string]any{"type": "array", "items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"type":    map[string]any{"type": "string", "enum": []string{"threshold_change", "new_rule", "flowspec", "scrub", "rtbh", "whitelist", "investigate", "no_action"}},
						"title":   map[string]any{"type": "string"},
						"detail":  map[string]any{"type": "string"},
						"rule_id": map[string]any{"type": "string"},
						"flowspec": map[string]any{"type": "object", "properties": map[string]any{
							"target": map[string]any{"type": "string"}, "direction": map[string]any{"type": "string", "enum": []string{"inbound", "outbound"}},
							"protocol": map[string]any{"type": "string"}, "src_ports": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}},
							"dst_ports": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}}, "min_packet_length": map[string]any{"type": "integer"},
							"action": map[string]any{"type": "string", "enum": []string{"discard", "rate-limit"}}, "rate_bps": map[string]any{"type": "number"},
						}},
						"threshold": map[string]any{"type": "object", "properties": map[string]any{
							"rule_id": map[string]any{"type": "string"}, "profile": map[string]any{"type": "string"},
							"pps": map[string]any{"type": "number"}, "bps": map[string]any{"type": "number"},
						}},
					},
					"required": []string{"type", "title", "detail"},
				}},
				"signal_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Bu bulgunun kapsadığı sinyal id'leri"},
			},
			Required: []string{"title", "summary", "classification", "severity", "confidence", "evidence", "recommendations"},
		},
	}
}

func downsample(pts []engine.Point, n int) []engine.Point {
	if len(pts) <= n {
		return pts
	}
	step := float64(len(pts)) / float64(n)
	out := make([]engine.Point, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, pts[int(float64(i)*step)])
	}
	return out
}
