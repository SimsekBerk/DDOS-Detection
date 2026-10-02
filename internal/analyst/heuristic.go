package analyst

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/SimsekBerk/DDOS-Detection/internal/engine"
	"github.com/SimsekBerk/DDOS-Detection/internal/flowstore"
)

// heuristicProvider is a deterministic, LLM-free analyst. It follows the same
// tool protocol (so traces look identical in the UI) and produces templated
// findings. It makes the demo fully functional without any model access.
type heuristicProvider struct{}

func (heuristicProvider) Name() string  { return "heuristic" }
func (heuristicProvider) Model() string { return "rule-based" }

type taskKey struct{}

// task describes what the current run is about (read by the heuristic provider).
type task struct {
	Mode       string
	SignalIDs  []string
	IncidentID string
	Question   string
}

func withTask(ctx context.Context, t task) context.Context {
	return context.WithValue(ctx, taskKey{}, t)
}

func call[T any](ctx context.Context, exec Executor, turn int, name string, in any) (T, error) {
	var v T
	raw, _ := json.Marshal(in)
	out, isErr, _ := exec(ctx, turn, name, raw)
	if isErr {
		return v, errors.New(out)
	}
	err := json.Unmarshal([]byte(out), &v)
	return v, err
}

func (h heuristicProvider) Run(ctx context.Context, _, _ string, _ []Tool, _ int, exec Executor) (Usage, error) {
	t, _ := ctx.Value(taskKey{}).(task)
	var f map[string]any
	var err error
	switch t.Mode {
	case "incident":
		f, err = h.incident(ctx, exec, t.IncidentID)
	case "question":
		f = map[string]any{
			"title": "Serbest soru heuristic modda desteklenmiyor", "classification": "unknown", "severity": "info", "confidence": 1,
			"summary":  "Kural tabanlı analist yalnızca aday sinyal ve olay analizleri üretir. Serbest sorular için analyst.provider olarak 'anthropic' veya yerel bir 'openai_compat' modeli yapılandırın.",
			"evidence": []any{}, "recommendations": []any{map[string]any{"type": "no_action", "title": "LLM sağlayıcısı yapılandırın", "detail": "config.yaml → analyst.provider"}},
		}
	default:
		f, err = h.signals(ctx, exec, t.SignalIDs)
	}
	if err != nil {
		return Usage{Turns: 1}, err
	}
	raw, _ := json.Marshal(f)
	_, isErr, done := exec(ctx, 9, submitTool, raw)
	if isErr || !done {
		return Usage{Turns: 1}, errors.New("heuristic finding rejected")
	}
	return Usage{Turns: 1}, nil
}

func kindPriority(k string) int {
	switch k {
	case "conditions_unmet":
		return 3
	case "near_threshold":
		return 2
	}
	return 1
}

func (h heuristicProvider) signals(ctx context.Context, exec Executor, ids []string) (map[string]any, error) {
	if _, err := call[map[string]any](ctx, exec, 1, "get_overview", map[string]any{}); err != nil {
		return nil, err
	}
	sigs, err := call[[]engine.Signal](ctx, exec, 2, "list_candidate_signals", map[string]any{"only_pending": len(ids) == 0, "limit": 50})
	if err != nil {
		return nil, err
	}
	if len(ids) > 0 {
		want := map[string]bool{}
		for _, id := range ids {
			want[id] = true
		}
		var sel []engine.Signal
		for _, s := range sigs {
			if want[s.ID] {
				sel = append(sel, s)
			}
		}
		sigs = sel
	}
	if len(sigs) == 0 {
		return map[string]any{
			"title": "Bekleyen aday sinyal yok", "classification": "benign", "severity": "info", "confidence": 0.9,
			"summary":         "İncelenecek eşik altı sapma veya koşulu sağlanmamış tetik bulunmuyor. Ağ normal görünüyor.",
			"evidence":        []any{map[string]any{"claim": "Bekleyen sinyal sayısı 0", "source": "list_candidate_signals only_pending=true"}},
			"recommendations": []any{map[string]any{"type": "no_action", "title": "Aksiyon gerekmiyor", "detail": "Periyodik izleme devam ediyor."}},
		}, nil
	}
	sort.Slice(sigs, func(i, j int) bool {
		// Signals already explained by an active incident come last.
		if (sigs[i].RelatedIncident == "") != (sigs[j].RelatedIncident == "") {
			return sigs[i].RelatedIncident == ""
		}
		if kindPriority(sigs[i].Kind) != kindPriority(sigs[j].Kind) {
			return kindPriority(sigs[i].Kind) > kindPriority(sigs[j].Kind)
		}
		return sigs[i].PeakRatio+sigs[i].PeakZ/10 > sigs[j].PeakRatio+sigs[j].PeakZ/10
	})
	top := sigs[0]
	var related []string
	for _, s := range sigs {
		if s.Target == top.Target {
			related = append(related, s.ID)
		}
	}

	filter := map[string]any{"seconds": 120}
	key := "dst"
	if top.Direction == "outbound" {
		key = "src"
		filter["direction"] = "outbound"
	} else {
		filter["direction"] = "inbound"
	}
	filter[key] = top.Target
	evidence := []map[string]any{{
		"claim":  fmt.Sprintf("%s kuralı için %s hedefinde %s sinyali: tepe %s / %s, eşiğe oran %.2f, z=%.1f, %d sn gözlendi", top.RuleID, top.Target, top.Kind, hpps(top.PeakPPS), hbps(top.PeakBPS), top.PeakRatio, top.PeakZ, top.Seconds),
		"source": "list_candidate_signals",
	}}

	var states []engine.TargetRuleState
	if a, err := netip.ParseAddr(top.Target); err == nil {
		states, _ = call[[]engine.TargetRuleState](ctx, exec, 3, "get_target_state", map[string]any{"ip": a.String(), "rule_id": top.RuleID})
	}
	bd, _ := call[flowstore.Breakdown](ctx, exec, 4, "traffic_breakdown", map[string]any{"filter": filter})
	ports, _ := call[flowstore.TopResult](ctx, exec, 5, "top_n", map[string]any{"dimension": "src_port", "metric": "bps", "filter": filter, "limit": 5})
	rule, _ := call[map[string]any](ctx, exec, 6, "get_rule", map[string]any{"rule_id": top.RuleID})

	if bd.Records > 0 {
		evidence = append(evidence, map[string]any{
			"claim":  fmt.Sprintf("Son 120 sn: %s, %s, ortalama paket %.0f B, %d benzersiz kaynak, fragment payı %%%.0f", hbps(bd.TotalBPS), hpps(bd.TotalPPS), bd.AvgPacketSize, bd.UniqueSrc, bd.FragmentShare*100),
			"source": fmt.Sprintf("traffic_breakdown %s=%s seconds=120", key, top.Target),
		})
	}
	topPort, topShare := "", 0.0
	if len(ports.Rows) > 0 {
		topPort, topShare = ports.Rows[0].Key, ports.Rows[0].Share
		evidence = append(evidence, map[string]any{
			"claim":  fmt.Sprintf("Baskın kaynak port %s (bps payı %%%.0f)", topPort, topShare*100),
			"source": fmt.Sprintf("top_n dimension=src_port %s=%s", key, top.Target),
		})
	}
	var st *engine.TargetRuleState
	for i := range states {
		if states[i].RuleID == top.RuleID && states[i].Target == top.Target {
			st = &states[i]
		}
	}
	if st != nil {
		evidence = append(evidence, map[string]any{
			"claim":  fmt.Sprintf("Efektif eşik: %s / %s; şu an oran %.2f, baseline hazır=%v (%s), koşul: %s", hpps(st.ThresholdPPS), hbps(st.ThresholdBPS), st.Ratio, st.BaselineReady, hpps(st.BaselinePPS), st.Conditions),
			"source": fmt.Sprintf("get_target_state ip=%s rule_id=%s", top.Target, top.RuleID),
		})
	}

	category := ""
	if r, ok := rule["rule"].(map[string]any); ok {
		category, _ = r["category"].(string)
	}
	f := map[string]any{"targets": []string{top.Target}, "signal_ids": related, "evidence": evidence}
	var recs []map[string]any
	severity, class, conf := "low", "suspicious", 0.55
	switch top.Kind {
	case "conditions_unmet":
		severity, conf = "medium", 0.6
		f["title"] = fmt.Sprintf("%s: %s hacim eşiği aşıldı, doğrulama koşulu sağlanmadı", top.Target, top.RuleName)
		f["missed_reason"] = fmt.Sprintf("Hacim eşiği aşıldı (oran %.2f) ama kuralın doğrulama koşulu sağlanmadığı için olay açılmadı: %s.", top.PeakRatio, top.Condition)
		switch {
		case strings.Contains(top.Condition, "benzersiz hedef"):
			f["hypothesis"] = "Trafik prefix içinde az sayıda hosta yoğunlaşmış; bu bir carpet bombing değil, tek hedefli bir saldırının prefix toplamına yansıması olabilir."
			recs = append(recs, map[string]any{"type": "investigate", "title": "Host seviyesindeki olaylarla ilişkilendirin", "detail": "Aynı prefix'teki aktif host olaylarını kontrol edin; prefix kuralının tetiklenmemesi beklenen davranıştır."})
		case strings.Contains(top.Condition, "benzersiz kaynak"):
			f["hypothesis"] = "Yüksek hacim az sayıda kaynaktan geliyor; klasik yansıtma (yüzlerce/binlerce yansıtıcı) değil. Doğrudan saldırı, tek bir istismar edilen sunucu veya meşru büyük bir transfer olabilir."
			recs = append(recs, map[string]any{"type": "investigate", "title": "Kaynakları doğrulayın", "detail": "top_n src_ip ile kaynakların kime ait olduğunu kontrol edin; tanıdık bir servis değilse kaynak bazlı rate-limit uygulayın."})
		case strings.Contains(top.Condition, "paket"):
			f["hypothesis"] = "Paket boyu dağılımı kuralın imzasıyla uyuşmuyor; farklı bir vektör veya meşru trafik olabilir."
			recs = append(recs, map[string]any{"type": "investigate", "title": "Paket boyu dağılımını inceleyin", "detail": "traffic_breakdown packet_sizes alanına göre doğru kuralı belirleyin."})
		default:
			f["hypothesis"] = "Örnek sayısı az; örnekleme oranı yüksek olabilir. Karar vermek için daha fazla veri gerekiyor."
			recs = append(recs, map[string]any{"type": "investigate", "title": "Örnekleme oranını kontrol edin", "detail": "Exporter sayfasında örnekleme ve kayıp oranlarını doğrulayın."})
		}
		if top.RelatedIncident != "" {
			severity, class = "low", "benign"
			f["hypothesis"] = f["hypothesis"].(string) + fmt.Sprintf(" İlişkili aktif olay: %s.", top.RelatedIncident)
		}
	case "near_threshold":
		f["title"] = fmt.Sprintf("%s: %s eşiğin altında devam ediyor", top.Target, top.RuleName)
		f["missed_reason"] = fmt.Sprintf("Trafik efektif eşiğin %%%.0f seviyesinde kaldı; statik eşik bu hedef için yüksek olabilir.", top.PeakRatio*100)
		f["hypothesis"] = "Eşiği bilerek aşmayan düşük yoğunluklu (low-and-slow) bir saldırı veya artan meşru trafik."
		if st != nil && st.ThresholdPPS > 0 && top.PeakPPS > 0 {
			newPPS := top.PeakPPS * 0.8
			recs = append(recs, map[string]any{
				"type": "threshold_change", "title": fmt.Sprintf("%s eşiğini düşür", top.RuleID), "rule_id": top.RuleID,
				"detail":    fmt.Sprintf("Mevcut efektif eşik %s; gözlenen tepe %s. Bu nesne için %s (tepenin %%80'i) önerilir.", hpps(st.ThresholdPPS), hpps(top.PeakPPS), hpps(newPPS)),
				"threshold": map[string]any{"rule_id": top.RuleID, "pps": newPPS},
			})
		}
	default:
		f["title"] = fmt.Sprintf("%s: %s trafiğinde baseline sapması", top.Target, top.RuleName)
		f["missed_reason"] = "Trafik baseline'ın belirgin üstünde ama statik eşiğin ve baseline tetik seviyesinin (factor × baseline) altında."
		f["hypothesis"] = "Kademeli artan bir saldırı (ramp-up) veya yeni bir meşru servis/trafik deseni."
		if top.PeakZ >= 6 {
			severity = "medium"
		} else {
			class = "unknown"
		}
	}
	if category == "reflection_amplification" || category == "carpet_bombing" {
		severity = "medium"
		if p := portNumber(topPort); p > 0 && topShare >= 0.5 {
			recs = append(recs, map[string]any{
				"type": "flowspec", "title": fmt.Sprintf("Kaynak port %d için FlowSpec", p),
				"detail":   "Yansıtma imzası baskın; hedefe yönelik dar FlowSpec kuralı (onay gerektirir).",
				"flowspec": map[string]any{"target": top.Target, "direction": top.Direction, "protocol": "udp", "src_ports": []int{p}, "action": "discard"},
			})
		}
	}
	if len(recs) == 0 {
		recs = append(recs, map[string]any{"type": "investigate", "title": "İzlemeye devam", "detail": "Sinyal sürerse olay olarak ele alın; trafiği flow explorer'da inceleyin."})
	}
	f["classification"], f["severity"], f["confidence"] = class, severity, conf
	relatedNote := ""
	if top.RelatedIncident != "" {
		relatedNote = fmt.Sprintf(" Bu hedefle ilişkili aktif olay var (%s).", top.RelatedIncident)
	}
	f["summary"] = fmt.Sprintf("%s (%s) hedefinde %s kuralı için %s sinyali %d saniye gözlendi; tepe %s / %s, efektif eşiğe oran %.2f. %s %s%s",
		top.Target, top.ObjectName, top.RuleName, kindLabel(top.Kind), top.Seconds, hpps(top.PeakPPS), hbps(top.PeakBPS), top.PeakRatio,
		f["missed_reason"], dominant(topPort, topShare), relatedNote)
	f["recommendations"] = recs
	return f, nil
}

func (h heuristicProvider) incident(ctx context.Context, exec Executor, id string) (map[string]any, error) {
	inc, err := call[engine.Incident](ctx, exec, 1, "get_incidents", map[string]any{"id": id})
	if err != nil {
		return nil, err
	}
	filter := map[string]any{"seconds": 300, "direction": inc.Direction}
	if inc.Direction == "outbound" {
		filter["src"] = inc.Target
	} else {
		filter["dst"] = inc.Target
	}
	if inc.Scope == "object" {
		delete(filter, "dst")
		delete(filter, "src")
		filter["object_name"] = inc.ObjectName
	}
	bd, _ := call[flowstore.Breakdown](ctx, exec, 2, "traffic_breakdown", map[string]any{"filter": filter})
	var vecs []string
	sev := inc.Severity
	for _, v := range inc.Vectors {
		vecs = append(vecs, fmt.Sprintf("%s (%s, tepe %s / %s)", v.RuleName, v.Reason, hpps(v.PeakPPS), hbps(v.PeakBPS)))
	}
	dur := inc.UpdatedAt - inc.StartedAt
	if inc.EndedAt > 0 {
		dur = inc.EndedAt - inc.StartedAt
	}
	evidence := []map[string]any{{"claim": fmt.Sprintf("%d vektör, tepe %s / %s, süre %d sn", len(inc.Vectors), hbps(inc.PeakBPS), hpps(inc.PeakPPS), dur), "source": "get_incidents id=" + id}}
	character := "bilinmiyor"
	if bd.Records > 0 {
		character = fmt.Sprintf("%d benzersiz kaynak, ortalama paket %.0f B, fragment payı %%%.0f", bd.UniqueSrc, bd.AvgPacketSize, bd.FragmentShare*100)
		evidence = append(evidence, map[string]any{"claim": character, "source": "traffic_breakdown seconds=300 target=" + inc.Target})
	}
	recs := []map[string]any{}
	for _, v := range inc.Vectors {
		switch v.Mitigation {
		case "flowspec-discard", "flowspec-rate-limit":
			recs = append(recs, map[string]any{"type": "investigate", "title": v.RuleName + ": FlowSpec etkisini doğrulayın", "rule_id": v.RuleID,
				"detail": fmt.Sprintf("Kural şablonundan oluşturulan FlowSpec önerisi mitigasyon kuyruğunda (%s). Onaylandıysa olay serisinde trafiğin düştüğünü doğrulayın.", strings.Join(inc.Mitigations, ", "))})
		case "scrub":
			recs = append(recs, map[string]any{"type": "scrub", "title": v.RuleName + " için scrubbing", "rule_id": v.RuleID,
				"detail": "Bu vektörde FlowSpec discard meşru trafiğe zarar verir; SYN cookie/proxy destekli scrubbing'e yönlendirme önerilir."})
		}
	}
	if len(inc.Mitigations) == 0 {
		recs = append(recs, map[string]any{"type": "investigate", "title": "Mitigasyon uygulanmadı", "detail": "Bu olay için hiçbir mitigasyon kaydı yok; politika (mode) ve kural mitigasyon aksiyonlarını gözden geçirin."})
	}
	return map[string]any{
		"title":          fmt.Sprintf("Olay raporu %s: %s (%s)", id, inc.Target, inc.ObjectName),
		"classification": "attack", "severity": sev, "confidence": 0.8, "targets": []string{inc.Target},
		"summary": fmt.Sprintf("%s hedefine %d vektörlü saldırı (%s). Tepe %s / %s, süre %d sn. Saldırı karakteri: %s. Vektörler: %s.",
			inc.Target, len(inc.Vectors), inc.Status, hbps(inc.PeakBPS), hpps(inc.PeakPPS), dur, character, strings.Join(vecs, "; ")),
		"hypothesis":      "Vektör kombinasyonu ve kaynak sayısı saldırının yansıtma mı yoksa botnet kaynaklı mı olduğunu gösterir; benzersiz kaynak sayısı yüksek ve kaynak portlar sabitse yansıtmadır.",
		"missed_reason":   "Olay dedektör tarafından yakalandı; tetik nedenleri vektörlerde listelenmiştir.",
		"evidence":        evidence,
		"recommendations": recs,
	}, nil
}

func portNumber(key string) int {
	if i := strings.LastIndex(key, "/"); i > 0 {
		n, _ := strconv.Atoi(key[i+1:])
		return n
	}
	return 0
}

func dominant(port string, share float64) string {
	if port == "" {
		return ""
	}
	return fmt.Sprintf("Trafiğin %%%.0f'i %s kaynak portundan geliyor.", share*100, port)
}

func kindLabel(k string) string {
	switch k {
	case "conditions_unmet":
		return "koşulu sağlanmamış tetik"
	case "near_threshold":
		return "eşiğe yakın"
	}
	return "baseline sapması"
}

func hbps(v float64) string { return human(v, "bps") }
func hpps(v float64) string { return human(v, "pps") }

func human(v float64, unit string) string {
	switch {
	case v >= 1e9:
		return fmt.Sprintf("%.2f G%s", v/1e9, unit)
	case v >= 1e6:
		return fmt.Sprintf("%.2f M%s", v/1e6, unit)
	case v >= 1e3:
		return fmt.Sprintf("%.1f k%s", v/1e3, unit)
	}
	return fmt.Sprintf("%.0f %s", v, unit)
}
