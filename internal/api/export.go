package api

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/SimsekBerk/DDOS-Detection/internal/auth"
	"github.com/SimsekBerk/DDOS-Detection/internal/flowstore"
)

func fmtTime(t int64) string {
	if t == 0 {
		return ""
	}
	return time.Unix(t, 0).Format("2006-01-02 15:04:05")
}

func fmtRate(v float64, unit string) string {
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

// incidentsCSV exports incidents for reporting tools / spreadsheets.
func (s *Server) incidentsCSV(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=olaylar-%s.csv", time.Now().Format("20060102-1504")))
	_, _ = w.Write([]byte("\xEF\xBB\xBF")) // UTF-8 BOM for Excel
	cw := csv.NewWriter(w)
	cw.Comma = ';'
	_ = cw.Write([]string{"olay", "durum", "önem", "hedef", "kapsam", "yön", "nesne", "başlangıç", "bitiş", "süre_sn", "tepe_bps", "tepe_pps", "vektörler", "mitigasyonlar"})
	for _, inc := range s.app.Eng.Incidents().List(r.URL.Query().Get("status"), 0) {
		if !u.AllowsObject(inc.ObjectName) {
			continue
		}
		end := inc.EndedAt
		if end == 0 {
			end = time.Now().Unix()
		}
		var vecs []string
		for _, v := range inc.Vectors {
			vecs = append(vecs, v.RuleID)
		}
		_ = cw.Write([]string{inc.ID, inc.Status, inc.Severity, inc.Target, inc.Scope, inc.Direction, inc.ObjectName,
			fmtTime(inc.StartedAt), fmtTime(inc.EndedAt), strconv.FormatInt(end-inc.StartedAt, 10),
			strconv.FormatFloat(inc.PeakBPS, 'f', 0, 64), strconv.FormatFloat(inc.PeakPPS, 'f', 0, 64),
			strings.Join(vecs, ","), strings.Join(inc.Mitigations, ",")})
	}
	cw.Flush()
	return nil, nil
}

func writeRows(b *strings.Builder, title string, rows []flowstore.Row) {
	if len(rows) == 0 {
		return
	}
	fmt.Fprintf(b, "\n**%s**\n\n| | bps | pps | pay |\n|---|---|---|---|\n", title)
	for _, r := range rows {
		fmt.Fprintf(b, "| `%s` | %s | %s | %%%.1f |\n", r.Key, fmtRate(r.BPS, "bps"), fmtRate(r.PPS, "pps"), r.Share*100)
	}
}

// incidentReport renders a Markdown incident report (for tickets / customers).
func (s *Server) incidentReport(w http.ResponseWriter, r *http.Request, u *auth.User) (any, error) {
	inc, err := s.getIncident(u, r.PathValue("id"))
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	end := inc.EndedAt
	if end == 0 {
		end = time.Now().Unix()
	}
	fmt.Fprintf(&b, "# Olay raporu %s\n\n", inc.ID)
	fmt.Fprintf(&b, "| Alan | Değer |\n|---|---|\n")
	fmt.Fprintf(&b, "| Hedef | `%s` (%s, %s) |\n| Nesne | %s (%s profili) |\n", inc.Target, inc.Scope, inc.Direction, inc.ObjectName, inc.Profile)
	fmt.Fprintf(&b, "| Durum / önem | %s / %s |\n| Başlangıç | %s |\n| Bitiş | %s |\n| Süre | %s |\n", inc.Status, inc.Severity, fmtTime(inc.StartedAt), fmtTime(inc.EndedAt), (time.Duration(end-inc.StartedAt) * time.Second).String())
	fmt.Fprintf(&b, "| Tepe | %s / %s |\n\n", fmtRate(inc.PeakBPS, "bps"), fmtRate(inc.PeakPPS, "pps"))
	fmt.Fprintf(&b, "## Vektörler\n\n| Kural | Tetik nedeni | Tepe | Başlangıç | Bitiş |\n|---|---|---|---|---|\n")
	for _, v := range inc.Vectors {
		fmt.Fprintf(&b, "| %s (`%s`) | %s | %s / %s | %s | %s |\n", v.RuleName, v.RuleID, v.Reason, fmtRate(v.PeakBPS, "bps"), fmtRate(v.PeakPPS, "pps"), fmtTime(v.StartedAt), fmtTime(v.EndedAt))
	}
	if ev := inc.Evidence; ev != nil && ev.Breakdown != nil {
		bd := ev.Breakdown
		fmt.Fprintf(&b, "\n## Kanıt (son %d sn, %s)\n\n", bd.Seconds, fmtTime(ev.ComputedAt))
		fmt.Fprintf(&b, "- Toplam: %s / %s, ortalama paket %.0f B\n- Benzersiz kaynak: %d, fragment payı %%%.0f\n", fmtRate(bd.TotalBPS, "bps"), fmtRate(bd.TotalPPS, "pps"), bd.AvgPacketSize, bd.UniqueSrc, bd.FragmentShare*100)
		writeRows(&b, "Top kaynak IP", bd.TopSources)
		writeRows(&b, "Top kaynak port", bd.TopSrcPorts)
		writeRows(&b, "Top kaynak ağ", bd.TopSrcNets)
		writeRows(&b, "Protokol", bd.Protocols)
	}
	var mitLines []string
	for _, id := range inc.Mitigations {
		if m := s.app.Mit.Get(id); m != nil {
			mitLines = append(mitLines, fmt.Sprintf("| %s | %s | %s | %s | %s |", m.ID, m.Kind, m.Status, m.Target, strings.ReplaceAll(m.Reason, "|", "/")))
		}
	}
	if len(mitLines) > 0 {
		sort.Strings(mitLines)
		fmt.Fprintf(&b, "\n## Mitigasyonlar\n\n| ID | Tür | Durum | Hedef | Gerekçe |\n|---|---|---|---|---|\n%s\n", strings.Join(mitLines, "\n"))
	}
	if !u.Scoped() {
		for _, id := range inc.Findings {
			if f := s.app.Ana.Get(id); f != nil && f.Status == "ok" {
				fmt.Fprintf(&b, "\n## AI analist bulgusu %s\n\n**%s** (%s, güven %%%.0f)\n\n%s\n", f.ID, f.Title, f.Classification, f.Confidence*100, f.Summary)
			}
		}
	}
	fmt.Fprintf(&b, "\n---\nddosd %s tarafından %s tarihinde oluşturuldu.\n", Version, time.Now().Format("2006-01-02 15:04"))
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.md", inc.ID))
	_, _ = w.Write([]byte(b.String()))
	return nil, nil
}
