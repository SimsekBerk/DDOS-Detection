package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// metrics exposes Prometheus text-format metrics. Requires an unscoped
// user (session or Bearer API token).
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	u, ok := s.authenticate(r)
	if !ok || u.Scoped() {
		w.Header().Set("WWW-Authenticate", `Bearer realm="ddosd"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var b strings.Builder
	metric := func(name, typ, help string, samples ...string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
		for _, s := range samples {
			fmt.Fprintf(&b, "%s%s\n", name, s)
		}
	}
	val := func(labels string, v float64) string {
		if labels != "" {
			labels = "{" + labels + "}"
		}
		return fmt.Sprintf("%s %g", labels, v)
	}
	snap := s.app.Eng.Snapshot()
	metric("ddosd_up", "gauge", "1 if the process is running", val("", 1))
	metric("ddosd_uptime_seconds", "gauge", "Process uptime", val("", float64(time.Now().Unix()-s.app.Started)))
	metric("ddosd_flow_records_total", "counter", "Flow records ingested", val("", float64(snap.RecordsTotal)))
	metric("ddosd_flow_records_per_second", "gauge", "Ingest rate", val("", snap.RecordsPerSec))
	metric("ddosd_engine_dropped_records_total", "counter", "Records dropped because the engine queue was full", val("", float64(snap.Dropped)))
	metric("ddosd_collector_dropped_datagrams_total", "counter", "Datagrams dropped because a worker queue was full", val("", float64(s.app.Col.Dropped())))
	metric("ddosd_collector_rejected_datagrams_total", "counter", "Datagrams from exporters outside the allowlist", val("", float64(s.app.Col.Rejected())))
	metric("ddosd_engine_eval_milliseconds", "gauge", "Duration of the last 1s evaluation tick", val("", snap.EvalMillis))
	metric("ddosd_engine_series", "gauge", "Tracked (rule, target) series", val("", float64(snap.Series)))
	metric("ddosd_engine_series_overflow_total", "counter", "Host series not created because max_series was reached", val("", float64(snap.SeriesOverflow)))
	metric("ddosd_flowstore_records", "gauge", "Records in the forensic ring buffer", val("", float64(snap.FlowStoreLen)))
	metric("ddosd_incidents_active", "gauge", "Active incidents", val("", float64(snap.ActiveIncidents)))
	metric("ddosd_signals_pending", "gauge", "Near-miss signals waiting for analysis", val("", float64(snap.PendingSignals)))
	pending, active := s.app.Mit.Counts()
	metric("ddosd_mitigations", "gauge", "Mitigations by status", val(`status="pending"`, float64(pending)), val(`status="active"`, float64(active)))

	var in, out []string
	for _, o := range snap.Objects {
		l := fmt.Sprintf(`object=%q`, o.Name)
		in = append(in, val(l+`,direction="in"`, o.Rates.InBPS), val(l+`,direction="out"`, o.Rates.OutBPS))
		out = append(out, val(l+`,direction="in"`, o.Rates.InPPS), val(l+`,direction="out"`, o.Rates.OutPPS))
	}
	metric("ddosd_object_bits_per_second", "gauge", "Traffic per protected object", in...)
	metric("ddosd_object_packets_per_second", "gauge", "Packets per protected object", out...)

	var recs, lost, errs, age []string
	now := time.Now().Unix()
	for _, e := range s.app.Col.Exporters() {
		l := fmt.Sprintf(`exporter=%q,name=%q`, e.Address, e.Name)
		recs = append(recs, val(l, float64(e.Records)))
		lost = append(lost, val(l, float64(e.LostEstimate)))
		errs = append(errs, val(l, float64(e.Errors)))
		age = append(age, val(l, float64(now-e.LastSeen)))
	}
	metric("ddosd_exporter_records_total", "counter", "Records received per exporter", recs...)
	metric("ddosd_exporter_lost_total", "counter", "Estimated lost flows/datagrams (sequence gaps)", lost...)
	metric("ddosd_exporter_errors_total", "counter", "Decode errors per exporter", errs...)
	metric("ddosd_exporter_last_seen_seconds", "gauge", "Seconds since the last datagram", age...)

	var sent, failed []string
	for _, c := range s.app.Notif.Status() {
		l := fmt.Sprintf(`channel=%q,type=%q`, c.Name, c.Type)
		sent = append(sent, val(l, float64(c.Sent)))
		failed = append(failed, val(l, float64(c.Failed)))
	}
	metric("ddosd_notifications_sent_total", "counter", "Delivered notifications", sent...)
	metric("ddosd_notifications_failed_total", "counter", "Failed notifications", failed...)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = w.Write([]byte(b.String()))
}
