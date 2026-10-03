import { api, Finding } from "../api";
import { useMe } from "../auth";
import { Card, Empty, ErrorLine, Kpi, PageHead, Sev, Status } from "../components/ui";
import { bps, classLabel, dateTime, num, pps, run, usePoll } from "../lib";

const recLabel: Record<string, string> = {
  threshold_change: "Eşik değişikliği",
  new_rule: "Yeni kural",
  flowspec: "FlowSpec",
  scrub: "Scrubbing",
  rtbh: "RTBH",
  whitelist: "İzin listesi",
  investigate: "İnceleme",
  no_action: "Aksiyon gerekmiyor",
};

export default function FindingDetail({ id }: { id: string }) {
  const me = useMe();
  const f = usePoll(() => api.get<Finding>("/analyst/findings/" + id), 3000, [id]);
  const d = f.data;
  if (!d) return <div className="page">{f.error ? <ErrorLine error={f.error} /> : <Empty>Analiz sürüyor…</Empty>}</div>;
  const canApply = me.can_operate && me.objects.length === 0;
  const apply = async (idx: number) => {
    await run("Öneri uygulandı", () => api.post(`/analyst/findings/${d.id}/apply/${idx}`));
    f.reload();
  };
  return (
    <div className="page">
      <PageHead crumb={<a href="#/analyst">AI analist</a>} title={<span className="wrap">{d.title}</span>} desc={`${d.id} · ${dateTime(d.created_at)} · ${d.provider}${d.model ? " / " + d.model : ""}`} />
      {d.error && <div className="alert-line">{d.error}</div>}
      <div className="kpis">
        <Kpi label="Önem" value={d.status === "error" ? <Status s="error" /> : <Sev s={d.severity || "info"} />} />
        <Kpi label="Sınıf" value={classLabel[d.classification] ?? "-"} />
        <Kpi label="Güven" value={"%" + Math.round(d.confidence * 100)} />
        <Kpi label="Analiz" value={(d.duration_ms / 1000).toFixed(1) + " sn"} sub={`${d.usage.turns} tur${d.usage.input_tokens ? ` · ${num(d.usage.input_tokens + d.usage.output_tokens)} token` : ""}`} />
      </div>
      <Card title="Özet">
        {d.question && <p className="ink2">Soru: {d.question}</p>}
        <p style={{ fontSize: 15 }}>{d.summary}</p>
        {d.missed_reason && (
          <>
            <h3>Dedektör neden alarm vermedi?</h3>
            <p>{d.missed_reason}</p>
          </>
        )}
        {d.hypothesis && (
          <>
            <h3>Hipotez</h3>
            <p>{d.hypothesis}</p>
          </>
        )}
        {(d.targets ?? []).length > 0 && (
          <p className="small muted">
            Hedefler:{" "}
            {(d.targets ?? []).map((t) => (
              <a key={t} href={"#/explorer/target/" + t} className="mono">
                {t}{" "}
              </a>
            ))}
            {d.incident_id && (
              <>
                · olay <a href={"#/incidents/" + d.incident_id}>{d.incident_id}</a>
              </>
            )}
          </p>
        )}
      </Card>

      <Card title="Öneriler">
        {d.recommendations.length === 0 ? (
          <Empty>Öneri yok</Empty>
        ) : (
          d.recommendations.map((r, i) => {
            const applicable = ["flowspec", "rtbh", "scrub"].includes(r.type) || (r.type === "threshold_change" && me.can_admin);
            return (
              <div key={i} className="item">
                <div className="item-head">
                  <div className="grow">
                    <div className="row">
                      <span className="pill">{recLabel[r.type] ?? r.type}</span>
                      <span className="item-title">{r.title}</span>
                    </div>
                    <p className="small ink2">{r.detail}</p>
                    {r.flowspec && (
                      <div className="mono small wrap">
                        {r.flowspec.direction === "outbound" ? "kaynak" : "hedef"} {r.flowspec.target}
                        {r.flowspec.protocol ? " · " + r.flowspec.protocol : ""}
                        {r.flowspec.src_ports?.length ? " · kaynak port " + r.flowspec.src_ports.join(",") : ""}
                        {r.flowspec.dst_ports?.length ? " · hedef port " + r.flowspec.dst_ports.join(",") : ""}
                        {r.flowspec.min_packet_length ? " · paket ≥" + r.flowspec.min_packet_length : ""} → {r.flowspec.action === "rate-limit" ? "sınırla " + bps(r.flowspec.rate_bps) : "düşür"}
                      </div>
                    )}
                    {r.threshold && (
                      <div className="mono small">
                        {r.threshold.rule_id}: {r.threshold.pps ? "pps → " + pps(r.threshold.pps) : ""} {r.threshold.bps ? "bps → " + bps(r.threshold.bps) : ""}
                      </div>
                    )}
                  </div>
                  {r.applied ? (
                    <span className="pill ok">uygulandı · {r.applied}</span>
                  ) : canApply && applicable ? (
                    <button className="btn primary sm" onClick={() => apply(i)}>
                      {r.type === "threshold_change" ? "Eşiği uygula" : "Onay kuyruğuna gönder"}
                    </button>
                  ) : null}
                </div>
              </div>
            );
          })
        )}
      </Card>

      <Card title="Kanıtlar" flush>
        {d.evidence.length === 0 ? (
          <Empty>Kanıt yok</Empty>
        ) : (
          <div className="tbl-wrap">
            <table className="tbl">
              <tbody>
                {d.evidence.map((e, i) => (
                  <tr key={i}>
                    <td className="wrap">{e.claim}</td>
                    <td className="mono small muted wrap" style={{ width: "34%" }}>
                      {e.source}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {(d.trace ?? []).length > 0 && (
        <Card title="Araç çağrıları">
          <p className="small muted">Analistin incelediği veriler (şeffaflık için).</p>
          {(d.trace ?? []).map((t, i) => (
            <details key={i} style={{ marginTop: 8 }}>
              <summary>
                <span className="mono">{t.tool}</span> <span className="muted small">· {t.duration_ms} ms{t.is_error ? " · hata" : ""}</span>
              </summary>
              <pre>{t.input}</pre>
              <pre>{t.output_preview}</pre>
            </details>
          ))}
        </Card>
      )}
    </div>
  );
}
