import { api, Finding } from "../api";
import { Card, Empty, ErrorLine, KV, Meter, Sev, Status, Tag } from "../components/ui";
import { bps, classLabel, dateTime, num, pps, run, usePoll } from "../lib";

const recLabel: Record<string, string> = {
  threshold_change: "Eşik değişikliği",
  new_rule: "Yeni kural",
  flowspec: "FlowSpec",
  scrub: "Scrubbing",
  rtbh: "RTBH",
  whitelist: "Whitelist",
  investigate: "İnceleme",
  no_action: "Aksiyon gerekmiyor",
};

export default function FindingDetail({ id }: { id: string }) {
  const f = usePoll(() => api.get<Finding>("/analyst/findings/" + id), 3000, [id]);
  const d = f.data;
  if (!d) return <div className="page">{f.error ? <ErrorLine error={f.error} /> : <Empty>Analiz sürüyor veya yükleniyor…</Empty>}</div>;

  const apply = async (idx: number) => {
    await run("Öneri uygulandı (mitigasyon ise onay kuyruğunda)", () => api.post(`/analyst/findings/${d.id}/apply/${idx}`));
    f.reload();
  };

  return (
    <div className="page">
      <div className="page-h">
        <div>
          <a href="#/analyst" className="small">
            ← AI Analist
          </a>
          <h1>
            {d.status === "error" ? <Status s="error" /> : <Sev s={d.severity || "info"} />} {d.title}
          </h1>
          <div className="muted">
            {d.id} · {dateTime(d.created_at)} · {d.provider} / {d.model} · {(d.duration_ms / 1000).toFixed(1)} sn · {d.usage.turns} tur
            {d.usage.input_tokens ? ` · ${num(d.usage.input_tokens)} girdi / ${num(d.usage.output_tokens)} çıktı token` : ""}
            {d.usage.cache_read_tokens ? ` (${num(d.usage.cache_read_tokens)} cache)` : ""}
          </div>
        </div>
      </div>
      {d.error && <div className="error-line">{d.error}</div>}
      {d.question && (
        <Card title="Soru">
          <p>{d.question}</p>
        </Card>
      )}
      <div className="grid g-3-1">
        <Card title="Özet">
          <p className="lead">{d.summary || "-"}</p>
          {d.hypothesis && (
            <>
              <h4>Hipotez</h4>
              <p>{d.hypothesis}</p>
            </>
          )}
          {d.missed_reason && (
            <>
              <h4>Dedektör neden alarm vermedi?</h4>
              <p>{d.missed_reason}</p>
            </>
          )}
        </Card>
        <Card title="Değerlendirme">
          <KV
            items={[
              ["Sınıf", <b key="c">{classLabel[d.classification] ?? d.classification ?? "-"}</b>],
              ["Önem", <Sev key="s" s={d.severity || "info"} />],
              [
                "Güven",
                <div key="g">
                  <Meter value={d.confidence} tone="blue" /> <span className="small">%{Math.round(d.confidence * 100)}</span>
                </div>,
              ],
              [
                "Hedefler",
                (d.targets ?? []).map((t) => (
                  <a key={t} href={"#/objects/" + t} className="mono">
                    {t}{" "}
                  </a>
                )),
              ],
              [
                "Olay",
                d.incident_id ? (
                  <a href={"#/incidents/" + d.incident_id} className="mono">
                    {d.incident_id}
                  </a>
                ) : (
                  "-"
                ),
              ],
              ["Sinyaller", (d.signal_ids ?? []).join(", ") || "-"],
            ]}
          />
        </Card>
      </div>

      <Card title={`Öneriler (${d.recommendations.length})`} pad={false}>
        {d.recommendations.length === 0 ? (
          <Empty>Öneri yok</Empty>
        ) : (
          <ul className="list recs">
            {d.recommendations.map((r, i) => {
              const canApply = ["flowspec", "threshold_change", "rtbh", "scrub"].includes(r.type);
              return (
                <li key={i}>
                  <div className="li-top">
                    <Tag tone={r.type === "flowspec" || r.type === "rtbh" ? "amber" : r.type === "threshold_change" ? "blue" : ""}>{recLabel[r.type] ?? r.type}</Tag>
                    <b>{r.title}</b>
                    <span className="right">
                      {r.applied ? (
                        <span className="badge tone-green">uygulandı: {r.applied.startsWith("MIT") ? <a href="#/mitigations">{r.applied}</a> : r.applied}</span>
                      ) : canApply ? (
                        <button className="btn primary tiny" onClick={() => apply(i)}>
                          {r.type === "threshold_change" ? "Eşiği uygula" : "Onay kuyruğuna gönder"}
                        </button>
                      ) : null}
                    </span>
                  </div>
                  <div className="small">{r.detail}</div>
                  {r.flowspec && (
                    <div className="mono small fs">
                      {r.flowspec.direction === "outbound" ? "kaynak" : "hedef"} {r.flowspec.target}
                      {r.flowspec.protocol ? " · " + r.flowspec.protocol : ""}
                      {r.flowspec.src_ports?.length ? " · sport " + r.flowspec.src_ports.join(",") : ""}
                      {r.flowspec.dst_ports?.length ? " · dport " + r.flowspec.dst_ports.join(",") : ""}
                      {r.flowspec.min_packet_length ? " · boy ≥" + r.flowspec.min_packet_length : ""} → {r.flowspec.action ?? "discard"}
                      {r.flowspec.rate_bps ? " " + bps(r.flowspec.rate_bps) : ""}
                    </div>
                  )}
                  {r.threshold && (
                    <div className="mono small fs">
                      {r.threshold.rule_id}: {r.threshold.pps ? "pps → " + pps(r.threshold.pps) : ""} {r.threshold.bps ? "bps → " + bps(r.threshold.bps) : ""}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </Card>

      <Card title={`Kanıtlar (${d.evidence.length})`} pad={false}>
        {d.evidence.length === 0 ? (
          <Empty>Kanıt yok</Empty>
        ) : (
          <table className="tbl">
            <tbody>
              {d.evidence.map((e, i) => (
                <tr key={i}>
                  <td>{e.claim}</td>
                  <td className="mono small muted" style={{ width: "35%" }}>
                    {e.source}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <Card title={`Araç çağrıları (${(d.trace ?? []).length})`} actions={<span className="small muted">şeffaflık: modelin gördüğü veriler</span>} pad={false}>
        {(d.trace ?? []).length === 0 ? (
          <Empty>İz yok</Empty>
        ) : (
          <ol className="trace">
            {(d.trace ?? []).map((t, i) => (
              <li key={i} className={t.is_error ? "err" : ""}>
                <details>
                  <summary>
                    <span className="mono">{t.tool}</span> <span className="muted small">tur {t.turn} · {t.duration_ms} ms</span>
                  </summary>
                  <div className="small muted">girdi</div>
                  <pre>{t.input}</pre>
                  <div className="small muted">çıktı (önizleme)</div>
                  <pre>{t.output_preview}</pre>
                </details>
              </li>
            ))}
          </ol>
        )}
      </Card>
    </div>
  );
}
