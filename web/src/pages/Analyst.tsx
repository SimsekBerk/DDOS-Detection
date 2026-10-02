import { useState } from "react";
import { AnalystStatus, api, Finding, Signal } from "../api";
import { Card, Empty, ErrorLine, Meter, Sev, Stat, Status, Tabs, Tag } from "../components/ui";
import { ago, bps, categoryLabel, classLabel, duration, go, num, pps, run, signalKindLabel, usePoll } from "../lib";

export default function AnalystPage() {
  const [tab, setTab] = useState<"findings" | "signals">("findings");
  const [onlyPending, setOnlyPending] = useState(true);
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [question, setQuestion] = useState("");
  const st = usePoll(() => api.get<AnalystStatus>("/analyst/status"), 1500);
  const finds = usePoll(() => api.get<Finding[]>("/analyst/findings?limit=100"), 3000);
  const sigs = usePoll(() => api.get<Signal[]>(`/signals?pending=${onlyPending}&limit=300`), 2500, [onlyPending]);
  const s = st.data;

  const start = async (path: string, body: unknown, label: string) => {
    const r = await run(label, () => api.post<{ finding_id: string }>(path, body));
    if (r) {
      st.reload();
      const id = r.finding_id;
      const wait = window.setInterval(async () => {
        const status = await api.get<AnalystStatus>("/analyst/status");
        if (!status.running) {
          window.clearInterval(wait);
          go("/analyst/" + id);
        }
      }, 1500);
    }
  };

  const toggle = (id: string) => {
    const n = new Set(sel);
    if (n.has(id)) n.delete(id);
    else n.add(id);
    setSel(n);
  };

  return (
    <div className="page">
      <div className="page-h">
        <div>
          <h1>AI Analist</h1>
          <div className="muted">
            Algılama motorunun "ikinci görüş" katmanı: eşik altı kalan sinyalleri ve olayları özet veri üzerinden inceler, açıklar ve öneri üretir. Hızlı yolda değildir; hiçbir aksiyonu kendisi uygulamaz.
          </div>
        </div>
      </div>
      <ErrorLine error={st.error} />
      <div className="stats">
        <Stat label="Sağlayıcı" value={s?.provider ?? "-"} sub={s?.model} />
        <Stat label="Durum" value={s?.running ? <Status s="running" /> : s?.enabled ? "Hazır" : "Kapalı"} sub={s?.current ?? (s?.last_run ? "son çalışma " + ago(s.last_run) : "henüz çalışmadı")} />
        <Stat label="Bekleyen sinyal" value={s?.pending_signals ?? 0} tone={(s?.pending_signals ?? 0) > 0 ? "t-blue" : ""} sub={s?.auto_run ? `her ${duration(s.interval_seconds)}de otomatik (sinyal varsa)` : "otomatik çalışma kapalı"} />
        <Stat label="Bulgu" value={s?.findings ?? 0} />
      </div>
      {s?.note && <div className="note">ℹ {s.note}</div>}
      {s?.last_error && <div className="error-line">Son hata: {s.last_error}</div>}

      <div className="grid g-2">
        <Card title="Analiz başlat">
          <div className="row wrap">
            <button className="btn primary" disabled={s?.running} onClick={() => start("/analyst/run", {}, "Analiz başladı")}>
              ✦ Bekleyen sinyalleri analiz et
            </button>
            <button className="btn" disabled={s?.running || sel.size === 0} onClick={() => start("/analyst/run", { signal_ids: [...sel] }, "Seçili sinyaller analiz ediliyor")}>
              Seçili {sel.size} sinyali analiz et
            </button>
          </div>
          <p className="small muted">Aday sinyal yoksa zamanlanmış analiz modeli hiç çağırmaz (maliyet sıfır).</p>
        </Card>
        <Card title="Analiste soru sor">
          <textarea rows={3} value={question} onChange={(e) => setQuestion(e.target.value)} placeholder="Örn: Son 10 dakikada Demo-DC'ye gelen UDP trafiği neden arttı? Hangi kaynak ağlar baskın?" />
          <div className="row end">
            <button className="btn primary" disabled={s?.running || question.length < 3} onClick={() => start("/analyst/ask", { question }, "Soru analiste iletildi")}>
              Sor
            </button>
          </div>
        </Card>
      </div>

      <Card
        pad={false}
        title={<Tabs value={tab} onChange={setTab} tabs={[{ id: "findings", label: `Bulgular (${(finds.data ?? []).length})` }, { id: "signals", label: `Aday sinyaller (${(sigs.data ?? []).length})` }]} />}
        actions={
          tab === "signals" ? (
            <label className="small check">
              <input type="checkbox" checked={onlyPending} onChange={(e) => setOnlyPending(e.target.checked)} /> sadece bekleyenler
            </label>
          ) : null
        }
      >
        {tab === "findings" ? (
          (finds.data ?? []).length === 0 ? (
            <Empty>Henüz bulgu yok. Simülatörden "Eşik Altı DNS Amp" senaryosunu başlatıp analiz edin.</Empty>
          ) : (
            <div className="tbl-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Önem</th>
                    <th>Bulgu</th>
                    <th>Sınıf</th>
                    <th>Güven</th>
                    <th>Mod</th>
                    <th>Model</th>
                    <th className="r">Süre / tur</th>
                    <th>Zaman</th>
                  </tr>
                </thead>
                <tbody>
                  {(finds.data ?? []).map((f) => (
                    <tr key={f.id} className="clickable" onClick={() => go("/analyst/" + f.id)}>
                      <td>{f.status === "error" ? <Status s="error" /> : <Sev s={f.severity || "info"} />}</td>
                      <td>
                        <b>{f.title}</b>
                        <div className="small muted mono">{f.id}</div>
                      </td>
                      <td>{classLabel[f.classification] ?? "-"}</td>
                      <td style={{ width: 110 }}>
                        <Meter value={f.confidence} tone="blue" />
                      </td>
                      <td>
                        <Tag>{{ signals: "sinyal", incident: "olay", question: "soru" }[f.mode] ?? f.mode}</Tag>
                      </td>
                      <td className="small">
                        {f.provider}
                        <div className="muted">{f.model}</div>
                      </td>
                      <td className="r small mono">
                        {(f.duration_ms / 1000).toFixed(1)} sn / {f.usage.turns}
                      </td>
                      <td className="small">{ago(f.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        ) : (sigs.data ?? []).length === 0 ? (
          <Empty>Aday sinyal yok</Empty>
        ) : (
          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th></th>
                  <th>Tür</th>
                  <th>Hedef</th>
                  <th>Kural</th>
                  <th>Eşiğe oran</th>
                  <th className="r">z</th>
                  <th className="r">Tepe</th>
                  <th className="r">Baseline</th>
                  <th className="r">Süre</th>
                  <th>Detay</th>
                  <th>Durum</th>
                </tr>
              </thead>
              <tbody>
                {(sigs.data ?? []).map((g) => (
                  <tr key={g.id}>
                    <td>
                      <input type="checkbox" checked={sel.has(g.id)} onChange={() => toggle(g.id)} aria-label={"seç " + g.id} />
                    </td>
                    <td>
                      <Tag tone={g.kind === "conditions_unmet" ? "amber" : g.kind === "near_threshold" ? "blue" : "violet"}>{signalKindLabel[g.kind] ?? g.kind}</Tag>
                    </td>
                    <td>
                      <span className="mono clickable link" onClick={() => g.scope === "host" && go("/objects/" + g.target)}>
                        {g.target}
                      </span>
                      <div className="small muted">
                        {g.object_name} · {g.direction}
                      </div>
                    </td>
                    <td className="small">
                      {g.rule_name}
                      <div className="muted">{categoryLabel[g.category] ?? g.category}</div>
                    </td>
                    <td style={{ width: 120 }}>
                      <Meter value={g.peak_ratio} />
                      <span className="small mono">{g.peak_ratio.toFixed(2)}×</span>
                    </td>
                    <td className="r mono small">{g.peak_z ? g.peak_z.toFixed(1) : "-"}</td>
                    <td className="r mono small">
                      {pps(g.peak_pps)}
                      <br />
                      {bps(g.peak_bps)}
                    </td>
                    <td className="r mono small">{g.baseline_pps ? pps(g.baseline_pps) : "-"}</td>
                    <td className="r small">{num(g.seconds)} sn</td>
                    <td className="small" style={{ maxWidth: 340 }}>
                      {g.detail}
                      {g.related_incident && (
                        <div>
                          ilişkili olay:{" "}
                          <a href={"#/incidents/" + g.related_incident} className="mono">
                            {g.related_incident}
                          </a>
                        </div>
                      )}
                    </td>
                    <td className="small">
                      {g.escalated_incident ? (
                        <a href={"#/incidents/" + g.escalated_incident}>olaya dönüştü</a>
                      ) : g.analyzed ? (
                        <a href={"#/analyst/" + g.finding_id}>analiz edildi</a>
                      ) : (
                        <span className="muted">bekliyor · {ago(g.last_seen)}</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
