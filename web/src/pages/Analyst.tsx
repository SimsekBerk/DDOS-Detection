import { useState } from "react";
import { AnalystStatus, api, Finding, Signal } from "../api";
import { useMe } from "../auth";
import { Card, Empty, ErrorLine, Field, Meter, Modal, PageHead, Seg, Sev, Status } from "../components/ui";
import { ago, bps, classLabel, go, pps, run, signalKindLabel, usePoll } from "../lib";

export default function AnalystPage() {
  const me = useMe();
  const [tab, setTab] = useState<"findings" | "signals">("findings");
  const [asking, setAsking] = useState(false);
  const st = usePoll(() => api.get<AnalystStatus>("/analyst/status"), 2000);
  const finds = usePoll(() => api.get<Finding[]>("/analyst/findings?limit=100"), 4000);
  const sigs = usePoll(() => api.get<Signal[]>("/signals?pending=true&limit=200"), 3000);
  const s = st.data;
  const canRun = me.can_operate && me.objects.length === 0;

  const start = async (path: string, body: unknown, label: string) => {
    const r = await run(label, () => api.post<{ finding_id: string }>(path, body));
    if (!r) return;
    const poll = window.setInterval(async () => {
      const status = await api.get<AnalystStatus>("/analyst/status").catch(() => null);
      if (status && !status.running) {
        window.clearInterval(poll);
        go("/analyst/" + r.finding_id);
      }
    }, 1500);
  };

  return (
    <div className="page">
      <PageHead
        title="AI analist"
        desc="Eşik altında kalan anormallikleri ve olayları özet veriler üzerinden inceler, açıklar ve öneri üretir. Hiçbir aksiyonu kendisi uygulamaz."
        actions={
          canRun && (
            <>
              <button className="btn" disabled={s?.running} onClick={() => setAsking(true)}>
                Soru sor
              </button>
              <button className="btn primary" disabled={s?.running} onClick={() => start("/analyst/run", {}, "Analiz başladı")}>
                {s?.running ? "Analiz sürüyor…" : "Sinyalleri analiz et"}
              </button>
            </>
          )
        }
      />
      <ErrorLine error={st.error} />
      {s && (
        <div className="banner">
          <span className="dot" style={{ background: s.running ? "var(--warning)" : s.enabled ? "var(--good)" : "var(--muted)" }} />
          <div className="small">
            <b>{s.provider === "heuristic" ? "Kural tabanlı analist" : `${s.provider} · ${s.model}`}</b>
            <div className="ink2">
              {s.running ? "Analiz çalışıyor" : s.last_run ? `Son analiz ${ago(s.last_run)}` : "Henüz analiz yapılmadı"}
              {s.auto_run ? " · bekleyen sinyal olduğunda otomatik çalışır" : " · otomatik çalışma kapalı"}
            </div>
            {s.note && <div className="ink2">{s.note}</div>}
          </div>
        </div>
      )}

      <Card
        flush
        title={
          <Seg
            value={tab}
            onChange={setTab}
            options={[
              { id: "findings", label: `Bulgular (${(finds.data ?? []).length})` },
              { id: "signals", label: `Aday sinyaller (${(sigs.data ?? []).length})` },
            ]}
          />
        }
      >
        {tab === "findings" ? (
          (finds.data ?? []).length === 0 ? (
            <Empty>Henüz bulgu yok</Empty>
          ) : (
            <div className="tbl-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Önem</th>
                    <th>Bulgu</th>
                    <th>Sınıf</th>
                    <th>Güven</th>
                    <th>Zaman</th>
                  </tr>
                </thead>
                <tbody>
                  {(finds.data ?? []).map((f) => (
                    <tr key={f.id} className="row-link" onClick={() => go("/analyst/" + f.id)}>
                      <td>{f.status === "error" ? <Status s="error" /> : <Sev s={f.severity || "info"} />}</td>
                      <td style={{ maxWidth: 480 }}>
                        <div className="cell-main trunc">{f.title}</div>
                        <div className="cell-sub">
                          {{ signals: "sinyal analizi", incident: "olay raporu", question: "soru" }[f.mode] ?? f.mode} · {f.provider}
                        </div>
                      </td>
                      <td className="small">{classLabel[f.classification] ?? "-"}</td>
                      <td style={{ width: 110 }}>
                        <Meter value={f.confidence} />
                      </td>
                      <td className="small">{ago(f.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        ) : (sigs.data ?? []).length === 0 ? (
          <Empty>Bekleyen sinyal yok. Dedektörün alarm vermediği ama normalin dışına çıkan trafik burada listelenir.</Empty>
        ) : (
          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Hedef</th>
                  <th>Tür</th>
                  <th>Eşiğe oran</th>
                  <th className="num">Tepe</th>
                  <th>Son görülme</th>
                </tr>
              </thead>
              <tbody>
                {(sigs.data ?? []).map((g) => (
                  <tr key={g.id} title={g.detail}>
                    <td style={{ maxWidth: 280 }}>
                      <div className="cell-main mono trunc">{g.target}</div>
                      <div className="cell-sub trunc">{g.rule_name}</div>
                    </td>
                    <td className="small">
                      {signalKindLabel[g.kind] ?? g.kind}
                      {g.related_incident && <div className="cell-sub">ilişkili olay {g.related_incident}</div>}
                    </td>
                    <td style={{ width: 130 }}>
                      <Meter value={g.peak_ratio} />
                      <div className="cell-sub num">{g.peak_ratio.toFixed(2)}×</div>
                    </td>
                    <td className="num">
                      {pps(g.peak_pps)}
                      <div className="cell-sub">{bps(g.peak_bps)}</div>
                    </td>
                    <td className="small">{ago(g.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {asking && <AskModal onClose={() => setAsking(false)} onAsk={(q) => start("/analyst/ask", { question: q }, "Soru analiste iletildi")} />}
    </div>
  );
}

function AskModal({ onClose, onAsk }: { onClose: () => void; onAsk: (q: string) => void }) {
  const [q, setQ] = useState("");
  return (
    <Modal
      title="Analiste soru sor"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Vazgeç
          </button>
          <button
            className="btn primary"
            disabled={q.length < 3}
            onClick={() => {
              onAsk(q);
              onClose();
            }}
          >
            Sor
          </button>
        </>
      }
    >
      <Field label="Soru" hint="Serbest sorular bir LLM sağlayıcısı gerektirir (Claude API veya yerel model).">
        <textarea rows={4} value={q} onChange={(e) => setQ(e.target.value)} placeholder="Son 10 dakikada Musteri-A'ya gelen UDP trafiği neden arttı?" />
      </Field>
    </Modal>
  );
}
