import { useMemo, useState } from "react";
import { api, Profile, RuleView } from "../api";
import { Card, Empty, ErrorLine, KV, Modal, Sev, Tabs, Tag } from "../components/ui";
import { actionLabel, bps, categoryLabel, fps, pps, run, usePoll } from "../lib";

type RulesResp = { rules: RuleView[]; profiles: Record<string, Profile>; files: string[] };

export default function RulesPage() {
  const r = usePoll(() => api.get<RulesResp>("/rules"), 10000);
  const [tab, setTab] = useState<"rules" | "profiles">("rules");
  const [cat, setCat] = useState("");
  const [q, setQ] = useState("");
  const initial = new URLSearchParams(window.location.hash.split("?")[1] ?? "").get("id");
  const [open, setOpen] = useState<string | null>(initial);
  const rules = r.data?.rules ?? [];
  const cats = useMemo(() => [...new Set(rules.map((x) => x.category))], [rules]);
  const shown = rules.filter((x) => (!cat || x.category === cat) && (!q || (x.id + x.name + x.description).toLowerCase().includes(q.toLowerCase())));
  const current = rules.find((x) => x.id === open);

  const toggle = async (x: RuleView) => {
    await run(x.active ? "Kural devre dışı" : "Kural etkin", () => api.patch(`/rules/${x.id}`, { enabled: !x.active }));
    r.reload();
  };

  return (
    <div className="page">
      <div className="page-h">
        <div>
          <h1>Kural Setleri</h1>
          <div className="muted">
            {rules.length} kural · {rules.filter((x) => x.active).length} aktif · dosyalar: {(r.data?.files ?? []).join(", ")}. L3/L4 DDoS vektörlerinin tamamını kapsar; eşikler profil ile nesne tipine göre ölçeklenir.
          </div>
        </div>
        <button
          className="btn"
          onClick={async () => {
            await run("Kurallar diskten yeniden yüklendi", () => api.post("/rules/reload"));
            r.reload();
          }}
        >
          ⟳ Diskten yeniden yükle
        </button>
      </div>
      <ErrorLine error={r.error} />
      <Card
        pad={false}
        title={<Tabs value={tab} onChange={setTab} tabs={[{ id: "rules", label: "Kurallar" }, { id: "profiles", label: "Profiller" }]} />}
        actions={
          tab === "rules" ? (
            <>
              <select value={cat} onChange={(e) => setCat(e.target.value)}>
                <option value="">Tüm kategoriler</option>
                {cats.map((c) => (
                  <option key={c} value={c}>
                    {categoryLabel[c] ?? c} ({rules.filter((x) => x.category === c).length})
                  </option>
                ))}
              </select>
              <input placeholder="Ara…" value={q} onChange={(e) => setQ(e.target.value)} />
            </>
          ) : null
        }
      >
        {tab === "profiles" ? (
          <Profiles profiles={r.data?.profiles ?? {}} />
        ) : shown.length === 0 ? (
          <Empty>Kural yok</Empty>
        ) : (
          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Aktif</th>
                  <th>Kural</th>
                  <th>Kategori</th>
                  <th>Kapsam</th>
                  <th>Eşleşme</th>
                  <th className="r">Eşik (temel)</th>
                  <th>Baseline</th>
                  <th>Sustain / Hold</th>
                  <th>Mitigasyon</th>
                  <th>Önem</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((x) => (
                  <tr key={x.id} className={"clickable" + (x.active ? "" : " dim")} onClick={() => setOpen(x.id)}>
                    <td onClick={(e) => e.stopPropagation()}>
                      <label className="switch">
                        <input type="checkbox" checked={x.active} onChange={() => toggle(x)} />
                        <span />
                      </label>
                    </td>
                    <td>
                      <b>{x.name}</b>
                      <div className="small muted mono">
                        {x.id}
                        {x.override ? " · özelleştirilmiş" : ""}
                      </div>
                    </td>
                    <td>
                      <Tag>{categoryLabel[x.category] ?? x.category}</Tag>
                    </td>
                    <td className="small">
                      {x.scope}
                      <div className="muted">{x.direction}</div>
                    </td>
                    <td className="mono small" style={{ maxWidth: 260 }}>
                      {x.match_summary}
                    </td>
                    <td className="r mono small">
                      {x.base_thresholds.pps ? pps(x.base_thresholds.pps) : ""}
                      {x.base_thresholds.bps ? <div>{bps(x.base_thresholds.bps)}</div> : null}
                      {x.base_thresholds.fps ? <div>{fps(x.base_thresholds.fps)}</div> : null}
                    </td>
                    <td className="small">{x.baseline.enabled ? `×${x.baseline.factor}` : "-"}</td>
                    <td className="small mono">
                      {x.sustain_seconds}s / {x.hold_down_seconds}s
                    </td>
                    <td className="small">{actionLabel[x.mitigation.action] ?? x.mitigation.action}</td>
                    <td>
                      <Sev s={x.severity} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {current && <RuleModal rule={current} onClose={() => setOpen(null)} onChange={r.reload} />}
    </div>
  );
}

function Profiles({ profiles }: { profiles: Record<string, Profile> }) {
  return (
    <div className="tbl-wrap">
      <table className="tbl">
        <thead>
          <tr>
            <th>Profil</th>
            <th>Açıklama</th>
            <th className="r">Ölçek</th>
            <th>Kapatılan kurallar</th>
            <th>Kural bazlı ayar</th>
          </tr>
        </thead>
        <tbody>
          {Object.values(profiles).map((p) => (
            <tr key={p.name}>
              <td>
                <b>{p.name}</b>
              </td>
              <td className="small">{p.description}</td>
              <td className="r mono">×{p.scale}</td>
              <td className="small mono">{(p.disable ?? []).join(", ") || "-"}</td>
              <td className="small mono">
                {Object.entries(p.overrides ?? {})
                  .map(([k, v]) => `${k} ${v.scale ? "×" + v.scale : ""}${v.pps ? " pps=" + v.pps : ""}`)
                  .join(" · ") || "-"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RuleModal({ rule, onClose, onChange }: { rule: RuleView; onClose: () => void; onChange: () => void }) {
  const [p, setP] = useState(String(rule.override?.pps ?? ""));
  const [b, setB] = useState(String(rule.override?.bps ?? ""));
  const save = async () => {
    await run("Eşik güncellendi", () =>
      api.patch(`/rules/${rule.id}`, {
        pps: p === "" ? -1 : Number(p),
        bps: b === "" ? -1 : Number(b),
      }),
    );
    onChange();
  };
  const reset = async () => {
    await run("Varsayılana döndürüldü", () => api.patch(`/rules/${rule.id}`, { reset: true }));
    onChange();
  };
  const c = rule.conditions;
  return (
    <Modal title={rule.name} onClose={onClose} wide>
      <p>{rule.description}</p>
      <div className="grid g-2">
        <div>
          <KV
            items={[
              ["Kimlik", <span key="i" className="mono">{rule.id}</span>],
              ["Kategori", categoryLabel[rule.category] ?? rule.category],
              ["Yön / kapsam", `${rule.direction} / ${rule.scope}`],
              ["Eşleşme", <span key="m" className="mono small">{rule.match_summary}</span>],
              ["Temel eşik", `${rule.thresholds.pps ? pps(rule.thresholds.pps) : "-"} · ${rule.thresholds.bps ? bps(rule.thresholds.bps) : "-"}${rule.thresholds.fps ? " · " + fps(rule.thresholds.fps) : ""}`],
              ["Baseline", rule.baseline.enabled ? `×${rule.baseline.factor} (min ${pps(rule.baseline.min_pps)} / ${bps(rule.baseline.min_bps)})` : "kapalı"],
              [
                "Koşullar",
                [
                  c.min_unique_sources ? `≥${c.min_unique_sources} benzersiz kaynak` : "",
                  c.min_unique_destinations ? `≥${c.min_unique_destinations} benzersiz hedef` : "",
                  c.min_avg_packet_size ? `ort. paket ≥${c.min_avg_packet_size}B` : "",
                  c.max_avg_packet_size ? `ort. paket ≤${c.max_avg_packet_size}B` : "",
                ]
                  .filter(Boolean)
                  .join(" · ") || "-",
              ],
              ["Tetik", `${rule.sustain_seconds} sn üst üste; bitiş ${rule.hold_down_seconds} sn eşiğin %70 altı`],
              ["Mitigasyon", `${actionLabel[rule.mitigation.action] ?? rule.mitigation.action}${rule.mitigation.rate ? " " + bps(rule.mitigation.rate) : ""}${rule.mitigation.rtbh_escalation ? ` · RTBH eskalasyonu %${rule.mitigation.rtbh_escalation * 100}` : ""}`],
            ]}
          />
          {rule.mitigation.note && <div className="note small">ℹ {rule.mitigation.note}</div>}
          {rule.rationale && (
            <>
              <h4>Gerekçe</h4>
              <p className="small">{rule.rationale}</p>
            </>
          )}
          {rule.false_positives && (
            <>
              <h4>Yanlış pozitif riski</h4>
              <p className="small">{rule.false_positives}</p>
            </>
          )}
          {(rule.references ?? []).length > 0 && <p className="small muted">Referanslar: {(rule.references ?? []).join(" · ")}</p>}
        </div>
        <div>
          <h4>Nesne bazında efektif eşikler</h4>
          <table className="tbl small">
            <thead>
              <tr>
                <th>Nesne</th>
                <th>Profil</th>
                <th className="r">pps</th>
                <th className="r">bps</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(rule.effective).map(([name, e]) => (
                <tr key={name} className={e.enabled ? "" : "dim"}>
                  <td>{name}</td>
                  <td>{e.profile}</td>
                  <td className="r mono">{e.enabled ? (e.pps ? pps(e.pps) : "-") : "kapalı"}</td>
                  <td className="r mono">{e.enabled ? (e.bps ? bps(e.bps) : "-") : ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <h4>Çalışma zamanı eşik ayarı</h4>
          <p className="small muted">Temel eşiği değiştirir (profil ölçeği yine uygulanır). Boş bırakmak dosyadaki değeri kullanır. Değişiklik data/rule_overrides.json'a kaydedilir.</p>
          <div className="form">
            <label>
              pps
              <input value={p} onChange={(e) => setP(e.target.value)} placeholder={String(rule.base_thresholds.pps || "")} />
            </label>
            <label>
              bps
              <input value={b} onChange={(e) => setB(e.target.value)} placeholder={String(rule.base_thresholds.bps || "")} />
            </label>
          </div>
          <div className="row end">
            <button className="btn" onClick={reset}>
              Varsayılana dön
            </button>
            <button className="btn primary" onClick={save}>
              Kaydet
            </button>
          </div>
        </div>
      </div>
    </Modal>
  );
}
