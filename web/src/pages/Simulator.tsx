import { useState } from "react";
import { api, Overview, Scenario, SimStatus } from "../api";
import { Card, Empty, ErrorLine, Stat, Tag } from "../components/ui";
import { bps, clock, duration, num, pps, run, usePoll } from "../lib";

const catLabel: Record<string, string> = {
  amplification: "Yansıma / Amplifikasyon",
  tcp: "TCP",
  udp: "UDP",
  icmp: "ICMP",
  fragment: "Fragment",
  ip_protocol: "IP Protokol",
  carpet: "Carpet Bombing",
  near_miss: "Eşik altı (AI analist için)",
  outbound: "Outbound",
};

export default function SimulatorPage({ ov }: { ov: Overview | null }) {
  const s = usePoll(() => api.get<SimStatus>("/sim"), 2000);
  const st = s.data?.status;
  const objects = ov?.engine.objects ?? [];
  const firstHost = (i: number) => {
    const p = objects[i]?.prefixes.find((x) => !x.includes(":"));
    if (!p) return "";
    const [a] = p.split("/");
    const o = a.split(".").map(Number);
    o[3] = Math.min(254, o[3] + 10);
    return o.join(".");
  };
  const firstPrefix = (i: number) => objects[i]?.prefixes.find((x) => !x.includes(":")) ?? "";

  if (s.data && !s.data.enabled)
    return (
      <div className="page">
        <h1>Simülatör</h1>
        <Empty>Demo simülatörü kapalı. config.yaml içinde demo.enabled: true yapın veya komut satırından ddos-sim kullanın.</Empty>
      </div>
    );

  const groups: Record<string, Scenario[]> = {};
  (s.data?.scenarios ?? []).forEach((x) => (groups[x.category] ??= []).push(x));

  return (
    <div className="page">
      <div className="page-h">
        <div>
          <h1>Simülatör</h1>
          <div className="muted">
            Sentetik trafik gerçek {st?.encoder} paketleri olarak {st?.collector} adresine gönderilir (örnekleme 1:{st?.sampling_rate}). Ağınıza gerçek saldırı trafiği üretilmez.
          </div>
        </div>
      </div>
      <ErrorLine error={s.error} />
      <div className="stats">
        <Stat label="Encoder" value={st?.encoder ?? "-"} sub={"1:" + (st?.sampling_rate ?? 1)} />
        <Stat label="Gönderilen datagram" value={num(st?.datagrams_sent)} />
        <Stat label="Üretilen flow" value={num(st?.specs_generated)} />
        <Stat label="Aktif senaryo" value={(st?.runs ?? []).length} tone={(st?.runs ?? []).length ? "t-red" : ""} />
      </div>
      <div className="grid g-2">
        <Card title="Baseline (normal) trafik">
          <div className="row wrap">
            <label className="check">
              <input
                type="checkbox"
                checked={!!st?.baseline}
                onChange={async (e) => {
                  await run(e.target.checked ? "Baseline açıldı" : "Baseline kapandı", () => api.post("/sim/baseline", { enabled: e.target.checked, bps: st?.baseline_bps }));
                  s.reload();
                }}
              />
              Baseline trafik ({bps(st?.baseline_bps)})
            </label>
            {[200e6, 600e6, 2e9].map((v) => (
              <button
                key={v}
                className="btn tiny"
                onClick={async () => {
                  await run("Baseline " + bps(v), () => api.post("/sim/baseline", { enabled: true, bps: v }));
                  s.reload();
                }}
              >
                {bps(v)}
              </button>
            ))}
          </div>
          <p className="small muted">Web, QUIC, DNS, NTP, SSH ve ping karışımı; 10 dakikalık periyotla ±%20 dalgalanır. Baseline algılaması için birkaç dakika öğrenme gerekir.</p>
        </Card>
        <Card
          title="Çalışan senaryolar"
          actions={
            (st?.runs ?? []).length ? (
              <button
                className="btn tiny danger"
                onClick={async () => {
                  await run("Tüm senaryolar durduruldu", () => api.post("/sim/stop", {}));
                  s.reload();
                }}
              >
                Hepsini durdur
              </button>
            ) : null
          }
          pad={false}
        >
          {(st?.runs ?? []).length === 0 ? (
            <Empty>Çalışan senaryo yok</Empty>
          ) : (
            <table className="tbl">
              <tbody>
                {(st?.runs ?? []).map((r) => (
                  <tr key={r.id}>
                    <td>
                      <b>{r.name}</b>
                      <div className="small muted mono">
                        {r.id} → {r.target}
                      </div>
                    </td>
                    <td className="mono small">
                      {pps(r.pps)} · {num(r.sources)} kaynak
                    </td>
                    <td className="small">
                      {clock(r.started_at)} · kalan {duration(r.ends_at - Date.now() / 1000)}
                    </td>
                    <td>
                      <button
                        className="btn tiny"
                        onClick={async () => {
                          await run("Durduruldu", () => api.post("/sim/stop", { id: r.id }));
                          s.reload();
                        }}
                      >
                        Durdur
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>

      {Object.entries(groups).map(([cat, list]) => (
        <Card key={cat} title={catLabel[cat] ?? cat}>
          <div className="scen-grid">
            {list.map((x) => (
              <ScenarioCard key={x.id} sc={x} defaultTarget={x.target_kind === "prefix" ? firstPrefix(1) || firstPrefix(0) : x.target_kind === "outbound" ? firstHost(0).replace(/\.\d+$/, ".25") : firstHost(0)} onStarted={s.reload} />
            ))}
          </div>
        </Card>
      ))}
    </div>
  );
}

function ScenarioCard({ sc, defaultTarget, onStarted }: { sc: Scenario; defaultTarget: string; onStarted: () => void }) {
  const [target, setTarget] = useState("");
  const [rate, setRate] = useState("");
  const [dur, setDur] = useState("120");
  const start = async () => {
    await run(sc.name + " başlatıldı", () =>
      api.post("/sim/start", { scenario: sc.id, target: target || defaultTarget, pps: rate ? Number(rate) : 0, duration_seconds: Number(dur) || 120 }),
    );
    onStarted();
  };
  return (
    <div className="scen">
      <div className="li-top">
        <b>{sc.name}</b>
      </div>
      <p className="small">{sc.description}</p>
      <div className="small muted">
        Beklenen: {sc.expected_rules.map((r) => <Tag key={r}>{r}</Tag>)}
      </div>
      <div className="scen-f">
        <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder={defaultTarget || "hedef"} aria-label="hedef" />
        <input value={rate} onChange={(e) => setRate(e.target.value)} placeholder={sc.relative_rule ? "eşiğe göre" : num(sc.default_pps) + " pps"} aria-label="pps" />
        <input value={dur} onChange={(e) => setDur(e.target.value)} aria-label="süre (sn)" title="süre (sn)" />
        <button className="btn primary tiny" onClick={start}>
          ▶ Başlat
        </button>
      </div>
    </div>
  );
}
