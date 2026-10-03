import { useState } from "react";
import { api, Overview, Scenario, SimStatus } from "../api";
import { Card, Empty, ErrorLine, PageHead } from "../components/ui";
import { bps, duration, num, pps, run, usePoll } from "../lib";

const catLabel: Record<string, string> = {
  amplification: "Yansıma / amplifikasyon",
  tcp: "TCP",
  udp: "UDP",
  icmp: "ICMP",
  fragment: "Fragment",
  ip_protocol: "IP protokolü",
  carpet: "Carpet bombing",
  near_miss: "Eşik altı (AI analist için)",
  outbound: "Giden saldırı",
};

export default function SimulatorPage({ ov }: { ov: Overview | null }) {
  const s = usePoll(() => api.get<SimStatus>("/sim"), 2500);
  const st = s.data?.status;
  const [cat, setCat] = useState("amplification");
  const objects = ov?.engine.objects ?? [];
  const v4 = (i: number) => objects[i]?.prefixes.find((x) => !x.includes(":")) ?? "";
  const host = (prefix: string, n: number) => {
    const [a] = prefix.split("/");
    const o = a.split(".").map(Number);
    o[3] = n;
    return o.join(".");
  };
  const defaultTarget = (sc: Scenario) => {
    if (sc.target_kind === "prefix") return v4(1) || v4(0);
    if (sc.target_kind === "outbound") return host(v4(0), 25);
    return host(v4(0), 10);
  };
  if (s.data && !s.data.enabled) return <Empty>Demo simülatörü kapalı.</Empty>;
  const scenarios = (s.data?.scenarios ?? []).filter((x) => x.category === cat);
  const cats = [...new Set((s.data?.scenarios ?? []).map((x) => x.category))];
  return (
    <div className="page">
      <PageHead
        title="Simülatör"
        desc={`Sentetik trafik gerçek ${st?.encoder ?? ""} paketleri olarak ${st?.collector ?? ""} adresine gönderilir. Ağınıza saldırı trafiği üretilmez.`}
        actions={
          <label className="check">
            <input
              type="checkbox"
              checked={!!st?.baseline}
              onChange={async (e) => {
                await run(e.target.checked ? "Normal trafik açıldı" : "Normal trafik kapandı", () => api.post("/sim/baseline", { enabled: e.target.checked, bps: st?.baseline_bps }));
                s.reload();
              }}
            />
            Normal trafik ({bps(st?.baseline_bps)})
          </label>
        }
      />
      <ErrorLine error={s.error} />
      {(st?.runs ?? []).length > 0 && (
        <Card title="Çalışan senaryolar" flush actions={<button className="btn sm" onClick={async () => { await run("Tümü durduruldu", () => api.post("/sim/stop", {})); s.reload(); }}>Hepsini durdur</button>}>
          <div className="tbl-wrap">
            <table className="tbl">
              <tbody>
                {(st?.runs ?? []).map((r) => (
                  <tr key={r.id}>
                    <td>
                      <div className="cell-main">{r.name}</div>
                      <div className="cell-sub mono">{r.target}</div>
                    </td>
                    <td className="num">
                      {pps(r.pps)}
                      <div className="cell-sub">{num(r.sources)} kaynak</div>
                    </td>
                    <td className="small">kalan {duration(r.ends_at - Date.now() / 1000)}</td>
                    <td className="r">
                      <button className="btn sm" onClick={async () => { await run("Durduruldu", () => api.post("/sim/stop", { id: r.id })); s.reload(); }}>
                        Durdur
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
      <Card flush title={<select value={cat} onChange={(e) => setCat(e.target.value)}>{cats.map((c) => <option key={c} value={c}>{catLabel[c] ?? c}</option>)}</select>}>
        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>Senaryo</th>
                <th>Beklenen kural</th>
                <th>Hedef</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {scenarios.map((sc) => (
                <ScenarioRow key={sc.id} sc={sc} target={defaultTarget(sc)} onStarted={s.reload} />
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

function ScenarioRow({ sc, target, onStarted }: { sc: Scenario; target: string; onStarted: () => void }) {
  const [t, setT] = useState("");
  return (
    <tr>
      <td style={{ maxWidth: 360 }}>
        <div className="cell-main">{sc.name}</div>
        <div className="cell-sub">{sc.description}</div>
      </td>
      <td className="small mono" style={{ maxWidth: 200 }}>
        <div className="wrap">{sc.expected_rules.join(", ")}</div>
      </td>
      <td>
        <input style={{ width: 150 }} value={t} placeholder={target} onChange={(e) => setT(e.target.value)} aria-label="hedef" />
      </td>
      <td className="r">
        <button
          className="btn primary sm"
          onClick={async () => {
            await run(sc.name + " başlatıldı (2 dk)", () => api.post("/sim/start", { scenario: sc.id, target: t || target, duration_seconds: 120 }));
            onStarted();
          }}
        >
          Başlat
        </button>
      </td>
    </tr>
  );
}
