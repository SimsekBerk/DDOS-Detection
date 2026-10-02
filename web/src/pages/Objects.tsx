import { useEffect, useState } from "react";
import { api, ObjectStatus, Overview, TargetRuleState, TotalPoint } from "../api";
import { Spark, ThresholdLine } from "../components/charts";
import { Card, Empty, ErrorLine, Meter, Status, Tag } from "../components/ui";
import { bps, go, pct, pps, usePoll } from "../lib";

export default function ObjectsPage({ ov, target }: { ov: Overview | null; target?: string }) {
  const [ip, setIp] = useState(target ?? "");
  useEffect(() => setIp(target ?? ""), [target]);
  const objs = ov?.engine.objects ?? [];
  return (
    <div className="page">
      <div className="page-h">
        <div>
          <h1>Korunan Nesneler</h1>
          <div className="muted">Nesneler config.yaml → protected_objects altında tanımlanır; profil eşikleri ölçekler.</div>
        </div>
      </div>
      <div className="grid g-3">
        {objs.map((o) => (
          <ObjectCard key={o.id} o={o} />
        ))}
      </div>
      <Card
        title="Hedef analizi — “dedektör neden tetiklenmedi?”"
        actions={
          <form
            className="row"
            onSubmit={(e) => {
              e.preventDefault();
              go("/objects/" + ip.trim());
            }}
          >
            <input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="IP adresi, ör. 198.51.100.10" />
            <button className="btn primary">İncele</button>
          </form>
        }
      >
        {target ? <TargetState ip={target} /> : <Empty>Bir IP girin: o hedef için tüm kuralların canlı oranı, efektif eşiği, baseline'ı ve koşul durumu gösterilir.</Empty>}
      </Card>
    </div>
  );
}

function ObjectCard({ o }: { o: ObjectStatus }) {
  const ts = usePoll(() => api.get<TotalPoint[]>(`/timeseries?object=${encodeURIComponent(o.name)}&range=900&step=15`), 10000, [o.name]);
  return (
    <Card title={o.name} actions={<Tag>{o.profile}</Tag>}>
      <div className="mono small muted">{o.prefixes.join(" · ")}</div>
      <div className="obj-rates">
        <div>
          <div className="small muted">Inbound</div>
          <b>{bps(o.rates.in_bps)}</b>
          <div className="small">{pps(o.rates.in_pps)}</div>
        </div>
        <div>
          <div className="small muted">Outbound</div>
          <b>{bps(o.rates.out_bps)}</b>
          <div className="small">{pps(o.rates.out_pps)}</div>
        </div>
        <Spark data={(ts.data ?? []) as unknown as Record<string, number>[]} dataKey="in_bps" />
      </div>
      <Meter value={o.utilization} />
      <div className="small muted">
        Kullanım {o.link_capacity_bps ? pct(o.utilization, 1) + " / " + bps(o.link_capacity_bps) : "(kapasite tanımsız)"} · carpet /{o.carpet_prefix_v4} v4, /{o.carpet_prefix_v6} v6
      </div>
      {o.active_incidents > 0 && (
        <a href="#/incidents" className="badge tone-red">
          {o.active_incidents} aktif olay
        </a>
      )}
      {o.notes && <div className="small note">{o.notes}</div>}
    </Card>
  );
}

function TargetState({ ip }: { ip: string }) {
  const st = usePoll(() => api.get<TargetRuleState[] | null>(`/target?ip=${encodeURIComponent(ip)}`), 2000, [ip]);
  const [sel, setSel] = useState<string | null>(null);
  const rows = (st.data ?? []).slice().sort((a, b) => b.ratio - a.ratio);
  const cur = rows.find((r) => r.rule_id + r.target === sel) ?? rows[0];
  if (st.error) return <ErrorLine error={st.error} />;
  if (rows.length === 0) return <Empty>{ip} için pencere içinde eşleşen kural serisi yok (trafik yok veya korunan alan dışında).</Empty>;
  const hist = (cur?.recent_seconds ?? []) as unknown as Record<string, number>[];
  return (
    <div className="grid g-2">
      <div className="tbl-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th>Kural</th>
              <th>Kapsam</th>
              <th className="r">Hız</th>
              <th className="r">Efektif eşik</th>
              <th>Oran</th>
              <th>Baseline</th>
              <th>Koşul</th>
              <th>Durum</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.rule_id + r.target} className={"clickable" + (cur === r ? " sel" : "")} onClick={() => setSel(r.rule_id + r.target)}>
                <td className="small">
                  <b>{r.rule_name}</b>
                  <div className="muted mono">{r.rule_id}</div>
                </td>
                <td className="small mono">
                  {r.scope}
                  <div className="muted">{r.target}</div>
                </td>
                <td className="r mono small">
                  {pps(r.pps)}
                  <br />
                  {bps(r.bps)}
                </td>
                <td className="r mono small">
                  {r.threshold_pps ? pps(r.threshold_pps) : "-"}
                  <br />
                  {r.threshold_bps ? bps(r.threshold_bps) : ""}
                </td>
                <td style={{ width: 110 }}>
                  <Meter value={r.ratio} />
                  <span className="small mono">{r.ratio.toFixed(2)}×</span>
                </td>
                <td className="small">{r.baseline_ready ? `${pps(r.baseline_pps)}${r.baseline_factor ? " ×" + r.baseline_factor : ""}` : <span className="muted">öğreniyor</span>}</td>
                <td className="small">{r.conditions === "ok" ? <span className="green">✓</span> : <span className="amber">{r.conditions}</span>}</td>
                <td>{r.active ? <Status s="active" label="olay" /> : r.consecutive_over > 0 ? <span className="small amber">{r.consecutive_over}/{r.sustain_seconds} sn</span> : <span className="muted small">normal</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div>
        {cur && (
          <>
            <h4>
              {cur.rule_name} · {cur.target}
            </h4>
            <ThresholdLine data={hist} dataKey="pps" unit="pps" threshold={cur.threshold_pps} baseline={cur.baseline_ready ? cur.baseline_pps : undefined} height={200} />
            <ThresholdLine data={hist} dataKey="bps" unit="bps" color="var(--violet)" threshold={cur.threshold_bps} baseline={cur.baseline_ready ? cur.baseline_bps : undefined} height={200} />
            <p className="small muted">
              Saniyelik ham değerler (son 60 sn). Tetik, {cur.sustain_seconds} sn boyunca pencere ortalamasının eşiği aşmasını ve koşulların sağlanmasını gerektirir.
            </p>
          </>
        )}
      </div>
    </div>
  );
}
