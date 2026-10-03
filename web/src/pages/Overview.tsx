import { useState } from "react";
import { api, Incident, Overview, TotalPoint } from "../api";
import { useMe } from "../auth";
import { Legend, TimeArea } from "../components/charts";
import { Card, Empty, ErrorLine, Kpi, Meter, PageHead, Seg, Sev } from "../components/ui";
import { bps, duration, go, pct, pps, usePoll } from "../lib";

const ranges = [
  { id: "900", label: "15 dk" },
  { id: "3600", label: "1 sa" },
  { id: "86400", label: "24 sa" },
] as const;

export default function OverviewPage({ ov }: { ov: Overview | null }) {
  const me = useMe();
  const [range, setRange] = useState<"900" | "3600" | "86400">("900");
  const [unit, setUnit] = useState<"bps" | "pps">("bps");
  const ts = usePoll(() => api.get<TotalPoint[]>(`/timeseries?range=${range}`), 4000, [range]);
  const inc = usePoll(() => api.get<Incident[]>("/incidents?status=active&limit=6"), 2500);
  const e = ov?.engine;
  const active = e?.active_incidents ?? 0;
  const series =
    unit === "bps"
      ? [
          { key: "in_bps", name: "Gelen", color: "var(--series-1)" },
          { key: "out_bps", name: "Giden", color: "var(--series-2)" },
        ]
      : [
          { key: "in_pps", name: "Gelen", color: "var(--series-1)" },
          { key: "out_pps", name: "Giden", color: "var(--series-2)" },
        ];
  const health = ov?.exporters_total !== undefined ? `${ov.exporters_up}/${ov.exporters_total} exporter aktif` : undefined;

  return (
    <div className="page">
      <PageHead title="Genel bakış" desc={me.objects.length ? `Kapsamınızdaki nesneler: ${me.objects.join(", ")}` : undefined} />
      <ErrorLine error={ts.error} />

      {active > 0 ? (
        <div className="banner alert" role="status">
          <span className="dot" />
          <div>
            <b>{active} aktif saldırı</b>
            <div className="small ink2">{(inc.data ?? []).map((i) => i.target).join(", ")}</div>
          </div>
          <a className="btn sm right" href="#/incidents">
            Saldırıları gör
          </a>
        </div>
      ) : (
        <div className="banner" role="status">
          <span className="dot" />
          <div>
            <b>Aktif saldırı yok</b>
            <div className="small ink2">
              {e ? `${e.rules_active} kural izleniyor · ${Math.round(e.records_per_sec).toLocaleString("tr-TR")} flow kaydı/sn` : "Bekleniyor"}
            </div>
          </div>
        </div>
      )}

      <div className="kpis">
        <Kpi label="Gelen trafik" value={bps(e?.global.in_bps)} sub={pps(e?.global.in_pps)} />
        <Kpi label="Giden trafik" value={bps(e?.global.out_bps)} sub={pps(e?.global.out_pps)} />
        <Kpi label="Onay bekleyen mitigasyon" value={ov?.mitigation.pending ?? 0} sub={`${ov?.mitigation.active ?? 0} kural uygulanıyor`} onClick={() => go("/mitigations")} />
        <Kpi label="AI için aday sinyal" value={e?.pending_signals ?? 0} sub={health ?? "eşik altı anormallikler"} onClick={() => go("/analyst")} />
      </div>

      <Card
        title="Trafik"
        actions={
          <>
            <Seg value={unit} onChange={setUnit} options={[{ id: "bps", label: "bit/sn" }, { id: "pps", label: "paket/sn" }]} />
            <Seg value={range} onChange={setRange} options={ranges.map((r) => ({ id: r.id, label: r.label }))} />
          </>
        }
      >
        <Legend series={series} />
        {(ts.data ?? []).length ? <TimeArea data={(ts.data ?? []) as unknown as Record<string, number>[]} series={series} unit={unit} height={260} /> : <Empty>Henüz veri yok. Router'ları bu sunucuya yönlendirin.</Empty>}
      </Card>

      <div className="grid cols-2">
        <Card title="Aktif saldırılar" actions={<a href="#/incidents">Tümü</a>} flush>
          {(inc.data ?? []).length === 0 ? (
            <Empty>Aktif saldırı yok</Empty>
          ) : (
            <div className="tbl-wrap">
              <table className="tbl">
                <tbody>
                  {(inc.data ?? []).map((i) => (
                    <tr key={i.id} className="row-link" onClick={() => go("/incidents/" + i.id)}>
                      <td>
                        <Sev s={i.severity} />
                      </td>
                      <td style={{ maxWidth: 260 }}>
                        <div className="cell-main mono trunc">{i.target}</div>
                        <div className="cell-sub trunc">{i.vectors.filter((v) => v.active).map((v) => v.rule_name).join(", ")}</div>
                      </td>
                      <td className="num">
                        {bps(i.cur_bps)}
                        <div className="cell-sub">{duration(Date.now() / 1000 - i.started_at)}</div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
        <Card title="Korunan nesneler" flush>
          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Nesne</th>
                  <th className="num">Gelen</th>
                  <th>Bağlantı kullanımı</th>
                </tr>
              </thead>
              <tbody>
                {(e?.objects ?? []).map((o) => (
                  <tr key={o.id}>
                    <td style={{ maxWidth: 220 }}>
                      <div className="cell-main trunc">
                        {o.name} {o.active_incidents > 0 && <span className="pill active">saldırı</span>}
                      </div>
                      <div className="cell-sub trunc">{o.profile}</div>
                    </td>
                    <td className="num">{bps(o.rates.in_bps)}</td>
                    <td style={{ minWidth: 140 }}>
                      {o.link_capacity_bps ? (
                        <>
                          <Meter value={o.utilization} />
                          <div className="cell-sub">{pct(o.utilization, 1)}</div>
                        </>
                      ) : (
                        <span className="cell-sub">kapasite tanımsız</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      </div>
    </div>
  );
}
