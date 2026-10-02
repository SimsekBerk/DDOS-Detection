import { useState } from "react";
import { api, Finding, Incident, Overview, TargetRuleState, TopResult, TotalPoint } from "../api";
import { StackedArea } from "../components/charts";
import { Bars, Card, Empty, ErrorLine, Meter, Sev, Stat, Tabs, Tag } from "../components/ui";
import { ago, bps, classLabel, duration, go, num, pct, pps, usePoll } from "../lib";

const ranges = [
  { id: "900", label: "15 dk" },
  { id: "3600", label: "1 sa" },
  { id: "86400", label: "24 sa" },
] as const;

export default function OverviewPage({ ov }: { ov: Overview | null }) {
  const [range, setRange] = useState<"900" | "3600" | "86400">("900");
  const [view, setView] = useState<"dir" | "proto" | "pps">("dir");
  const ts = usePoll(() => api.get<TotalPoint[]>(`/timeseries?range=${range}`), 3000, [range]);
  const inc = usePoll(() => api.get<Incident[]>("/incidents?status=active&limit=8"), 2000);
  const hot = usePoll(() => api.get<TargetRuleState[]>("/series/top?limit=8"), 3000);
  const finds = usePoll(() => api.get<Finding[]>("/analyst/findings?limit=4"), 5000);
  const topDst = usePoll(() => api.post<TopResult>("/flows/top", { filter: { seconds: 30, direction: "inbound" }, dimension: "dst_ip", metric: "bps", limit: 8 }), 4000);
  const topPort = usePoll(() => api.post<TopResult>("/flows/top", { filter: { seconds: 30, direction: "inbound" }, dimension: "src_port", metric: "bps", limit: 8 }), 4000);

  const e = ov?.engine;
  const data = (ts.data ?? []) as unknown as Record<string, number>[];
  const series =
    view === "dir"
      ? [
          { key: "in_bps", name: "Inbound", color: "var(--accent)" },
          { key: "out_bps", name: "Outbound", color: "var(--violet)" },
        ]
      : view === "proto"
        ? [
            { key: "tcp_bps", name: "TCP", color: "var(--accent)" },
            { key: "udp_bps", name: "UDP", color: "var(--amber)" },
            { key: "icmp_bps", name: "ICMP", color: "var(--green)" },
            { key: "other_proto_bps", name: "Diğer", color: "var(--violet)" },
          ]
        : [
            { key: "in_pps", name: "Inbound pps", color: "var(--accent)" },
            { key: "out_pps", name: "Outbound pps", color: "var(--violet)" },
          ];

  return (
    <div className="page">
      <div className="page-h">
        <h1>Genel Bakış</h1>
        <div className="muted">Son {e?.window_seconds ?? 10} sn penceresi · {e?.rules_active ?? 0}/{e?.rules ?? 0} kural aktif</div>
      </div>
      <ErrorLine error={ts.error} />
      <div className="stats">
        <Stat label="Inbound" value={bps(e?.global.in_bps)} sub={pps(e?.global.in_pps)} />
        <Stat label="Outbound" value={bps(e?.global.out_bps)} sub={pps(e?.global.out_pps)} />
        <Stat label="Flow kayıt / sn" value={num(e?.records_per_sec)} sub={e && e.dropped_records > 0 ? <span className="red">{num(e.dropped_records)} düşürüldü</span> : "kayıp yok"} />
        <Stat label="Aktif saldırı" value={e?.active_incidents ?? 0} tone={(e?.active_incidents ?? 0) > 0 ? "t-red" : ""} sub={`toplam ${e?.total_incidents ?? 0}`} onClick={() => go("/incidents")} />
        <Stat label="Onay bekleyen" value={ov?.mitigation.pending ?? 0} tone={(ov?.mitigation.pending ?? 0) > 0 ? "t-amber" : ""} sub={`${ov?.mitigation.active ?? 0} aktif kural`} onClick={() => go("/mitigations")} />
        <Stat label="Aday sinyal" value={e?.pending_signals ?? 0} tone={(e?.pending_signals ?? 0) > 0 ? "t-blue" : ""} sub="AI analist için" onClick={() => go("/analyst")} />
        <Stat label="Exporter" value={`${ov?.exporters_up ?? 0}/${ov?.exporters_total ?? 0}`} sub="son 60 sn aktif" onClick={() => go("/exporters")} />
      </div>

      <div className="grid g-3-1">
        <Card
          title="Trafik"
          actions={
            <>
              <Tabs value={view} onChange={setView} tabs={[{ id: "dir", label: "Yön" }, { id: "proto", label: "Protokol" }, { id: "pps", label: "pps" }]} />
              <Tabs value={range} onChange={setRange} tabs={ranges.map((r) => ({ id: r.id, label: r.label }))} />
            </>
          }
        >
          {data.length ? <StackedArea data={data} series={series} unit={view === "pps" ? "pps" : "bps"} height={260} stacked={view === "proto"} /> : <Empty>Henüz veri yok — exporter'ları bu sunucuya yönlendirin veya simülatörü başlatın.</Empty>}
        </Card>
        <Card title="Aktif saldırılar" actions={<a href="#/incidents">Tümü →</a>} pad={false}>
          {(inc.data ?? []).length === 0 ? (
            <Empty>Aktif saldırı yok</Empty>
          ) : (
            <ul className="list">
              {(inc.data ?? []).map((i) => (
                <li key={i.id} className="clickable" onClick={() => go("/incidents/" + i.id)}>
                  <div className="li-top">
                    <Sev s={i.severity} />
                    <b className="mono">{i.target}</b>
                    <span className="muted">{i.object_name}</span>
                  </div>
                  <div className="li-sub">
                    {i.vectors.filter((v) => v.active).map((v) => (
                      <Tag key={v.rule_id}>{v.rule_name}</Tag>
                    ))}
                  </div>
                  <div className="li-sub muted">
                    {bps(i.cur_bps)} · {pps(i.cur_pps)} · {duration(Date.now() / 1000 - i.started_at)}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <div className="grid g-2">
        <Card title="Korunan nesneler" actions={<a href="#/objects">Detay →</a>} pad={false}>
          <table className="tbl">
            <thead>
              <tr>
                <th>Nesne</th>
                <th>Profil</th>
                <th className="r">Inbound</th>
                <th className="r">pps</th>
                <th>Kullanım</th>
                <th className="r">Olay</th>
              </tr>
            </thead>
            <tbody>
              {(e?.objects ?? []).map((o) => (
                <tr key={o.id}>
                  <td>
                    <b>{o.name}</b>
                    <div className="muted small mono">{o.prefixes.join(", ")}</div>
                  </td>
                  <td>
                    <Tag>{o.profile}</Tag>
                  </td>
                  <td className="r mono">{bps(o.rates.in_bps)}</td>
                  <td className="r mono">{pps(o.rates.in_pps)}</td>
                  <td style={{ minWidth: 120 }}>
                    <Meter value={o.utilization} />
                    <span className="small muted">{o.link_capacity_bps ? pct(o.utilization, 1) : "kapasite tanımsız"}</span>
                  </td>
                  <td className="r">{o.active_incidents > 0 ? <span className="badge tone-red">{o.active_incidents}</span> : <span className="muted">0</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
        <Card title="Eşiğe en yakın kural serileri" actions={<span className="muted small">oran = hız / efektif eşik</span>} pad={false}>
          {(hot.data ?? []).length === 0 ? (
            <Empty>Seri yok</Empty>
          ) : (
            <table className="tbl">
              <tbody>
                {(hot.data ?? []).map((s, i) => (
                  <tr key={i} className="clickable" onClick={() => s.scope === "host" && go("/objects/" + s.target)}>
                    <td>
                      <div className="mono">{s.target}</div>
                      <div className="small muted">{s.rule_name}</div>
                    </td>
                    <td className="r mono small">
                      {bps(s.bps)}
                      <br />
                      {pps(s.pps)}
                    </td>
                    <td style={{ width: 140 }}>
                      <Meter value={s.ratio} />
                      <span className="small mono">{s.ratio.toFixed(2)}×</span>
                    </td>
                    <td>{s.active ? <span className="badge tone-red">olay</span> : null}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>

      <div className="grid g-3">
        <Card title="Top hedefler (inbound, 30 sn)">
          <Bars rows={topDst.data?.rows} onClick={(k) => go("/objects/" + k)} />
        </Card>
        <Card title="Top kaynak portlar (inbound, 30 sn)">
          <Bars rows={topPort.data?.rows} />
        </Card>
        <Card title="Son AI bulguları" actions={<a href="#/analyst">Analist →</a>} pad={false}>
          {(finds.data ?? []).length === 0 ? (
            <Empty>Henüz bulgu yok</Empty>
          ) : (
            <ul className="list">
              {(finds.data ?? []).map((f) => (
                <li key={f.id} className="clickable" onClick={() => go("/analyst/" + f.id)}>
                  <div className="li-top">
                    <Sev s={f.severity || "info"} />
                    <span className="small muted">{classLabel[f.classification] ?? f.classification}</span>
                    <span className="small muted right">{ago(f.created_at)}</span>
                  </div>
                  <div className="li-title">{f.title}</div>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}
