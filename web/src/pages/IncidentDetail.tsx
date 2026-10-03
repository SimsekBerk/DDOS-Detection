import { useState } from "react";
import { api, Finding, Incident, Mitigation, SampleFlow } from "../api";
import { useMe } from "../auth";
import { TimeArea } from "../components/charts";
import MitigationCard from "../components/MitigationCard";
import { Bars, Card, Empty, ErrorLine, Kpi, PageHead, Seg, Sev, Status, Tabs } from "../components/ui";
import { actionLabel, bps, categoryLabel, classLabel, clock, dateTime, duration, go, num, pct, pps, run, usePoll } from "../lib";

type Detail = { incident: Incident; mitigations: Mitigation[]; findings: Finding[] };
type EvTab = "sources" | "ports" | "proto" | "samples";

export default function IncidentDetail({ id }: { id: string }) {
  const me = useMe();
  const d = usePoll(() => api.get<Detail>("/incidents/" + id), 2500, [id]);
  const [unit, setUnit] = useState<"bps" | "pps">("bps");
  const [ev, setEv] = useState<EvTab>("sources");
  const inc = d.data?.incident;
  if (!inc) return <div className="page">{d.error ? <ErrorLine error={d.error} /> : <Empty>Yükleniyor…</Empty>}</div>;

  const bd = inc.evidence?.breakdown;
  const dur = (inc.ended_at || Date.now() / 1000) - inc.started_at;
  const report = async () => {
    const r = await run("AI olay raporu hazırlanıyor", () => api.post<{ finding_id: string }>(`/analyst/incident/${inc.id}`));
    if (r) window.setTimeout(() => go("/analyst/" + r.finding_id), 1500);
  };

  return (
    <div className="page">
      <PageHead
        crumb={<a href="#/incidents">Saldırılar</a>}
        title={
          <span className="row">
            <span className="mono wrap">{inc.target}</span>
            <Status s={inc.status} />
          </span>
        }
        desc={`${inc.object_name} · ${inc.scope === "prefix" ? "blok (carpet bombing)" : inc.scope === "object" ? "nesnenin tamamı" : "tek hedef"} · ${inc.direction === "outbound" ? "giden" : "gelen"} · ${inc.id}`}
        actions={
          <>
            <a className="btn" href={`/api/v1/incidents/${inc.id}/report.md`}>
              Rapor indir
            </a>
            {me.can_operate && !me.objects.length && (
              <button className="btn primary" onClick={report}>
                AI raporu
              </button>
            )}
          </>
        }
      />
      <ErrorLine error={d.error} />
      <div className="kpis">
        <Kpi label="Önem" value={<Sev s={inc.severity} />} sub={`${inc.vectors.length} vektör`} />
        <Kpi label="Tepe" value={bps(inc.peak_bps)} sub={pps(inc.peak_pps) + (inc.link_capacity_bps ? ` · bağlantının ${pct(inc.peak_bps / inc.link_capacity_bps)}'i` : "")} />
        <Kpi label="Şu an" value={bps(inc.cur_bps)} sub={pps(inc.cur_pps)} />
        <Kpi label="Süre" value={duration(dur)} sub={`${dateTime(inc.started_at)}${inc.ended_at ? " – " + clock(inc.ended_at) : ""}`} />
      </div>

      <Card title="Saldırı trafiği" actions={<Seg value={unit} onChange={setUnit} options={[{ id: "bps", label: "bit/sn" }, { id: "pps", label: "paket/sn" }]} />}>
        {(inc.series ?? []).length ? (
          <TimeArea data={(inc.series ?? []) as unknown as Record<string, number>[]} series={[{ key: unit, name: unit === "bps" ? "bit/sn" : "paket/sn", color: "var(--series-1)" }]} unit={unit} height={220} />
        ) : (
          <Empty>Seri yok</Empty>
        )}
      </Card>

      <Card title="Vektörler" flush>
        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>Kural</th>
                <th>Neden tetiklendi</th>
                <th className="num">Tepe</th>
                <th>Önerilen aksiyon</th>
                <th>Durum</th>
              </tr>
            </thead>
            <tbody>
              {inc.vectors.map((v) => (
                <tr key={v.rule_id}>
                  <td style={{ maxWidth: 240 }}>
                    <div className="cell-main">{v.rule_name}</div>
                    <div className="cell-sub">{categoryLabel[v.category] ?? v.category}</div>
                  </td>
                  <td style={{ maxWidth: 320 }}>
                    <div className="small wrap">{v.reason}</div>
                    <div className="cell-sub">ort. paket {num(v.avg_packet_size)} B{v.unique_sources ? ` · ${num(v.unique_sources)} kaynak` : ""}</div>
                  </td>
                  <td className="num">
                    {bps(v.peak_bps)}
                    <div className="cell-sub">{pps(v.peak_pps)}</div>
                  </td>
                  <td className="small">{actionLabel[v.mitigation_action] ?? v.mitigation_action}</td>
                  <td>
                    <Status s={v.active ? "active" : "ended"} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <div className="grid cols-main">
        <Card title="Kanıt" flush actions={bd ? <span className="small muted">son {bd.seconds} sn · {num(bd.unique_src)} kaynak · fragment {pct(bd.fragment_share)}</span> : null}>
          <Tabs
            value={ev}
            onChange={setEv}
            tabs={[
              { id: "sources", label: "Kaynaklar" },
              { id: "ports", label: "Portlar" },
              { id: "proto", label: "Protokol ve boyut" },
              { id: "samples", label: "Örnek kayıtlar" },
            ]}
          />
          <div className="card-body">
            {!bd ? (
              <Empty>Kanıt hesaplanıyor…</Empty>
            ) : ev === "sources" ? (
              <div className="grid cols-2">
                <div>
                  <h3>Kaynak IP</h3>
                  <Bars rows={bd.top_sources} />
                </div>
                <div>
                  <h3>Kaynak ağ</h3>
                  <Bars rows={bd.top_src_nets} />
                </div>
              </div>
            ) : ev === "ports" ? (
              <div className="grid cols-2">
                <div>
                  <h3>Kaynak port</h3>
                  <Bars rows={bd.top_src_ports} />
                </div>
                <div>
                  <h3>Hedef port</h3>
                  <Bars rows={bd.top_dst_ports} />
                </div>
              </div>
            ) : ev === "proto" ? (
              <div className="grid cols-2">
                <div>
                  <h3>Protokol</h3>
                  <Bars rows={bd.protocols} />
                </div>
                <div>
                  <h3>Paket boyu</h3>
                  <Bars rows={bd.packet_sizes} metric="pps" />
                </div>
              </div>
            ) : (
              <SampleTable samples={inc.evidence?.samples ?? []} />
            )}
          </div>
        </Card>
        <Card title="AI bulguları">
          {(d.data?.findings ?? []).length === 0 ? (
            <Empty>Bu olay için henüz analiz yok</Empty>
          ) : (
            (d.data?.findings ?? []).map((f) => (
              <div key={f.id} className="item" style={{ cursor: "pointer" }} onClick={() => go("/analyst/" + f.id)}>
                <div className="row">
                  <Sev s={f.severity || "info"} />
                  <span className="small muted">{classLabel[f.classification] ?? f.classification}</span>
                </div>
                <div className="small" style={{ marginTop: 4 }}>
                  {f.title}
                </div>
              </div>
            ))
          )}
        </Card>
      </div>

      <Card title="Mitigasyonlar">
        {(d.data?.mitigations ?? []).length === 0 ? (
          <Empty>Bu olay için mitigasyon talebi yok</Empty>
        ) : (
          (d.data?.mitigations ?? []).map((m) => <MitigationCard key={m.id} m={m} onChange={d.reload} />)
        )}
      </Card>
    </div>
  );
}

export function SampleTable({ samples }: { samples: SampleFlow[] }) {
  if (samples.length === 0) return <Empty>Örnek yok</Empty>;
  return (
    <div className="tbl-wrap">
      <table className="tbl small">
        <thead>
          <tr>
            <th>Zaman</th>
            <th>Kaynak</th>
            <th>Hedef</th>
            <th>Protokol</th>
            <th className="num">Paket</th>
            <th className="num">Ort. boyut</th>
            <th>Exporter</th>
          </tr>
        </thead>
        <tbody>
          {samples.map((s, i) => (
            <tr key={i}>
              <td className="mono">{clock(s.time)}</td>
              <td className="mono">
                {s.src}
                {s.fragment ? "" : ":" + s.src_port}
              </td>
              <td className="mono">
                {s.dst}
                {s.fragment ? "" : ":" + s.dst_port}
              </td>
              <td>
                {s.protocol}
                {s.tcp_flags ? " " + s.tcp_flags : ""}
                {s.icmp ? " " + s.icmp : ""}
                {s.fragment ? " (fragment)" : ""}
              </td>
              <td className="num">{num(s.packets)}</td>
              <td className="num">{num(s.avg_packet_size)} B</td>
              <td className="mono">
                {s.exporter} <span className="muted">1:{s.sampling_rate}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
