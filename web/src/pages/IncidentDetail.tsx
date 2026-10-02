import { useState } from "react";
import { api, Finding, Incident, Mitigation } from "../api";
import { StackedArea } from "../components/charts";
import MitigationCard from "../components/MitigationCard";
import { Bars, Card, Empty, ErrorLine, KV, Sev, Stat, Status, Tabs, Tag } from "../components/ui";
import { actionLabel, bps, categoryLabel, classLabel, clock, dateTime, duration, go, num, pct, pps, run, usePoll } from "../lib";

type Detail = { incident: Incident; mitigations: Mitigation[] | null; findings: Finding[] | null };

const evTabs = [
  { id: "top_sources", label: "Kaynak IP" },
  { id: "top_src_ports", label: "Kaynak port" },
  { id: "top_dst_ports", label: "Hedef port" },
  { id: "top_src_nets", label: "Kaynak ağ" },
  { id: "protocols", label: "Protokol" },
  { id: "packet_sizes", label: "Paket boyu" },
  { id: "tcp_flags", label: "TCP flag" },
  { id: "exporters", label: "Exporter" },
  { id: "samples", label: "Örnek flow" },
] as const;
type EvTab = (typeof evTabs)[number]["id"];

export default function IncidentDetail({ id }: { id: string }) {
  const d = usePoll(() => api.get<Detail>("/incidents/" + id), 2000, [id]);
  const [ev, setEv] = useState<EvTab>("top_sources");
  const inc = d.data?.incident;
  if (!inc) return <div className="page">{d.error ? <ErrorLine error={d.error} /> : <Empty>Yükleniyor…</Empty>}</div>;

  const bd = inc.evidence?.breakdown;
  const dur = (inc.ended_at || Date.now() / 1000) - inc.started_at;
  const series = (inc.series ?? []) as unknown as Record<string, number>[];
  const requestReport = async () => {
    const r = await run("AI olay raporu başlatıldı", () => api.post<{ finding_id: string }>(`/analyst/incident/${inc.id}`));
    if (r) window.setTimeout(() => go("/analyst/" + r.finding_id), 1500);
  };

  return (
    <div className="page">
      <div className="page-h">
        <div>
          <a href="#/incidents" className="small">
            ← Saldırılar
          </a>
          <h1>
            <Sev s={inc.severity} /> <span className="mono">{inc.target}</span>
          </h1>
          <div className="muted">
            {inc.id} · {inc.object_name} ({inc.profile}) · {inc.scope === "prefix" ? "prefix / carpet bombing" : inc.scope} · {inc.direction}
            {inc.reopened ? ` · ${inc.reopened} kez yeniden açıldı` : ""}
          </div>
        </div>
        <div className="row">
          <Status s={inc.status} />
          <button className="btn" onClick={() => go("/explorer?dst=" + inc.target)}>
            Flow Explorer
          </button>
          <button className="btn primary" onClick={requestReport}>
            ✦ AI olay raporu
          </button>
        </div>
      </div>
      <ErrorLine error={d.error} />

      <div className="stats">
        <Stat label="Tepe bps" value={bps(inc.peak_bps)} sub={inc.link_capacity_bps ? "bağlantının " + pct(inc.peak_bps / inc.link_capacity_bps) + "'i" : undefined} />
        <Stat label="Tepe pps" value={pps(inc.peak_pps)} />
        <Stat label="Şu an" value={bps(inc.cur_bps)} sub={pps(inc.cur_pps)} />
        <Stat label="Süre" value={duration(dur)} sub={`${dateTime(inc.started_at)} – ${inc.ended_at ? clock(inc.ended_at) : "devam"}`} />
        <Stat label="Benzersiz kaynak" value={num(bd?.unique_src)} sub={bd ? `ort. paket ${num(bd.avg_packet_size)} B` : "kanıt bekleniyor"} />
        <Stat label="Fragment payı" value={bd ? pct(bd.fragment_share) : "-"} sub={bd ? `${num(bd.records)} kayıt` : ""} />
      </div>

      <div className="grid g-2">
        <Card title="Saldırı trafiği (aktif vektörlerin en yükseği)">
          {series.length ? (
            <StackedArea data={series} series={[{ key: "bps", name: "bps", color: "var(--red)" }]} unit="bps" height={220} />
          ) : (
            <Empty>Seri yok</Empty>
          )}
        </Card>
        <Card title="pps">
          {series.length ? <StackedArea data={series} series={[{ key: "pps", name: "pps", color: "var(--amber)" }]} unit="pps" height={220} /> : <Empty>Seri yok</Empty>}
        </Card>
      </div>

      <Card title={`Vektörler (${inc.vectors.length})`} pad={false}>
        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>Kural</th>
                <th>Kategori</th>
                <th>Tetik nedeni</th>
                <th className="r">Eşik</th>
                <th className="r">Şu an</th>
                <th className="r">Tepe</th>
                <th className="r">Ort. paket</th>
                <th>Önerilen aksiyon</th>
                <th>Durum</th>
              </tr>
            </thead>
            <tbody>
              {inc.vectors.map((v) => (
                <tr key={v.rule_id}>
                  <td>
                    <a href={"#/rules?id=" + v.rule_id}>
                      <b>{v.rule_name}</b>
                    </a>
                    <div className="small muted mono">{v.rule_id}</div>
                  </td>
                  <td>
                    <Tag>{categoryLabel[v.category] ?? v.category}</Tag>
                  </td>
                  <td className="small">
                    {v.reason}
                    <div className="muted">{v.trigger_kind === "baseline" ? `baseline ${pps(v.baseline_pps)} / ${bps(v.baseline_bps)}` : "statik eşik"}</div>
                  </td>
                  <td className="r mono small">
                    {v.threshold_pps ? pps(v.threshold_pps) : "-"}
                    <br />
                    {v.threshold_bps ? bps(v.threshold_bps) : ""}
                  </td>
                  <td className="r mono small">
                    {pps(v.cur_pps)}
                    <br />
                    {bps(v.cur_bps)}
                  </td>
                  <td className="r mono small">
                    {pps(v.peak_pps)}
                    <br />
                    {bps(v.peak_bps)}
                  </td>
                  <td className="r mono small">{num(v.avg_packet_size)} B</td>
                  <td className="small">{actionLabel[v.mitigation_action] ?? v.mitigation_action}</td>
                  <td>
                    <Status s={v.active ? "active" : "ended"} />
                    <div className="small muted">{clock(v.started_at)}</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <div className="grid g-3-1">
        <Card title="Kanıt (adli kırılım)" actions={<span className="small muted">son {bd?.seconds ?? 30} sn · güncelleme {clock(inc.evidence?.computed_at)}</span>}>
          <Tabs value={ev} onChange={setEv} tabs={evTabs.map((t) => ({ id: t.id, label: t.label }))} />
          {!bd ? (
            <Empty>Kanıt hesaplanıyor…</Empty>
          ) : ev === "samples" ? (
            <SampleTable samples={inc.evidence?.samples ?? []} />
          ) : (
            <Bars rows={bd[ev]} metric={ev === "packet_sizes" || ev === "tcp_flags" ? "pps" : "bps"} />
          )}
        </Card>
        <Card title="Özet">
          <KV
            items={[
              ["Toplam (kanıt penceresi)", bd ? `${bps(bd.total_bps)} · ${pps(bd.total_pps)}` : "-"],
              ["Benzersiz hedef", num(bd?.unique_dst)],
              ["Örnekleme", bd?.sampling_rates?.map((r) => "1:" + r).join(", ") ?? "-"],
              ["Bağlantı kapasitesi", inc.link_capacity_bps ? bps(inc.link_capacity_bps) : "tanımsız"],
              ["AI bulguları", (d.data?.findings ?? []).length],
            ]}
          />
          {(d.data?.findings ?? []).map((f) => (
            <div key={f.id} className="mini-finding clickable" onClick={() => go("/analyst/" + f.id)}>
              <Sev s={f.severity || "info"} /> <span className="small">{classLabel[f.classification] ?? f.classification}</span>
              <div className="small">{f.title}</div>
            </div>
          ))}
        </Card>
      </div>

      <Card title={`Mitigasyonlar (${(d.data?.mitigations ?? []).length})`}>
        {(d.data?.mitigations ?? []).length === 0 ? (
          <Empty>Bu olay için mitigasyon talebi yok (kural aksiyonu "alarm" veya mod kapalı olabilir).</Empty>
        ) : (
          (d.data?.mitigations ?? []).map((m) => <MitigationCard key={m.id} m={m} onChange={d.reload} />)
        )}
      </Card>
    </div>
  );
}

export function SampleTable({ samples }: { samples: { time: number; src: string; dst: string; src_port: number; dst_port: number; protocol: string; tcp_flags?: string; icmp?: string; fragment?: boolean; packets: number; bytes: number; avg_packet_size: number; sampling_rate: number; exporter: string; source: string }[] }) {
  if (samples.length === 0) return <Empty>Örnek yok</Empty>;
  return (
    <div className="tbl-wrap">
      <table className="tbl small">
        <thead>
          <tr>
            <th>Zaman</th>
            <th>Kaynak</th>
            <th>Hedef</th>
            <th>Proto</th>
            <th>Flag/ICMP</th>
            <th className="r">Paket</th>
            <th className="r">Byte</th>
            <th className="r">Ort.</th>
            <th>Örnekleme</th>
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
                {s.fragment ? <Tag>frag</Tag> : null}
              </td>
              <td className="mono">{s.tcp_flags ?? s.icmp ?? ""}</td>
              <td className="r mono">{num(s.packets)}</td>
              <td className="r mono">{num(s.bytes)}</td>
              <td className="r mono">{num(s.avg_packet_size)}</td>
              <td className="mono">1:{s.sampling_rate}</td>
              <td className="mono">
                {s.exporter} <span className="muted">{s.source}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
