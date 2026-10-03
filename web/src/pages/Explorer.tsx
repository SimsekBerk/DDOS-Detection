import { FormEvent, useEffect, useState } from "react";
import { api, Breakdown, FlowFilter, SampleFlow, TargetRuleState, TopResult } from "../api";
import { ThresholdLine } from "../components/charts";
import { Bars, Card, Empty, ErrorLine, Field, Kpi, Meter, PageHead, Seg } from "../components/ui";
import { bps, go, num, pct, pps, usePoll } from "../lib";
import { SampleTable } from "./IncidentDetail";

const dims: [string, string][] = [
  ["src_ip", "Kaynak IP"],
  ["dst_ip", "Hedef IP"],
  ["src_port", "Kaynak port"],
  ["dst_port", "Hedef port"],
  ["protocol", "Protokol"],
  ["src_net", "Kaynak ağ"],
  ["packet_size", "Paket boyu"],
  ["tcp_flags", "TCP flag"],
  ["exporter", "Exporter"],
  ["object", "Nesne"],
];

export default function ExplorerPage({ target }: { target?: string }) {
  const [tab, setTab] = useState<"flows" | "target">(target ? "target" : "flows");
  useEffect(() => {
    if (target) setTab("target");
  }, [target]);
  return (
    <div className="page">
      <PageHead title="Trafik gezgini" desc="Son flow kayıtları üzerinde sorgu ve bir IP adresi için kural bazında durum analizi." />
      <Seg
        value={tab}
        onChange={(t) => {
          setTab(t);
          if (t === "flows") go("/explorer");
        }}
        options={[
          { id: "flows", label: "Flow sorgusu" },
          { id: "target", label: "Hedef analizi" },
        ]}
      />
      {tab === "flows" ? <FlowQuery /> : <TargetAnalysis ip={target} />}
    </div>
  );
}

function FlowQuery() {
  const [f, setF] = useState<FlowFilter>({ seconds: 60, direction: "inbound" });
  const [dim, setDim] = useState("dst_ip");
  const [view, setView] = useState<"top" | "samples">("top");
  const [top, setTop] = useState<TopResult | null>(null);
  const [bd, setBd] = useState<Breakdown | null>(null);
  const [samples, setSamples] = useState<SampleFlow[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const query = async (e?: FormEvent) => {
    e?.preventDefault();
    setBusy(true);
    setErr(null);
    const filter = Object.fromEntries(Object.entries(f).filter(([, v]) => v !== "" && v !== undefined && !(typeof v === "number" && isNaN(v))));
    try {
      const [t, b, s] = await Promise.all([
        api.post<TopResult>("/flows/top", { filter, dimension: dim, metric: "bps", limit: 20 }),
        api.post<Breakdown>("/flows/breakdown", { filter }),
        api.post<SampleFlow[]>("/flows/samples", { filter, limit: 100 }),
      ]);
      setTop(t);
      setBd(b);
      setSamples(s);
    } catch (e2) {
      setErr((e2 as Error).message);
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => {
    void query();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dim]);
  const set = (k: keyof FlowFilter, numeric = false) => (e: { target: { value: string } }) =>
    setF({ ...f, [k]: e.target.value === "" ? undefined : numeric ? Number(e.target.value) : e.target.value });

  return (
    <>
      <Card>
        <form className="form" onSubmit={query}>
          <Field label="Hedef IP / prefix">
            <input value={f.dst ?? ""} onChange={set("dst")} placeholder="198.51.100.0/24" />
          </Field>
          <Field label="Kaynak IP / prefix">
            <input value={f.src ?? ""} onChange={set("src")} />
          </Field>
          <Field label="Protokol">
            <select value={f.protocol ?? ""} onChange={set("protocol")}>
              <option value="">hepsi</option>
              <option>tcp</option>
              <option>udp</option>
              <option>icmp</option>
              <option>gre</option>
            </select>
          </Field>
          <Field label="Yön">
            <select value={f.direction ?? ""} onChange={set("direction")}>
              <option value="">hepsi</option>
              <option value="inbound">gelen</option>
              <option value="outbound">giden</option>
            </select>
          </Field>
          <Field label="Kaynak port">
            <input type="number" value={f.src_port ?? ""} onChange={set("src_port", true)} />
          </Field>
          <Field label="Hedef port">
            <input type="number" value={f.dst_port ?? ""} onChange={set("dst_port", true)} />
          </Field>
          <Field label="Zaman penceresi">
            <select value={String(f.seconds ?? 60)} onChange={set("seconds", true)}>
              <option value="30">30 sn</option>
              <option value="60">1 dk</option>
              <option value="300">5 dk</option>
              <option value="900">15 dk</option>
            </select>
          </Field>
          <Field label="Gruplama">
            <select value={dim} onChange={(e) => setDim(e.target.value)}>
              {dims.map(([k, l]) => (
                <option key={k} value={k}>
                  {l}
                </option>
              ))}
            </select>
          </Field>
          <div className="field full">
            <div className="row end">
              <button type="button" className="btn" onClick={() => setF({ seconds: 60 })}>
                Temizle
              </button>
              <button className="btn primary" disabled={busy}>
                {busy ? "Sorgulanıyor…" : "Sorgula"}
              </button>
            </div>
          </div>
        </form>
      </Card>
      <ErrorLine error={err} />
      {bd && (
        <div className="kpis">
          <Kpi label="Toplam" value={bps(bd.total_bps)} sub={pps(bd.total_pps)} />
          <Kpi label="Benzersiz kaynak / hedef" value={`${num(bd.unique_src)} / ${num(bd.unique_dst)}`} />
          <Kpi label="Ortalama paket" value={num(bd.avg_packet_size) + " B"} sub={"fragment " + pct(bd.fragment_share)} />
          <Kpi label="Kayıt" value={num(bd.records)} sub={"örnekleme " + bd.sampling_rates.map((r) => "1:" + r).join(", ")} />
        </div>
      )}
      <Card
        flush
        title={<Seg value={view} onChange={setView} options={[{ id: "top", label: dims.find((d) => d[0] === dim)?.[1] ?? "Top" }, { id: "samples", label: `Kayıtlar (${samples.length})` }]} />}
      >
        <div className="card-body">{view === "top" ? <Bars rows={top?.rows} limit={20} /> : <SampleTable samples={samples} />}</div>
      </Card>
    </>
  );
}

function TargetAnalysis({ ip }: { ip?: string }) {
  const [input, setInput] = useState(ip ?? "");
  useEffect(() => setInput(ip ?? ""), [ip]);
  return (
    <>
      <Card>
        <form
          className="row"
          onSubmit={(e) => {
            e.preventDefault();
            go("/explorer/target/" + input.trim());
          }}
        >
          <input style={{ flex: 1, minWidth: 200 }} value={input} onChange={(e) => setInput(e.target.value)} placeholder="IP adresi, ör. 198.51.100.10" />
          <button className="btn primary">Analiz et</button>
        </form>
        <p className="small muted">Bir IP için her kuralın anlık hızını, efektif eşiğini, normal seviyesini (baseline) ve koşul durumunu gösterir: “dedektör neden tetiklenmedi?” sorusunun cevabı.</p>
      </Card>
      {ip && <TargetState ip={ip} />}
    </>
  );
}

function TargetState({ ip }: { ip: string }) {
  const st = usePoll(() => api.get<TargetRuleState[] | null>(`/target?ip=${encodeURIComponent(ip)}`), 2500, [ip]);
  const [sel, setSel] = useState<string | null>(null);
  const [unit, setUnit] = useState<"pps" | "bps">("pps");
  const rows = (st.data ?? []).slice().sort((a, b) => b.ratio - a.ratio);
  const cur = rows.find((r) => r.rule_id + r.target === sel) ?? rows[0];
  if (st.error) return <ErrorLine error={st.error} />;
  if (!st.data) return <Empty>Yükleniyor…</Empty>;
  if (rows.length === 0) return <Empty>{ip} için son pencerede eşleşen trafik yok.</Empty>;
  return (
    <div className="grid cols-main">
      <Card title={`${ip} — kural durumu`} flush>
        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>Kural</th>
                <th className="num">Hız</th>
                <th>Eşiğe oran</th>
                <th>Durum</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.rule_id + r.target} className="row-link" onClick={() => setSel(r.rule_id + r.target)} style={cur === r ? { background: "var(--surface-2)" } : undefined}>
                  <td style={{ maxWidth: 260 }}>
                    <div className="cell-main trunc">{r.rule_name}</div>
                    <div className="cell-sub trunc">
                      {r.scope === "host" ? "tek hedef" : r.scope === "prefix" ? "blok " + r.target : "nesne"}
                    </div>
                  </td>
                  <td className="num">
                    {pps(r.pps)}
                    <div className="cell-sub">{bps(r.bps)}</div>
                  </td>
                  <td style={{ width: 130 }}>
                    <Meter value={r.ratio} />
                    <div className="cell-sub num">{r.ratio.toFixed(2)}×</div>
                  </td>
                  <td className="small">
                    {r.active ? (
                      <a href={"#/incidents/" + r.incident}>saldırı</a>
                    ) : r.conditions !== "ok" && r.ratio >= 1 ? (
                      <span title={r.conditions}>koşul sağlanmadı</span>
                    ) : r.consecutive_over > 0 ? (
                      `${r.consecutive_over}/${r.sustain_seconds} sn`
                    ) : (
                      <span className="muted">normal</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      {cur && (
        <Card title={cur.rule_name} actions={<Seg value={unit} onChange={setUnit} options={[{ id: "pps", label: "paket/sn" }, { id: "bps", label: "bit/sn" }]} />}>
          <ThresholdLine
            data={(cur.recent_seconds ?? []) as unknown as Record<string, number>[]}
            dataKey={unit}
            unit={unit}
            threshold={unit === "pps" ? cur.threshold_pps : cur.threshold_bps}
            baseline={cur.baseline_ready ? (unit === "pps" ? cur.baseline_pps : cur.baseline_bps) : undefined}
          />
          <dl className="kv" style={{ marginTop: 12 }}>
            <dt>Efektif eşik</dt>
            <dd>
              {cur.threshold_pps ? pps(cur.threshold_pps) : "-"} · {cur.threshold_bps ? bps(cur.threshold_bps) : "-"}
            </dd>
            <dt>Normal seviye</dt>
            <dd>{cur.baseline_ready ? `${pps(cur.baseline_pps)} · ${bps(cur.baseline_bps)}` : "öğreniliyor"}</dd>
            <dt>Koşullar</dt>
            <dd>{cur.conditions === "ok" ? "sağlanıyor" : cur.conditions}</dd>
            <dt>Tetik</dt>
            <dd>{cur.sustain_seconds} sn üst üste eşik aşımı gerekir</dd>
          </dl>
        </Card>
      )}
    </div>
  );
}
