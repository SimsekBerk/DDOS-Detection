import { useEffect, useState } from "react";
import { api, Breakdown, FlowFilter, SampleFlow, TopResult } from "../api";
import { Bars, Card, Empty, ErrorLine, KV, Tabs } from "../components/ui";
import { bps, num, pct, pps } from "../lib";
import { SampleTable } from "./IncidentDetail";

const dims = [
  ["src_ip", "Kaynak IP"],
  ["dst_ip", "Hedef IP"],
  ["src_port", "Kaynak port"],
  ["dst_port", "Hedef port"],
  ["protocol", "Protokol"],
  ["tcp_flags", "TCP flag"],
  ["packet_size", "Paket boyu"],
  ["src_net", "Kaynak ağ (/24)"],
  ["dst_net", "Hedef ağ (/24)"],
  ["exporter", "Exporter"],
  ["in_if", "Giriş arayüzü"],
  ["src_as", "Kaynak AS"],
  ["icmp_type", "ICMP tipi"],
  ["direction", "Yön"],
  ["object", "Nesne"],
  ["fragment", "Fragment"],
];

function initialFilter(): FlowFilter {
  const q = new URLSearchParams(window.location.hash.split("?")[1] ?? "");
  const f: FlowFilter = { seconds: 60 };
  if (q.get("dst")) f.dst = q.get("dst")!;
  if (q.get("src")) f.src = q.get("src")!;
  return f;
}

export default function ExplorerPage() {
  const [f, setF] = useState<FlowFilter>(initialFilter);
  const [dim, setDim] = useState("src_ip");
  const [metric, setMetric] = useState<"bps" | "pps" | "fps">("bps");
  const [tab, setTab] = useState<"top" | "breakdown" | "samples">("top");
  const [top, setTop] = useState<TopResult | null>(null);
  const [bd, setBd] = useState<Breakdown | null>(null);
  const [samples, setSamples] = useState<SampleFlow[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const clean = (x: FlowFilter): FlowFilter => {
    const o: Record<string, unknown> = {};
    Object.entries(x).forEach(([k, v]) => {
      if (v !== "" && v !== undefined && v !== null && !(typeof v === "number" && isNaN(v))) o[k] = v;
    });
    return o as FlowFilter;
  };

  const query = async () => {
    setBusy(true);
    setErr(null);
    try {
      const filter = clean(f);
      const [t, b, s] = await Promise.all([
        api.post<TopResult>("/flows/top", { filter, dimension: dim, metric, limit: 25 }),
        api.post<Breakdown>("/flows/breakdown", { filter }),
        api.post<SampleFlow[]>("/flows/samples", { filter, limit: 100 }),
      ]);
      setTop(t);
      setBd(b);
      setSamples(s);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => {
    void query();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dim, metric]);

  const set = (k: keyof FlowFilter, numeric = false) => (e: { target: { value: string } }) =>
    setF({ ...f, [k]: e.target.value === "" ? undefined : numeric ? Number(e.target.value) : e.target.value });

  return (
    <div className="page">
      <div className="page-h">
        <div>
          <h1>Flow Explorer</h1>
          <div className="muted">Bellekteki son flow kayıtları üzerinde ad-hoc sorgu (örnekleme ile ölçeklenmiş). Üretimde bu katman ClickHouse ile değiştirilir.</div>
        </div>
      </div>
      <Card title="Filtre">
        <form
          className="form filters"
          onSubmit={(e) => {
            e.preventDefault();
            void query();
          }}
        >
          <label>
            Pencere (sn)
            <input type="number" value={f.seconds ?? 60} onChange={set("seconds", true)} />
          </label>
          <label>
            Yön
            <select value={f.direction ?? ""} onChange={set("direction")}>
              <option value="">hepsi</option>
              <option value="inbound">inbound</option>
              <option value="outbound">outbound</option>
              <option value="other">other</option>
            </select>
          </label>
          <label>
            Kaynak IP/prefix
            <input value={f.src ?? ""} onChange={set("src")} />
          </label>
          <label>
            Hedef IP/prefix
            <input value={f.dst ?? ""} onChange={set("dst")} />
          </label>
          <label>
            Protokol
            <input value={f.protocol ?? ""} onChange={set("protocol")} placeholder="udp, tcp, 47…" />
          </label>
          <label>
            Kaynak port
            <input type="number" value={f.src_port ?? ""} onChange={set("src_port", true)} />
          </label>
          <label>
            Hedef port
            <input type="number" value={f.dst_port ?? ""} onChange={set("dst_port", true)} />
          </label>
          <label>
            TCP flag (tam)
            <input value={f.tcp_flags ?? ""} onChange={set("tcp_flags")} placeholder="SYN veya SYN|ACK" />
          </label>
          <label>
            Grupla
            <select value={dim} onChange={(e) => setDim(e.target.value)}>
              {dims.map(([k, l]) => (
                <option key={k} value={k}>
                  {l}
                </option>
              ))}
            </select>
          </label>
          <label>
            Metrik
            <select value={metric} onChange={(e) => setMetric(e.target.value as "bps")}>
              <option value="bps">bps</option>
              <option value="pps">pps</option>
              <option value="fps">fps</option>
            </select>
          </label>
          <div className="row end full">
            <button className="btn" type="button" onClick={() => setF({ seconds: 60 })}>
              Temizle
            </button>
            <button className="btn primary" disabled={busy}>
              {busy ? "Sorgulanıyor…" : "Sorgula"}
            </button>
          </div>
        </form>
      </Card>
      <ErrorLine error={err} />
      {bd && (
        <div className="stats">
          <div className="stat">
            <div className="stat-l">Toplam</div>
            <div className="stat-v">{bps(bd.total_bps)}</div>
            <div className="stat-s">{pps(bd.total_pps)}</div>
          </div>
          <div className="stat">
            <div className="stat-l">Kayıt</div>
            <div className="stat-v">{num(bd.records)}</div>
            <div className="stat-s">{bd.seconds} sn</div>
          </div>
          <div className="stat">
            <div className="stat-l">Benzersiz kaynak / hedef</div>
            <div className="stat-v">
              {num(bd.unique_src)} / {num(bd.unique_dst)}
            </div>
          </div>
          <div className="stat">
            <div className="stat-l">Ort. paket</div>
            <div className="stat-v">{num(bd.avg_packet_size)} B</div>
            <div className="stat-s">fragment {pct(bd.fragment_share)}</div>
          </div>
        </div>
      )}
      <Card pad={false} title={<Tabs value={tab} onChange={setTab} tabs={[{ id: "top", label: "Top-N" }, { id: "breakdown", label: "Kırılım" }, { id: "samples", label: `Ham kayıtlar (${samples.length})` }]} />}>
        <div className="card-b">
          {tab === "top" &&
            (top && top.rows.length ? (
              <>
                <Bars rows={top.rows} metric={metric === "pps" ? "pps" : "bps"} limit={25} />
                <table className="tbl small" style={{ marginTop: 12 }}>
                  <thead>
                    <tr>
                      <th>{dims.find((d) => d[0] === dim)?.[1]}</th>
                      <th className="r">bps</th>
                      <th className="r">pps</th>
                      <th className="r">fps</th>
                      <th className="r">Pay</th>
                      <th className="r">Kayıt</th>
                    </tr>
                  </thead>
                  <tbody>
                    {top.rows.map((r) => (
                      <tr key={r.key}>
                        <td className="mono">{r.key}</td>
                        <td className="r mono">{bps(r.bps)}</td>
                        <td className="r mono">{pps(r.pps)}</td>
                        <td className="r mono">{r.fps.toFixed(1)}</td>
                        <td className="r mono">{pct(r.share, 1)}</td>
                        <td className="r mono">{num(r.records)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            ) : (
              <Empty>Sonuç yok</Empty>
            ))}
          {tab === "breakdown" &&
            (bd ? (
              <div className="grid g-3">
                <div>
                  <h4>Protokol</h4>
                  <Bars rows={bd.protocols} />
                </div>
                <div>
                  <h4>Paket boyu</h4>
                  <Bars rows={bd.packet_sizes} metric="pps" />
                </div>
                <div>
                  <h4>TCP flag</h4>
                  <Bars rows={bd.tcp_flags} metric="pps" />
                </div>
                <div>
                  <h4>Kaynak port</h4>
                  <Bars rows={bd.top_src_ports} />
                </div>
                <div>
                  <h4>Hedef port</h4>
                  <Bars rows={bd.top_dst_ports} />
                </div>
                <div>
                  <h4>Kaynak ağlar</h4>
                  <Bars rows={bd.top_src_nets} />
                </div>
                <div>
                  <KV items={[["Örnekleme oranları", bd.sampling_rates.map((r) => "1:" + r).join(", ")], ["Exporter", bd.exporters.map((e) => e.key).join(", ")]]} />
                </div>
              </div>
            ) : (
              <Empty>-</Empty>
            ))}
          {tab === "samples" && <SampleTable samples={samples} />}
        </div>
      </Card>
    </div>
  );
}
