import { useState } from "react";
import { api, Incident } from "../api";
import { Card, Empty, ErrorLine, PageHead, Seg, Sev, Status } from "../components/ui";
import { bps, dateTime, duration, go, pps, usePoll } from "../lib";

export default function IncidentsPage() {
  const [status, setStatus] = useState<"" | "active" | "ended">("");
  const [q, setQ] = useState("");
  const inc = usePoll(() => api.get<Incident[]>(`/incidents?status=${status}&limit=500`), 3000, [status]);
  const rows = (inc.data ?? []).filter((i) => {
    if (!q) return true;
    const h = (i.id + " " + i.target + " " + i.object_name + " " + i.vectors.map((v) => v.rule_id + " " + v.rule_name).join(" ")).toLowerCase();
    return h.includes(q.toLowerCase());
  });
  return (
    <div className="page">
      <PageHead
        title="Saldırılar"
        desc="Aynı hedefe gelen tüm saldırı vektörleri tek olayda toplanır."
        actions={
          <a className="btn" href={`/api/v1/incidents/export.csv?status=${status}`}>
            CSV indir
          </a>
        }
      />
      <ErrorLine error={inc.error} />
      <Card
        flush
        title={<Seg value={status} onChange={setStatus} options={[{ id: "", label: "Tümü" }, { id: "active", label: "Aktif" }, { id: "ended", label: "Biten" }]} />}
        actions={<input placeholder="IP, nesne veya kural ara" value={q} onChange={(e) => setQ(e.target.value)} />}
      >
        {rows.length === 0 ? (
          <Empty>{inc.data ? "Kayıt yok" : "Yükleniyor…"}</Empty>
        ) : (
          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Önem</th>
                  <th>Hedef</th>
                  <th>Vektör</th>
                  <th className="num">Tepe</th>
                  <th>Başlangıç</th>
                  <th>Durum</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((i) => (
                  <tr key={i.id} className="row-link" onClick={() => go("/incidents/" + i.id)}>
                    <td>
                      <Sev s={i.severity} />
                    </td>
                    <td>
                      <div className="cell-main mono trunc" style={{ maxWidth: 200 }}>{i.target}</div>
                      <div className="cell-sub trunc">
                        {i.object_name}
                        {i.scope === "prefix" ? " · blok" : ""}
                        {i.direction === "outbound" ? " · giden" : ""}
                      </div>
                    </td>
                    <td>
                      <div className="trunc" style={{ maxWidth: 200 }}>{i.vectors[0]?.rule_name}</div>
                      {i.vectors.length > 1 && <div className="cell-sub">+{i.vectors.length - 1} vektör</div>}
                    </td>
                    <td className="num">
                      {bps(i.peak_bps)}
                      <div className="cell-sub">{pps(i.peak_pps)}</div>
                    </td>
                    <td className="small nowrap">
                      {dateTime(i.started_at)}
                      <div className="cell-sub">{duration((i.ended_at || Date.now() / 1000) - i.started_at)} sürdü</div>
                    </td>
                    <td>
                      <Status s={i.status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
