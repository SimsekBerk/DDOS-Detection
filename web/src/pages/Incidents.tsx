import { useMemo, useState } from "react";
import { api, Incident } from "../api";
import { Card, Empty, ErrorLine, Sev, Status, Tabs, Tag } from "../components/ui";
import { bps, categoryLabel, dateTime, duration, go, pps, usePoll } from "../lib";

export default function IncidentsPage() {
  const [status, setStatus] = useState<"active" | "" | "ended">("");
  const [q, setQ] = useState("");
  const [cat, setCat] = useState("");
  const inc = usePoll(() => api.get<Incident[]>(`/incidents?status=${status}&limit=500`), 2500, [status]);

  const cats = useMemo(() => {
    const s = new Set<string>();
    (inc.data ?? []).forEach((i) => i.vectors.forEach((v) => s.add(v.category)));
    return [...s];
  }, [inc.data]);

  const rows = (inc.data ?? []).filter((i) => {
    if (cat && !i.vectors.some((v) => v.category === cat)) return false;
    if (!q) return true;
    const h = (i.id + " " + i.target + " " + i.object_name + " " + i.vectors.map((v) => v.rule_id + " " + v.rule_name).join(" ")).toLowerCase();
    return h.includes(q.toLowerCase());
  });

  return (
    <div className="page">
      <div className="page-h">
        <h1>Saldırılar</h1>
        <div className="muted">Olaylar hedef başına tutulur; aynı hedefe gelen tüm vektörler tek olayda toplanır.</div>
      </div>
      <ErrorLine error={inc.error} />
      <Card
        pad={false}
        title={<Tabs value={status} onChange={setStatus} tabs={[{ id: "", label: "Tümü" }, { id: "active", label: "Aktif" }, { id: "ended", label: "Biten" }]} />}
        actions={
          <>
            <select value={cat} onChange={(e) => setCat(e.target.value)}>
              <option value="">Tüm kategoriler</option>
              {cats.map((c) => (
                <option key={c} value={c}>
                  {categoryLabel[c] ?? c}
                </option>
              ))}
            </select>
            <input placeholder="Ara: IP, kural, nesne…" value={q} onChange={(e) => setQ(e.target.value)} />
          </>
        }
      >
        {rows.length === 0 ? (
          <Empty>Kayıt yok</Empty>
        ) : (
          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Önem</th>
                  <th>Olay</th>
                  <th>Hedef</th>
                  <th>Vektörler</th>
                  <th className="r">Tepe bps</th>
                  <th className="r">Tepe pps</th>
                  <th>Başlangıç</th>
                  <th>Süre</th>
                  <th>Durum</th>
                  <th className="r">Mitigasyon</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((i) => (
                  <tr key={i.id} className="clickable" onClick={() => go("/incidents/" + i.id)}>
                    <td>
                      <Sev s={i.severity} />
                    </td>
                    <td className="mono small">{i.id}</td>
                    <td>
                      <b className="mono">{i.target}</b>
                      <div className="small muted">
                        {i.object_name} · {i.scope === "prefix" ? "prefix (carpet)" : i.scope} · {i.direction}
                      </div>
                    </td>
                    <td>
                      {i.vectors.map((v) => (
                        <Tag key={v.rule_id} tone={v.active ? "on" : ""}>
                          {v.rule_name}
                        </Tag>
                      ))}
                    </td>
                    <td className="r mono">{bps(i.peak_bps)}</td>
                    <td className="r mono">{pps(i.peak_pps)}</td>
                    <td className="small">{dateTime(i.started_at)}</td>
                    <td className="small">{duration((i.ended_at || Date.now() / 1000) - i.started_at)}</td>
                    <td>
                      <Status s={i.status} />
                    </td>
                    <td className="r">{i.mitigations.length}</td>
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
