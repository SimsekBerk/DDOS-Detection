import { api, Exporter } from "../api";
import { Card, Empty, ErrorLine, Status, Tag } from "../components/ui";
import { ago, num, usePoll } from "../lib";

export default function ExportersPage() {
  const r = usePoll(() => api.get<{ exporters: Exporter[]; listening: string[] }>("/exporters"), 2500);
  const list = r.data?.exporters ?? [];
  const now = Date.now() / 1000;
  return (
    <div className="page">
      <div className="page-h">
        <div>
          <h1>Telemetri Kaynakları</h1>
          <div className="muted">
            Dinlenen portlar: <span className="mono">{(r.data?.listening ?? []).join(", ")}</span> — her port NetFlow v5/v9, IPFIX ve sFlow v5'i otomatik tanır.
          </div>
        </div>
      </div>
      <ErrorLine error={r.error} />
      <Card pad={false}>
        {list.length === 0 ? (
          <Empty>
            Henüz exporter yok. Router'larınızı bu sunucunun IP'sine yönlendirin (bkz. <span className="mono">docs/ROUTER-CONFIG.md</span>) veya Simülatör'ü başlatın.
          </Empty>
        ) : (
          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Durum</th>
                  <th>Exporter</th>
                  <th>Protokol</th>
                  <th className="r">Kayıt/sn</th>
                  <th className="r">Datagram</th>
                  <th className="r">Kayıt</th>
                  <th>Örnekleme</th>
                  <th className="r">Şablon</th>
                  <th className="r">Kayıp (tahmini)</th>
                  <th className="r">Şablonsuz set</th>
                  <th className="r">Hata</th>
                  <th>Son görülme</th>
                </tr>
              </thead>
              <tbody>
                {list.map((e) => {
                  const up = now - e.last_seen < 60;
                  const eff = e.sampling_override || e.sampling_reported || e.sampling_learned;
                  return (
                    <tr key={e.address}>
                      <td>
                        <Status s={up ? "ok" : "error"} label={up ? "aktif" : "sessiz"} />
                      </td>
                      <td>
                        <b className="mono">{e.address}</b>
                        <div className="small muted">{e.name || "isimsiz"} · {e.listener}</div>
                      </td>
                      <td>
                        {Object.keys(e.protocols).map((p) => (
                          <Tag key={p}>{p}</Tag>
                        ))}
                      </td>
                      <td className="r mono">{num(e.records_per_sec)}</td>
                      <td className="r mono">{num(e.datagrams)}</td>
                      <td className="r mono">{num(e.records)}</td>
                      <td className="small">
                        <b>1:{eff || 1}</b>
                        <div className="muted">
                          {e.sampling_override ? "config override" : e.sampling_reported ? "flow'dan" : e.sampling_learned ? "options template" : "bildirilmedi → varsayılan"}
                        </div>
                      </td>
                      <td className="r mono">{e.templates}</td>
                      <td className={"r mono" + (e.lost_estimate > 0 ? " amber" : "")}>{num(e.lost_estimate)}</td>
                      <td className={"r mono" + (e.missing_template > 0 ? " amber" : "")}>{num(e.missing_template)}</td>
                      <td className={"r mono" + (e.errors > 0 ? " red" : "")} title={e.last_error}>
                        {num(e.errors)}
                      </td>
                      <td className="small">{ago(e.last_seen)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <Card title="Sağlık göstergeleri">
        <ul className="small tips">
          <li>
            <b>Kayıp (tahmini)</b>: sıra numarası boşlukları. Artıyorsa UDP alım tamponu (<span className="mono">net.core.rmem_max</span>) veya ağ yolu sorunu vardır.
          </li>
          <li>
            <b>Şablonsuz set</b>: NetFlow v9/IPFIX şablonu gelmeden gelen veri. Collector yeni başladıysa normaldir; sürekli artıyorsa router'da template timeout'u (ör. 60 sn) düşürün.
          </li>
          <li>
            <b>Örnekleme</b>: Eşikler gerçek trafik üzerinden değerlendirilir; örnekleme oranı yanlışsa tüm eşikler kayar. Router oranı göndermiyorsa config'de <span className="mono">exporters[].sampling_rate</span> ile zorlayın.
          </li>
          <li>
            Algılama hızı için: sFlow tercih edin; NetFlow/IPFIX'te active timeout 10 sn, inactive 15 sn önerilir.
          </li>
        </ul>
      </Card>
    </div>
  );
}
