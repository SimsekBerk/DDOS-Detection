import { api, Overview } from "../api";
import { Card, Code, KV, Meter } from "../components/ui";
import { ago, duration, num, usePoll } from "../lib";

export default function SystemPage({ ov }: { ov: Overview | null }) {
  const cfg = usePoll(() => api.get<unknown>("/config"), 30000);
  const e = ov?.engine;
  return (
    <div className="page">
      <div className="page-h">
        <h1>Sistem</h1>
      </div>
      <div className="grid g-2">
        <Card title="Motor">
          <KV
            items={[
              ["Sürüm", ov?.version],
              ["Çalışma süresi", ov ? duration(ov.uptime) : "-"],
              ["Değerlendirme penceresi", e?.window_seconds + " sn"],
              ["Aktif kural serisi", num(e?.series)],
              ["Değerlendirme süresi", (e?.eval_millis ?? 0).toFixed(2) + " ms / sn"],
              ["Flow kayıt / sn", num(e?.records_per_sec)],
              ["Toplam kayıt", num(e?.records_total)],
              ["Düşürülen kayıt (kuyruk dolu)", num(e?.dropped_records)],
              [
                "Flow tamponu",
                <div key="fb">
                  <Meter value={(e?.flowstore_len ?? 0) / (e?.flowstore_cap || 1)} tone="blue" />
                  <span className="small">
                    {num(e?.flowstore_len)} / {num(e?.flowstore_cap)} · en eski {ago(e?.oldest_flow)}
                  </span>
                </div>,
              ],
              ["Kurallar", `${e?.rules_active ?? 0} aktif / ${e?.rules ?? 0}`],
              ["Dinlenen portlar", (ov?.listening ?? []).join(", ")],
            ]}
          />
        </Card>
        <Card title="Mitigasyon ve analist">
          <KV
            items={[
              ["Mitigasyon modu", ov?.mitigation.mode],
              ["Sürücü", ov?.mitigation.driver],
              ["Analist sağlayıcı", `${ov?.analyst.provider} (${ov?.analyst.model})`],
              ["Yapılandırılan", ov?.analyst.configured_provider],
              ["Otomatik analiz", ov?.analyst.auto_run ? `her ${duration(ov.analyst.interval_seconds)}` : "kapalı"],
              ["Demo simülatörü", ov?.demo ? "açık" : "kapalı"],
            ]}
          />
          {ov?.analyst.note && <div className="note small">ℹ {ov.analyst.note}</div>}
        </Card>
      </div>
      <Card title="Efektif yapılandırma (gizli alanlar maskelendi)">
        <Code text={JSON.stringify(cfg.data, null, 2)} label="config" />
      </Card>
    </div>
  );
}
