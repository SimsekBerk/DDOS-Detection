import { useState } from "react";
import { api, Mitigation } from "../api";
import { useMe } from "../auth";
import { ago, bps, clock, dateTime, run } from "../lib";
import { Code, Status, Tabs } from "./ui";

const kindLabel: Record<string, string> = { flowspec: "FlowSpec", rtbh: "RTBH (kara delik)", scrub: "Scrubbing" };
const sourceLabel: Record<string, string> = { rule: "kural", analyst: "AI analist", manual: "manuel" };

/** summary renders a FlowSpec/RTBH rule as one readable line. */
export function mitigationSummary(m: Mitigation): string {
  const f = m.flowspec;
  if (f) {
    const p: string[] = [];
    if (f.destination) p.push("hedef " + f.destination);
    if (f.source) p.push("kaynak " + f.source);
    if (f.protocols?.length) p.push(f.protocols.join("/"));
    if (f.src_ports?.length) p.push("kaynak port " + f.src_ports.join(","));
    if (f.dst_ports?.length) p.push("hedef port " + f.dst_ports.join(","));
    if (f.packet_length) p.push("paket " + f.packet_length);
    if (f.fragment) p.push("fragment");
    if (f.tcp_flags_set?.length || f.tcp_flags_not_set?.length) p.push("tcp " + [...(f.tcp_flags_set ?? []), ...(f.tcp_flags_not_set ?? []).map((x) => "!" + x)].join("&"));
    if (f.icmp_types?.length) p.push("icmp " + f.icmp_types.join(","));
    p.push(f.action === "rate-limit" ? "→ " + bps(f.rate_bps) + " sınırla" : "→ düşür");
    return p.join(" · ");
  }
  if (m.rtbh) return `${m.rtbh.prefix} → next-hop ${m.rtbh.next_hop}, community ${m.rtbh.community}`;
  return "Trafik scrubbing merkezine yönlendirilir";
}

export default function MitigationCard({ m, onChange }: { m: Mitigation; onChange?: () => void }) {
  const me = useMe();
  const [tab, setTab] = useState("exabgp");
  const act = async (a: string, label: string) => {
    if (a === "approve" && m.kind === "rtbh" && !window.confirm("RTBH hedefi tamamen erişilemez kılar. Onaylıyor musunuz?")) return;
    await run(label, () => api.post(`/mitigations/${m.id}/${a}`));
    onChange?.();
  };
  const rendered = m.rendered ?? {};
  const tabs = ["exabgp", "gobgp", "junos", "iosxr", "withdraw"].filter((k) => rendered[k]);
  const names: Record<string, string> = { exabgp: "ExaBGP", gobgp: "GoBGP", junos: "Junos", iosxr: "IOS-XR", withdraw: "Geri çekme" };
  return (
    <div className="item">
      <div className="item-head">
        <div className="grow">
          <div className="row">
            <Status s={m.status} />
            <span className="item-title">
              {kindLabel[m.kind] ?? m.kind} · <span className="mono">{m.target}</span>
            </span>
          </div>
          <div className="mono small ink2 wrap" style={{ marginTop: 6 }}>
            {mitigationSummary(m)}
          </div>
          <div className="small muted" style={{ marginTop: 4 }}>
            {m.reason} · {sourceLabel[m.source] ?? m.source} · {ago(m.created_at)}
            {m.status === "active" && m.expires_at ? ` · bitiş ${clock(m.expires_at)}` : ""}
            {m.incident_id && (
              <>
                {" · "}
                <a href={"#/incidents/" + m.incident_id}>{m.incident_id}</a>
              </>
            )}
          </div>
          {m.note && <div className="note small" style={{ marginTop: 8 }}>{m.note}</div>}
          {m.error && <div className="alert-line small" style={{ marginTop: 8 }}>{m.error}</div>}
        </div>
        {me.can_operate && (
          <div className="row">
            {m.status === "pending" && (
              <>
                <button className="btn primary" onClick={() => act("approve", "Mitigasyon uygulandı")}>
                  Onayla
                </button>
                <button className="btn" onClick={() => act("reject", "Reddedildi")}>
                  Reddet
                </button>
              </>
            )}
            {m.status === "active" && (
              <>
                <button className="btn" onClick={() => act("extend", "Süre 30 dk uzatıldı")}>
                  +30 dk
                </button>
                <button className="btn danger" onClick={() => act("withdraw", "Geri çekildi")}>
                  Geri çek
                </button>
              </>
            )}
          </div>
        )}
      </div>
      <details style={{ marginTop: 10 }}>
        <summary>Ayrıntılar</summary>
        <div className="stack" style={{ marginTop: 10 }}>
          {(m.guardrails ?? []).length > 0 && (
            <div className="small ink2">
              <b>Güvenlik kontrolleri:</b> {(m.guardrails ?? []).join(" · ")}
            </div>
          )}
          {tabs.length > 0 && (
            <div>
              <Tabs value={tab} onChange={setTab} tabs={tabs.map((t) => ({ id: t, label: names[t] ?? t }))} />
              <Code text={rendered[tab] ?? ""} label={tab === "junos" || tab === "iosxr" ? "Şablon — cihazınızda doğrulayın" : `${m.driver} sürücüsü komutu`} />
            </div>
          )}
          <div className="small">
            {m.history.map((h, i) => (
              <div key={i} className="ink2">
                <span className="mono">{dateTime(h.t)}</span> · {h.status} · {h.actor} {h.msg ? "· " + h.msg : ""}
              </div>
            ))}
          </div>
        </div>
      </details>
    </div>
  );
}
