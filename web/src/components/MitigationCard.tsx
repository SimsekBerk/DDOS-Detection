import { useState } from "react";
import { api, Mitigation } from "../api";
import { ago, bps, clock, dateTime, run } from "../lib";
import { Code, Status, Tabs, Tag } from "./ui";

const kindLabel: Record<string, string> = { flowspec: "BGP FlowSpec", rtbh: "RTBH", scrub: "Scrubbing yönlendirme" };
const sourceLabel: Record<string, string> = { rule: "Kural", analyst: "AI analist", manual: "Manuel" };

function flowSpecText(m: Mitigation): string {
  const f = m.flowspec;
  if (!f) return "";
  const parts: string[] = [];
  if (f.destination) parts.push("hedef " + f.destination);
  if (f.source) parts.push("kaynak " + f.source);
  if (f.protocols?.length) parts.push(f.protocols.join("/"));
  if (f.src_ports?.length) parts.push("sport " + f.src_ports.join(","));
  if (f.dst_ports?.length) parts.push("dport " + f.dst_ports.join(","));
  if (f.packet_length) parts.push("boy " + f.packet_length);
  if (f.fragment) parts.push("fragment");
  if (f.tcp_flags_set?.length || f.tcp_flags_not_set?.length) parts.push("tcp " + [...(f.tcp_flags_set ?? []), ...(f.tcp_flags_not_set ?? []).map((x) => "!" + x)].join("&"));
  if (f.icmp_types?.length) parts.push("icmp " + f.icmp_types.join(","));
  parts.push("→ " + (f.action === "rate-limit" ? "rate-limit " + bps(f.rate_bps) : "discard"));
  return parts.join(" · ");
}

export default function MitigationCard({ m, onChange }: { m: Mitigation; onChange?: () => void }) {
  const [tab, setTab] = useState<string>("exabgp");
  const act = async (a: string, label: string) => {
    if (a === "approve" && m.kind === "rtbh" && !window.confirm("RTBH hedefi tamamen erişilemez kılar. Onaylıyor musunuz?")) return;
    await run(label, () => api.post(`/mitigations/${m.id}/${a}`));
    onChange?.();
  };
  const rendered = m.rendered ?? {};
  const tabs = ["exabgp", "gobgp", "junos", "iosxr", "withdraw"].filter((k) => rendered[k]);
  return (
    <div className={"mit " + m.status}>
      <div className="mit-h">
        <div>
          <div className="li-top">
            <Status s={m.status} />
            <b>{kindLabel[m.kind] ?? m.kind}</b>
            <span className="mono">{m.target}</span>
            <Tag>{sourceLabel[m.source] ?? m.source}</Tag>
            <span className="muted small mono">{m.id}</span>
          </div>
          <div className="small">{m.reason}</div>
          {m.flowspec && <div className="mono small fs">{flowSpecText(m)}</div>}
          {m.rtbh && (
            <div className="mono small fs">
              {m.rtbh.prefix} → next-hop {m.rtbh.next_hop} community {m.rtbh.community}
            </div>
          )}
          {m.note && <div className="note small">ℹ {m.note}</div>}
          {m.error && <div className="error-line small">{m.error}</div>}
        </div>
        <div className="mit-a">
          {m.status === "pending" && (
            <>
              <button className="btn primary" onClick={() => act("approve", "Mitigasyon uygulandı")}>
                Onayla ve uygula
              </button>
              <button className="btn" onClick={() => act("reject", "Reddedildi")}>
                Reddet
              </button>
            </>
          )}
          {m.status === "active" && (
            <>
              <button className="btn danger" onClick={() => act("withdraw", "Geri çekildi")}>
                Geri çek
              </button>
              <button className="btn" onClick={() => act("extend", "TTL 30 dk uzatıldı")}>
                +30 dk
              </button>
            </>
          )}
          <div className="small muted r">
            {m.incident_id && (
              <a href={"#/incidents/" + m.incident_id} className="mono">
                {m.incident_id}
              </a>
            )}
            {m.finding_id && (
              <>
                {" "}
                <a href={"#/analyst/" + m.finding_id} className="mono">
                  {m.finding_id}
                </a>
              </>
            )}
            <div>oluşturuldu {ago(m.created_at)}</div>
            {m.status === "active" && m.expires_at ? <div>TTL bitişi {clock(m.expires_at)}</div> : null}
            {m.withdraw_at ? <div>geri çekme {clock(m.withdraw_at)}</div> : null}
          </div>
        </div>
      </div>
      {(m.guardrails ?? []).length > 0 && (
        <div className="guards">
          {(m.guardrails ?? []).map((g, i) => (
            <span key={i} className="small">
              {g}
            </span>
          ))}
        </div>
      )}
      {tabs.length > 0 && (
        <details>
          <summary className="small">Router yapılandırması ({m.driver} sürücüsü)</summary>
          <Tabs value={tab} onChange={setTab} tabs={tabs.map((t) => ({ id: t, label: { exabgp: "ExaBGP", gobgp: "GoBGP", junos: "Junos", iosxr: "IOS-XR", withdraw: "Geri çekme" }[t] ?? t }))} />
          <Code text={rendered[tab] ?? ""} label={tab === "junos" || tab === "iosxr" ? "Şablon — platformunuzda doğrulayın" : "API komutu"} />
        </details>
      )}
      {m.history.length > 0 && (
        <details>
          <summary className="small">Geçmiş ({m.history.length})</summary>
          <ul className="hist">
            {m.history.map((h, i) => (
              <li key={i} className="small">
                <span className="mono">{dateTime(h.t)}</span> <Status s={h.status} /> <b>{h.actor}</b> {h.msg}
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}
