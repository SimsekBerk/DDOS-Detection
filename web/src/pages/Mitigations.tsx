import { useState } from "react";
import { api, Mitigation, Overview } from "../api";
import MitigationCard from "../components/MitigationCard";
import { Card, Empty, ErrorLine, Modal, Stat, Tabs } from "../components/ui";
import { run, usePoll } from "../lib";

export default function MitigationsPage({ ov }: { ov: Overview | null }) {
  const [tab, setTab] = useState<"pending" | "active" | "history">("pending");
  const [creating, setCreating] = useState(false);
  const list = usePoll(() => api.get<Mitigation[]>("/mitigations"), 2500);
  const all = list.data ?? [];
  const shown = all.filter((m) => (tab === "pending" ? m.status === "pending" : tab === "active" ? m.status === "active" : !["pending", "active"].includes(m.status)));

  return (
    <div className="page">
      <div className="page-h">
        <div>
          <h1>Mitigasyon</h1>
          <div className="muted">
            Mod <b>{ov?.mitigation.mode}</b> · sürücü <b>{ov?.mitigation.driver}</b>. Kural ve AI önerileri güvenlik bariyerlerinden geçer; manuel modda her talep onay ister, RTBH ve AI önerileri her zaman onay ister.
          </div>
        </div>
        <button className="btn primary" onClick={() => setCreating(true)}>
          + Manuel FlowSpec
        </button>
      </div>
      <ErrorLine error={list.error} />
      <div className="stats">
        <Stat label="Onay bekleyen" value={all.filter((m) => m.status === "pending").length} tone="t-amber" onClick={() => setTab("pending")} />
        <Stat label="Aktif" value={all.filter((m) => m.status === "active").length} tone="t-red" onClick={() => setTab("active")} />
        <Stat label="Bariyer reddi" value={all.filter((m) => m.status === "rejected" && m.history.some((h) => h.actor === "guardrail")).length} sub="güvenlik bariyeri" onClick={() => setTab("history")} />
        <Stat label="Toplam" value={all.length} onClick={() => setTab("history")} />
      </div>
      <Card title={<Tabs value={tab} onChange={setTab} tabs={[{ id: "pending", label: "Onay bekleyen" }, { id: "active", label: "Aktif" }, { id: "history", label: "Geçmiş" }]} />}>
        {shown.length === 0 ? <Empty>Kayıt yok</Empty> : shown.map((m) => <MitigationCard key={m.id} m={m} onChange={list.reload} />)}
      </Card>
      {creating && <CreateFlowSpec onClose={() => setCreating(false)} onDone={list.reload} />}
    </div>
  );
}

function CreateFlowSpec({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [f, setF] = useState({ destination: "", protocol: "udp", src_ports: "", dst_ports: "", packet_length: "", action: "discard", rate: "10000000", reason: "" });
  const set = (k: string) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  const submit = async () => {
    const dst = f.destination.includes("/") ? f.destination : f.destination + (f.destination.includes(":") ? "/128" : "/32");
    const body = {
      kind: "flowspec",
      reason: f.reason,
      flowspec: {
        destination: dst,
        protocols: f.protocol ? [f.protocol] : undefined,
        src_ports: f.src_ports ? f.src_ports.split(",").map((s) => s.trim()) : undefined,
        dst_ports: f.dst_ports ? f.dst_ports.split(",").map((s) => s.trim()) : undefined,
        packet_length: f.packet_length || undefined,
        action: f.action,
        rate_bps: f.action === "rate-limit" ? Number(f.rate) : undefined,
      },
    };
    const r = await run("FlowSpec talebi oluşturuldu (onay bekliyor)", () => api.post("/mitigations", body));
    if (r) {
      onDone();
      onClose();
    }
  };
  return (
    <Modal title="Manuel FlowSpec talebi" onClose={onClose}>
      <div className="form">
        <label>
          Hedef IP / prefix
          <input value={f.destination} onChange={set("destination")} placeholder="198.51.100.10 veya 198.51.100.0/24" />
        </label>
        <label>
          Protokol
          <select value={f.protocol} onChange={set("protocol")}>
            <option value="">(hepsi)</option>
            <option>udp</option>
            <option>tcp</option>
            <option>icmp</option>
            <option>gre</option>
          </select>
        </label>
        <label>
          Kaynak port(lar)
          <input value={f.src_ports} onChange={set("src_ports")} placeholder="53, 123 veya 1024-65535" />
        </label>
        <label>
          Hedef port(lar)
          <input value={f.dst_ports} onChange={set("dst_ports")} />
        </label>
        <label>
          Paket boyu
          <input value={f.packet_length} onChange={set("packet_length")} placeholder=">=512" />
        </label>
        <label>
          Aksiyon
          <select value={f.action} onChange={set("action")}>
            <option value="discard">discard</option>
            <option value="rate-limit">rate-limit</option>
          </select>
        </label>
        {f.action === "rate-limit" && (
          <label>
            Oran (bps)
            <input value={f.rate} onChange={set("rate")} />
          </label>
        )}
        <label className="full">
          Gerekçe
          <input value={f.reason} onChange={set("reason")} placeholder="Ticket / açıklama" />
        </label>
      </div>
      <p className="small muted">Talep güvenlik bariyerlerinden geçer (korunan alan, never_mitigate, prefix uzunluğu, aktif kural limiti) ve onay kuyruğuna düşer.</p>
      <div className="row end">
        <button className="btn" onClick={onClose}>
          Vazgeç
        </button>
        <button className="btn primary" onClick={submit} disabled={!f.destination}>
          Talep oluştur
        </button>
      </div>
    </Modal>
  );
}
