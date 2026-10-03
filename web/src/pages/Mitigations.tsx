import { useState } from "react";
import { api, Mitigation, Overview } from "../api";
import { useMe } from "../auth";
import MitigationCard from "../components/MitigationCard";
import { Card, Empty, ErrorLine, Field, Modal, PageHead, Seg } from "../components/ui";
import { run, usePoll } from "../lib";

const modeText: Record<string, string> = {
  manual: "Kural ve AI önerileri onay kuyruğuna düşer.",
  auto: "Güvenlik kontrollerinden geçen kural önerileri otomatik uygulanır (RTBH ve AI önerileri hariç).",
  off: "Mitigasyon kapalı; yalnızca algılama ve bildirim yapılır.",
};

export default function MitigationsPage({ ov }: { ov: Overview | null }) {
  const me = useMe();
  const [tab, setTab] = useState<"pending" | "active" | "history">("pending");
  const [creating, setCreating] = useState(false);
  const list = usePoll(() => api.get<Mitigation[]>("/mitigations"), 2500);
  const all = list.data ?? [];
  const count = (s: string) => all.filter((m) => m.status === s).length;
  const shown = all.filter((m) => (tab === "history" ? !["pending", "active"].includes(m.status) : m.status === tab));
  const mode = ov?.mitigation.mode ?? "";
  return (
    <div className="page">
      <PageHead
        title="Mitigasyon"
        desc={`Mod: ${mode} — ${modeText[mode] ?? ""} Sürücü: ${ov?.mitigation.driver ?? "-"}.`}
        actions={
          me.can_operate && (
            <button className="btn" onClick={() => setCreating(true)}>
              Manuel FlowSpec
            </button>
          )
        }
      />
      <ErrorLine error={list.error} />
      <Card
        flush
        title={
          <Seg
            value={tab}
            onChange={setTab}
            options={[
              { id: "pending", label: `Onay bekleyen (${count("pending")})` },
              { id: "active", label: `Uygulanan (${count("active")})` },
              { id: "history", label: "Geçmiş" },
            ]}
          />
        }
      >
        <div className="card-body">{shown.length === 0 ? <Empty>Kayıt yok</Empty> : shown.map((m) => <MitigationCard key={m.id} m={m} onChange={list.reload} />)}</div>
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
    const list = (s: string) => (s ? s.split(",").map((x) => x.trim()).filter(Boolean) : undefined);
    const r = await run("FlowSpec talebi oluşturuldu", () =>
      api.post("/mitigations", {
        kind: "flowspec",
        reason: f.reason,
        flowspec: {
          destination: dst,
          protocols: f.protocol ? [f.protocol] : undefined,
          src_ports: list(f.src_ports),
          dst_ports: list(f.dst_ports),
          packet_length: f.packet_length || undefined,
          action: f.action,
          rate_bps: f.action === "rate-limit" ? Number(f.rate) : undefined,
        },
      }),
    );
    if (r) {
      onDone();
      onClose();
    }
  };
  return (
    <Modal
      title="Manuel FlowSpec talebi"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Vazgeç
          </button>
          <button className="btn primary" onClick={submit} disabled={!f.destination}>
            Talep oluştur
          </button>
        </>
      }
    >
      <div className="form">
        <Field label="Hedef IP veya prefix" full>
          <input value={f.destination} onChange={set("destination")} placeholder="198.51.100.10" />
        </Field>
        <Field label="Protokol">
          <select value={f.protocol} onChange={set("protocol")}>
            <option value="">hepsi</option>
            <option>udp</option>
            <option>tcp</option>
            <option>icmp</option>
            <option>gre</option>
          </select>
        </Field>
        <Field label="Aksiyon">
          <select value={f.action} onChange={set("action")}>
            <option value="discard">düşür</option>
            <option value="rate-limit">sınırla</option>
          </select>
        </Field>
        <Field label="Kaynak port" hint="ör. 53 veya 1024-65535">
          <input value={f.src_ports} onChange={set("src_ports")} />
        </Field>
        <Field label="Hedef port">
          <input value={f.dst_ports} onChange={set("dst_ports")} />
        </Field>
        <Field label="Paket boyu" hint="ör. >=512">
          <input value={f.packet_length} onChange={set("packet_length")} />
        </Field>
        {f.action === "rate-limit" && (
          <Field label="Hız sınırı (bit/sn)">
            <input value={f.rate} onChange={set("rate")} />
          </Field>
        )}
        <Field label="Gerekçe" full>
          <input value={f.reason} onChange={set("reason")} placeholder="Ticket numarası veya açıklama" />
        </Field>
      </div>
      <p className="small muted">Talep güvenlik kontrollerinden geçer ve onay kuyruğuna düşer.</p>
    </Modal>
  );
}
