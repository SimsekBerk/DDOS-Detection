import { ReactNode, useState } from "react";
import { Row } from "../api";
import { bps, pps, pct, severityLabel } from "../lib";

export function Card(props: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; pad?: boolean }) {
  return (
    <section className={"card " + (props.className ?? "")}>
      {(props.title || props.actions) && (
        <header className="card-h">
          <h3>{props.title}</h3>
          <div className="card-actions">{props.actions}</div>
        </header>
      )}
      <div className={props.pad === false ? "" : "card-b"}>{props.children}</div>
    </section>
  );
}

export function Stat(props: { label: string; value: ReactNode; sub?: ReactNode; tone?: string; onClick?: () => void }) {
  return (
    <div className={"stat " + (props.tone ?? "") + (props.onClick ? " clickable" : "")} onClick={props.onClick}>
      <div className="stat-l">{props.label}</div>
      <div className="stat-v">{props.value}</div>
      {props.sub && <div className="stat-s">{props.sub}</div>}
    </div>
  );
}

export function Sev({ s }: { s: string }) {
  return <span className={"badge sev-" + s}>{severityLabel[s] ?? s}</span>;
}

const statusTone: Record<string, string> = {
  active: "tone-red",
  ended: "tone-gray",
  pending: "tone-amber",
  withdrawn: "tone-gray",
  rejected: "tone-gray",
  failed: "tone-red",
  expired: "tone-gray",
  ok: "tone-green",
  error: "tone-red",
  running: "tone-blue",
};

const statusLabel: Record<string, string> = {
  active: "Aktif",
  ended: "Bitti",
  pending: "Onay bekliyor",
  withdrawn: "Geri çekildi",
  rejected: "Reddedildi",
  failed: "Hata",
  expired: "Süresi doldu",
  ok: "Tamam",
  error: "Hata",
  running: "Çalışıyor",
};

export function Status({ s, label }: { s: string; label?: string }) {
  return <span className={"badge " + (statusTone[s] ?? "tone-gray")}>{label ?? statusLabel[s] ?? s}</span>;
}

export function Tag({ children, tone }: { children: ReactNode; tone?: string }) {
  return <span className={"tag " + (tone ?? "")}>{children}</span>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function Tabs<T extends string>(props: { tabs: { id: T; label: ReactNode }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div className="tabs" role="tablist">
      {props.tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={props.value === t.id} className={props.value === t.id ? "on" : ""} onClick={() => props.onChange(t.id)}>
          {t.label}
        </button>
      ))}
    </div>
  );
}

export function Code({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="code">
      <div className="code-h">
        <span>{label}</span>
        <button
          className="btn tiny ghost"
          onClick={() => {
            void navigator.clipboard?.writeText(text);
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1200);
          }}
        >
          {copied ? "Kopyalandı" : "Kopyala"}
        </button>
      </div>
      <pre>{text}</pre>
    </div>
  );
}

/** Bars renders a top-N list as horizontal share bars. */
export function Bars(props: { rows: Row[] | undefined | null; metric?: "bps" | "pps"; onClick?: (key: string) => void; limit?: number }) {
  const rows = (props.rows ?? []).slice(0, props.limit ?? 10);
  if (rows.length === 0) return <Empty>Veri yok</Empty>;
  const metric = props.metric ?? "bps";
  const max = Math.max(...rows.map((r) => (metric === "pps" ? r.pps : r.bps)), 1);
  return (
    <div className="bars">
      {rows.map((r) => {
        const v = metric === "pps" ? r.pps : r.bps;
        return (
          <div key={r.key} className={"bar-row" + (props.onClick ? " clickable" : "")} onClick={() => props.onClick?.(r.key)} title={r.key}>
            <div className="bar-k mono">{r.key}</div>
            <div className="bar-track">
              <div className="bar-fill" style={{ width: (100 * v) / max + "%" }} />
            </div>
            <div className="bar-v mono">{metric === "pps" ? pps(r.pps) : bps(r.bps)}</div>
            <div className="bar-p mono">{pct(r.share)}</div>
          </div>
        );
      })}
    </div>
  );
}

export function KV({ items }: { items: [ReactNode, ReactNode][] }) {
  return (
    <dl className="kv">
      {items.map(([k, v], i) => (
        <div key={i}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Meter({ value, max = 1, tone }: { value: number; max?: number; tone?: string }) {
  const p = Math.max(0, Math.min(1, value / (max || 1)));
  const t = tone ?? (p >= 1 ? "red" : p >= 0.7 ? "amber" : p >= 0.5 ? "yellow" : "green");
  return (
    <div className="meter" title={(p * 100).toFixed(0) + "%"}>
      <div className={"meter-f m-" + t} style={{ width: p * 100 + "%" }} />
    </div>
  );
}

export function Modal(props: { title: ReactNode; onClose: () => void; children: ReactNode; wide?: boolean }) {
  return (
    <div className="modal-bg" onClick={props.onClose}>
      <div className={"modal" + (props.wide ? " wide" : "")} onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <header>
          <h3>{props.title}</h3>
          <button className="btn ghost" onClick={props.onClose} aria-label="Kapat">
            ✕
          </button>
        </header>
        <div className="modal-b">{props.children}</div>
      </div>
    </div>
  );
}

export function ErrorLine({ error }: { error: string | null }) {
  if (!error) return null;
  return <div className="error-line">API hatası: {error}</div>;
}
