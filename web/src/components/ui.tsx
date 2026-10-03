import { cloneElement, createContext, isValidElement, ReactElement, ReactNode, useId, useState } from "react";
import { Row } from "../api";
import { bps, pct, pps, severityLabel } from "../lib";

export function PageHead(props: { title: ReactNode; desc?: ReactNode; crumb?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        {props.crumb && <div className="crumb">{props.crumb}</div>}
        <h1>{props.title}</h1>
        {props.desc && <p>{props.desc}</p>}
      </div>
      {props.actions && <div className="row">{props.actions}</div>}
    </div>
  );
}

export function Card(props: { title?: ReactNode; actions?: ReactNode; children: ReactNode; flush?: boolean; className?: string }) {
  return (
    <section className={"card " + (props.className ?? "")}>
      {(props.title || props.actions) && (
        <div className="card-head">
          {props.title && <h2>{props.title}</h2>}
          {props.actions && <div className="actions">{props.actions}</div>}
        </div>
      )}
      {props.flush ? props.children : <div className="card-body">{props.children}</div>}
    </section>
  );
}

export function Kpi(props: { label: string; value: ReactNode; sub?: ReactNode; onClick?: () => void }) {
  return (
    <div className={"kpi" + (props.onClick ? " clickable" : "")} onClick={props.onClick} role={props.onClick ? "button" : undefined}>
      <div className="kpi-label">{props.label}</div>
      <div className="kpi-value num">{splitUnit(props.value)}</div>
      {props.sub !== undefined && <div className="kpi-sub">{props.sub}</div>}
    </div>
  );
}

// splitUnit renders "396.76 Mbps" as a large number with a small unit so
// values fit narrow KPI tiles without truncation.
function splitUnit(v: ReactNode): ReactNode {
  if (typeof v !== "string") return v;
  const m = /^([-+]?[\d.,]+)\s+(\p{L}.*)$/u.exec(v);
  if (!m) return v;
  return (
    <>
      {m[1]}
      <span className="unit">{m[2]}</span>
    </>
  );
}

export function Sev({ s }: { s: string }) {
  return <span className={"sev " + s}>{severityLabel[s] ?? s}</span>;
}

const statusText: Record<string, string> = {
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
const statusClass: Record<string, string> = { active: "active", pending: "pending", failed: "err", error: "err", ok: "ok", running: "pending" };

export function Status({ s, label }: { s: string; label?: string }) {
  return <span className={"pill " + (statusClass[s] ?? "")}>{label ?? statusText[s] ?? s}</span>;
}

export function Tag({ children, title }: { children: ReactNode; title?: string }) {
  return (
    <span className="tag" title={title}>
      {children}
    </span>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function ErrorLine({ error }: { error: string | null | undefined }) {
  if (!error) return null;
  return <div className="alert-line">{error}</div>;
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

export function Seg<T extends string>(props: { options: { id: T; label: ReactNode }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div className="seg">
      {props.options.map((o) => (
        <button key={o.id} className={props.value === o.id ? "on" : ""} onClick={() => props.onChange(o.id)}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Code({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="code">
      <div className="code-head">
        <span>{label}</span>
        <button
          className="btn ghost sm"
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

/** Bars shows a top-N list: label, value and share, with a thin magnitude bar. */
export function Bars(props: { rows: Row[] | null | undefined; metric?: "bps" | "pps"; limit?: number; onClick?: (key: string) => void }) {
  const rows = (props.rows ?? []).slice(0, props.limit ?? 8);
  if (rows.length === 0) return <Empty>Veri yok</Empty>;
  const m = props.metric ?? "bps";
  const max = Math.max(...rows.map((r) => (m === "pps" ? r.pps : r.bps)), 1);
  return (
    <div className="bars">
      {rows.map((r) => {
        const v = m === "pps" ? r.pps : r.bps;
        return (
          <div key={r.key} className="bar" title={r.key}>
            <div className="bar-label">
              <span className={"mono" + (props.onClick ? " link" : "")} onClick={() => props.onClick?.(r.key)}>
                {r.key}
              </span>
              <div className="bar-track">
                <div className="bar-fill" style={{ width: (100 * v) / max + "%" }} />
              </div>
            </div>
            <div className="num r">{m === "pps" ? pps(r.pps) : bps(r.bps)}</div>
            <div className="num r muted">{pct(r.share)}</div>
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
        <div key={i} style={{ display: "contents" }}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Meter({ value }: { value: number }) {
  const p = Math.max(0, Math.min(1, value));
  const cls = value >= 1 ? "hot" : value >= 0.7 ? "warn" : "";
  return (
    <div className={"meter " + cls} title={(value * 100).toFixed(0) + "%"}>
      <div style={{ width: p * 100 + "%" }} />
    </div>
  );
}

export function Modal(props: { title: ReactNode; onClose: () => void; children: ReactNode; wide?: boolean; footer?: ReactNode }) {
  return (
    <div className="modal-bg" onClick={props.onClose}>
      <div className={"modal" + (props.wide ? " wide" : "")} onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <div className="modal-head">
          <h2>{props.title}</h2>
          <button className="btn ghost sm right" onClick={props.onClose} aria-label="Kapat">
            ✕
          </button>
        </div>
        <div className="modal-body">
          {props.children}
          {props.footer && <div className="row end" style={{ marginTop: 16 }}>{props.footer}</div>}
        </div>
      </div>
    </div>
  );
}

/** FieldId lets inputs nested inside a Field pick up the id its label points to. */
export const FieldId = createContext<string | undefined>(undefined);

export function Field(props: { label: ReactNode; hint?: ReactNode; children: ReactNode; full?: boolean }) {
  const id = useId();
  // A single native control gets the id directly; composite inputs read it
  // from FieldId so the label is announced and clickable either way.
  let child = props.children;
  if (isValidElement(child) && typeof child.type === "string" && ["input", "select", "textarea"].includes(child.type)) {
    child = cloneElement(child as ReactElement<{ id?: string }>, { id });
  }
  return (
    <div className={"field" + (props.full ? " full" : "")}>
      <label htmlFor={id}>{props.label}</label>
      <FieldId.Provider value={id}>{child}</FieldId.Provider>
      {props.hint && <div className="hint">{props.hint}</div>}
    </div>
  );
}
