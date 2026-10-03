import { InputHTMLAttributes, ReactNode, useContext, useEffect, useState } from "react";
import { Field, FieldId } from "./ui";

const useFieldId = () => useContext(FieldId);

// Small controlled inputs for the settings editor. Each one renders a labelled
// field and reports a typed value; invalid text is kept locally and flagged.

export function formatRate(v: number | string | undefined | null): string {
  if (v === undefined || v === null || v === "") return "";
  if (typeof v === "string") return v;
  for (const [m, s] of [
    [1e12, "T"],
    [1e9, "G"],
    [1e6, "M"],
    [1e3, "k"],
  ] as [number, string][]) {
    if (v >= m) return +(v / m).toFixed(3) + s;
  }
  return String(v);
}

export function parseRate(s: string): number | null {
  let t = s.trim().toLowerCase();
  if (!t) return 0;
  for (const suf of ["bps", "pps", "fps", "/s"]) if (t.endsWith(suf)) t = t.slice(0, -suf.length);
  let mult = 1;
  const last = t.slice(-1);
  const m: Record<string, number> = { t: 1e12, g: 1e9, m: 1e6, k: 1e3 };
  if (m[last]) {
    mult = m[last];
    t = t.slice(0, -1);
  }
  const v = Number(t.trim().replace(",", "."));
  if (!isFinite(v) || v < 0 || t.trim() === "") return null;
  return v * mult;
}

const durRe = /^(\d+(\.\d+)?(ns|us|µs|ms|s|m|h))+$/;

type Base = { label: ReactNode; hint?: ReactNode; full?: boolean; disabled?: boolean };

/** Ided is an <input> that takes its id from the surrounding Field. */
function Ided(props: InputHTMLAttributes<HTMLInputElement>) {
  const id = useFieldId();
  return <input id={id} {...props} />;
}

export function TextIn(p: Base & { value: string | undefined; onChange: (v: string) => void; placeholder?: string; mono?: boolean; type?: string }) {
  return (
    <Field label={p.label} hint={p.hint} full={p.full}>
      <input
        type={p.type ?? "text"}
        className={p.mono ? "mono" : undefined}
        value={p.value ?? ""}
        placeholder={p.placeholder}
        disabled={p.disabled}
        onChange={(e) => p.onChange(e.target.value)}
        autoComplete="off"
        spellCheck={false}
      />
    </Field>
  );
}

export function SecretIn(p: Base & { value: string | undefined; onChange: (v: string) => void }) {
  const masked = p.value === "********";
  return (
    <Field label={p.label} hint={masked ? "Kayıtlı değer gizli; değiştirmezseniz korunur." : p.hint} full={p.full}>
      <input type="password" value={p.value ?? ""} onChange={(e) => p.onChange(e.target.value)} autoComplete="new-password" placeholder="ayarlanmadı" />
    </Field>
  );
}

export function NumIn(p: Base & { value: number | undefined; onChange: (v: number) => void; min?: number; max?: number; step?: number; suffix?: string; prefix?: string }) {
  const [text, setText] = useState(String(p.value ?? ""));
  useEffect(() => {
    if (Number(text) !== p.value) setText(String(p.value ?? ""));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [p.value]);
  const n = Number(text);
  const bad = text !== "" && (!isFinite(n) || (p.min !== undefined && n < p.min) || (p.max !== undefined && n > p.max));
  return (
    <Field label={p.label} hint={bad ? <span className="bad">Geçersiz değer{p.min !== undefined ? ` (${p.min}–${p.max ?? "∞"})` : ""}</span> : p.hint} full={p.full}>
      <div className="input-suffix">
        {p.prefix && <span className="pre">{p.prefix}</span>}
        <Ided
          inputMode="decimal"
          value={text}
          disabled={p.disabled}
          aria-invalid={bad}
          onChange={(e) => {
            setText(e.target.value);
            const v = Number(e.target.value);
            if (e.target.value !== "" && isFinite(v)) p.onChange(v);
            if (e.target.value === "") p.onChange(0);
          }}
        />
        {p.suffix && <span>{p.suffix}</span>}
      </div>
    </Field>
  );
}

/** RateIn edits a rate with SI suffixes ("10G", "200M", "50k"). */
export function RateIn(p: Base & { value: number | string | undefined; onChange: (v: number) => void; unit: string; placeholder?: string }) {
  const [text, setText] = useState(formatRate(p.value));
  useEffect(() => {
    const cur = parseRate(text);
    const v = typeof p.value === "string" ? parseRate(p.value) : p.value ?? 0;
    if (cur !== v) setText(formatRate(p.value));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [p.value]);
  const bad = parseRate(text) === null;
  return (
    <Field label={p.label} hint={bad ? <span className="bad">ör. 10G, 200M, 50k</span> : p.hint} full={p.full}>
      <div className="input-suffix">
        <Ided
          value={text}
          placeholder={p.placeholder}
          aria-invalid={bad}
          disabled={p.disabled}
          onChange={(e) => {
            setText(e.target.value);
            const v = parseRate(e.target.value);
            if (v !== null) p.onChange(v);
          }}
        />
        <span>{p.unit}</span>
      </div>
    </Field>
  );
}

/** DurIn edits a Go duration string ("10s", "5m", "1h30m"). */
export function DurIn(p: Base & { value: string | undefined; onChange: (v: string) => void }) {
  const shown = (p.value ?? "").replace(/(\d)m0s$/, "$1m").replace(/(\d)h0m$/, "$1h");
  const [text, setText] = useState(shown);
  useEffect(() => {
    if (text.trim() !== (p.value ?? "")) setText(shown);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [p.value]);
  const bad = text !== "" && !durRe.test(text.trim());
  return (
    <Field label={p.label} hint={bad ? <span className="bad">ör. 30s, 5m, 1h</span> : p.hint} full={p.full}>
      <input
        value={text}
        aria-invalid={bad}
        disabled={p.disabled}
        onChange={(e) => {
          setText(e.target.value);
          if (durRe.test(e.target.value.trim())) p.onChange(e.target.value.trim());
        }}
      />
    </Field>
  );
}

/** ListIn edits a string list, one entry per line (commas also split). */
export function ListIn(p: Base & { value: string[] | null | undefined; onChange: (v: string[]) => void; placeholder?: string; rows?: number }) {
  const joined = (p.value ?? []).join("\n");
  const [text, setText] = useState(joined);
  const parse = (s: string) =>
    s
      .split(/[\n,]/)
      .map((x) => x.trim())
      .filter(Boolean);
  useEffect(() => {
    if (parse(text).join("\n") !== joined) setText(joined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [joined]);
  return (
    <Field label={p.label} hint={p.hint ?? "Her satıra bir değer"} full={p.full}>
      <textarea
        className="mono"
        rows={p.rows ?? Math.min(8, Math.max(2, (p.value ?? []).length + 1))}
        value={text}
        placeholder={p.placeholder}
        disabled={p.disabled}
        spellCheck={false}
        onChange={(e) => {
          setText(e.target.value);
          p.onChange(parse(e.target.value));
        }}
      />
    </Field>
  );
}

export function SelectIn<T extends string>(p: Base & { value: T | undefined; onChange: (v: T) => void; options: ([T, string] | T)[] }) {
  return (
    <Field label={p.label} hint={p.hint} full={p.full}>
      <select value={p.value ?? ""} disabled={p.disabled} onChange={(e) => p.onChange(e.target.value as T)}>
        {p.options.map((o) => {
          const [v, l] = Array.isArray(o) ? o : [o, o];
          return (
            <option key={v} value={v}>
              {l}
            </option>
          );
        })}
      </select>
    </Field>
  );
}

export function Toggle(p: { label: ReactNode; hint?: ReactNode; value: boolean | undefined; onChange: (v: boolean) => void; full?: boolean; disabled?: boolean }) {
  return (
    <div className={"field" + (p.full ? " full" : "")}>
      <label className="check toggle">
        <input type="checkbox" checked={!!p.value} disabled={p.disabled} onChange={(e) => p.onChange(e.target.checked)} />
        <span>{p.label}</span>
      </label>
      {p.hint && <span className="hint">{p.hint}</span>}
    </div>
  );
}

/** Section groups fields under a heading inside a settings card. */
export function Section(p: { title: ReactNode; desc?: ReactNode; children: ReactNode; actions?: ReactNode }) {
  return (
    <div className="fs">
      <div className="fs-head">
        <div>
          <h3>{p.title}</h3>
          {p.desc && <p className="small muted">{p.desc}</p>}
        </div>
        {p.actions && <div className="row">{p.actions}</div>}
      </div>
      <div className="form">{p.children}</div>
    </div>
  );
}
