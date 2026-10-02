import { useCallback, useEffect, useRef, useState } from "react";

// ---------------------------------------------------------------- formatting

export function fmtRate(v: number | undefined | null, unit: string): string {
  const x = v ?? 0;
  const abs = Math.abs(x);
  if (abs >= 1e12) return (x / 1e12).toFixed(2) + " T" + unit;
  if (abs >= 1e9) return (x / 1e9).toFixed(2) + " G" + unit;
  if (abs >= 1e6) return (x / 1e6).toFixed(2) + " M" + unit;
  if (abs >= 1e3) return (x / 1e3).toFixed(1) + " k" + unit;
  return x.toFixed(0) + " " + unit;
}
export const bps = (v?: number | null) => fmtRate(v, "bps");
export const pps = (v?: number | null) => fmtRate(v, "pps");
export const fps = (v?: number | null) => fmtRate(v, "fps");

export function num(v?: number | null, d = 0): string {
  return (v ?? 0).toLocaleString("tr-TR", { maximumFractionDigits: d });
}

export function pct(v?: number | null, d = 0): string {
  return "%" + ((v ?? 0) * 100).toFixed(d);
}

export function clock(t?: number): string {
  if (!t) return "-";
  return new Date(t * 1000).toLocaleTimeString("tr-TR", { hour12: false });
}

export function dateTime(t?: number): string {
  if (!t) return "-";
  const d = new Date(t * 1000);
  return d.toLocaleDateString("tr-TR", { day: "2-digit", month: "2-digit" }) + " " + d.toLocaleTimeString("tr-TR", { hour12: false });
}

export function ago(t?: number): string {
  if (!t) return "-";
  const s = Math.max(0, Math.floor(Date.now() / 1000 - t));
  if (s < 60) return s + " sn önce";
  if (s < 3600) return Math.floor(s / 60) + " dk önce";
  if (s < 86400) return Math.floor(s / 3600) + " sa önce";
  return Math.floor(s / 86400) + " gün önce";
}

export function duration(sec: number): string {
  sec = Math.max(0, Math.floor(sec));
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  if (h) return `${h}sa ${m}dk`;
  if (m) return `${m}dk ${s}sn`;
  return `${s}sn`;
}

export const severityLabel: Record<string, string> = {
  critical: "Kritik",
  high: "Yüksek",
  medium: "Orta",
  low: "Düşük",
  info: "Bilgi",
};

export const categoryLabel: Record<string, string> = {
  reflection_amplification: "Yansıma / Amplifikasyon",
  tcp_flood: "TCP Flood",
  udp_flood: "UDP Flood",
  icmp_flood: "ICMP Flood",
  fragment: "Fragment",
  ip_protocol: "IP Protokol",
  carpet_bombing: "Carpet Bombing",
  volumetric: "Hacimsel",
  outbound: "Outbound",
  infrastructure: "Altyapı",
};

export const actionLabel: Record<string, string> = {
  "flowspec-discard": "FlowSpec discard",
  "flowspec-rate-limit": "FlowSpec rate-limit",
  rtbh: "RTBH",
  scrub: "Scrubbing",
  alert: "Sadece alarm",
};

export const signalKindLabel: Record<string, string> = {
  near_threshold: "Eşiğe yakın",
  baseline_deviation: "Baseline sapması",
  conditions_unmet: "Koşul sağlanmadı",
};

export const classLabel: Record<string, string> = {
  attack: "Saldırı",
  suspicious: "Şüpheli",
  benign: "Zararsız",
  misconfiguration: "Yanlış yapılandırma",
  unknown: "Belirsiz",
};

// ---------------------------------------------------------------- hooks

/** usePoll fetches immediately and then every `ms` milliseconds. */
export function usePoll<T>(fn: () => Promise<T>, ms: number, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fnRef = useRef(fn);
  fnRef.current = fn;
  const load = useCallback(async () => {
    try {
      const d = await fnRef.current();
      setData(d);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }, []);
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      if (!alive || document.hidden) return;
      await load();
    };
    void load();
    const id = window.setInterval(tick, ms);
    return () => {
      alive = false;
      window.clearInterval(id);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ms, load, ...deps]);
  return { data, error, reload: load };
}

// ---------------------------------------------------------------- routing

export function useRoute(): [string, string[]] {
  const [hash, setHash] = useState(window.location.hash || "#/");
  useEffect(() => {
    const on = () => setHash(window.location.hash || "#/");
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  const path = hash.replace(/^#/, "").split("?")[0];
  const parts = path.split("/").filter(Boolean);
  return [path, parts];
}

export function go(path: string) {
  window.location.hash = path;
}

// ---------------------------------------------------------------- toasts

type Toast = { id: number; kind: "ok" | "err"; text: string };
let toastListener: ((t: Toast[]) => void) | null = null;
let toasts: Toast[] = [];
let toastSeq = 0;

export function toast(text: string, kind: "ok" | "err" = "ok") {
  const t = { id: ++toastSeq, kind, text };
  toasts = [...toasts, t];
  toastListener?.(toasts);
  window.setTimeout(() => {
    toasts = toasts.filter((x) => x.id !== t.id);
    toastListener?.(toasts);
  }, 4500);
}

export function Toasts() {
  const [list, setList] = useState<Toast[]>([]);
  useEffect(() => {
    toastListener = setList;
    return () => {
      toastListener = null;
    };
  }, []);
  return (
    <div className="toasts" role="status" aria-live="polite">
      {list.map((t) => (
        <div key={t.id} className={"toast " + t.kind}>
          {t.text}
        </div>
      ))}
    </div>
  );
}

/** run wraps an async action with toast feedback. */
export async function run<T>(label: string, f: () => Promise<T>): Promise<T | undefined> {
  try {
    const r = await f();
    toast(label);
    return r;
  } catch (e) {
    toast((e as Error).message, "err");
    return undefined;
  }
}
