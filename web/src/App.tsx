import { useEffect, useState } from "react";
import { api, Overview } from "./api";
import { bps, go, pps, Toasts, usePoll, useRoute } from "./lib";
import OverviewPage from "./pages/Overview";
import IncidentsPage from "./pages/Incidents";
import IncidentDetail from "./pages/IncidentDetail";
import MitigationsPage from "./pages/Mitigations";
import AnalystPage from "./pages/Analyst";
import FindingDetail from "./pages/FindingDetail";
import RulesPage from "./pages/Rules";
import ObjectsPage from "./pages/Objects";
import ExplorerPage from "./pages/Explorer";
import ExportersPage from "./pages/Exporters";
import SimulatorPage from "./pages/Simulator";
import SystemPage from "./pages/System";

const nav = [
  { path: "/", label: "Genel Bakış", icon: "◉" },
  { path: "/incidents", label: "Saldırılar", icon: "⚠" },
  { path: "/mitigations", label: "Mitigasyon", icon: "⛨" },
  { path: "/analyst", label: "AI Analist", icon: "✦" },
  { path: "/rules", label: "Kural Setleri", icon: "☰" },
  { path: "/objects", label: "Korunan Nesneler", icon: "▣" },
  { path: "/explorer", label: "Flow Explorer", icon: "⌕" },
  { path: "/exporters", label: "Telemetri Kaynakları", icon: "⇄" },
  { path: "/sim", label: "Simülatör", icon: "▶" },
  { path: "/system", label: "Sistem", icon: "⚙" },
];

function useTheme(): [string, () => void] {
  const [theme, setTheme] = useState<string>(() => {
    try {
      return localStorage.getItem("ddosd-theme") ?? "dark";
    } catch {
      return "dark";
    }
  });
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem("ddosd-theme", theme);
    } catch {
      /* storage unavailable */
    }
  }, [theme]);
  return [theme, () => setTheme(theme === "dark" ? "light" : "dark")];
}

export default function App() {
  const [path, parts] = useRoute();
  const [theme, toggleTheme] = useTheme();
  const [navOpen, setNavOpen] = useState(false);
  const ov = usePoll(() => api.get<Overview>("/overview"), 2000);
  const o = ov.data;

  useEffect(() => setNavOpen(false), [path]);

  let page;
  switch (parts[0]) {
    case undefined:
      page = <OverviewPage ov={o} />;
      break;
    case "incidents":
      page = parts[1] ? <IncidentDetail id={parts[1]} /> : <IncidentsPage />;
      break;
    case "mitigations":
      page = <MitigationsPage ov={o} />;
      break;
    case "analyst":
      page = parts[1] ? <FindingDetail id={parts[1]} /> : <AnalystPage />;
      break;
    case "rules":
      page = <RulesPage />;
      break;
    case "objects":
      page = <ObjectsPage ov={o} target={parts[1]} />;
      break;
    case "explorer":
      page = <ExplorerPage />;
      break;
    case "exporters":
      page = <ExportersPage />;
      break;
    case "sim":
      page = <SimulatorPage ov={o} />;
      break;
    case "system":
      page = <SystemPage ov={o} />;
      break;
    default:
      page = <div className="empty">Sayfa bulunamadı</div>;
  }

  const active = o?.engine.active_incidents ?? 0;
  const pending = o?.mitigation.pending ?? 0;
  const signals = o?.engine.pending_signals ?? 0;
  const live = o ? Date.now() / 1000 - o.engine.time < 5 : false;

  return (
    <div className={"shell" + (navOpen ? " nav-open" : "")}>
      <aside className="side">
        <div className="brand" onClick={() => go("/")}>
          <svg viewBox="0 0 32 32" width="26" height="26" aria-hidden>
            <path d="M16 2 4 7v8c0 7.5 5.1 13.6 12 15 6.9-1.4 12-7.5 12-15V7z" fill="var(--accent)" />
            <path d="M10 16h3l2-5 3 10 2-5h2" stroke="var(--bg)" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <div>
            <b>ddosd</b>
            <small>DDoS Algılama</small>
          </div>
        </div>
        <nav>
          {nav.map((n) => {
            const on = n.path === "/" ? path === "/" || path === "" : path.startsWith(n.path);
            if (n.path === "/sim" && o && !o.demo) return null;
            let badge = null;
            if (n.path === "/incidents" && active > 0) badge = <span className="nb red">{active}</span>;
            if (n.path === "/mitigations" && pending > 0) badge = <span className="nb amber">{pending}</span>;
            if (n.path === "/analyst" && signals > 0) badge = <span className="nb blue">{signals}</span>;
            return (
              <a key={n.path} href={"#" + n.path} className={on ? "on" : ""}>
                <span className="ni">{n.icon}</span>
                <span className="nl">{n.label}</span>
                {badge}
              </a>
            );
          })}
        </nav>
        <div className="side-f">
          <div>
            Mod: <b>{o?.mitigation.mode ?? "-"}</b> · Sürücü: <b>{o?.mitigation.driver ?? "-"}</b>
          </div>
          <div>
            Analist: <b>{o?.analyst.provider ?? "-"}</b>
          </div>
          <div className="muted">{o ? "v" + o.version : ""}</div>
        </div>
      </aside>
      <div className="main">
        <header className="top">
          <button className="btn ghost burger" onClick={() => setNavOpen(!navOpen)} aria-label="Menü">
            ☰
          </button>
          <div className={"live " + (live ? "on" : "off")}>
            <span className="dot" />
            {live ? "Canlı" : ov.error ? "Bağlantı yok" : "Bekleniyor"}
          </div>
          <div className="top-m">
            <span>
              ↓ <b>{bps(o?.engine.global.in_bps)}</b> <span className="muted">{pps(o?.engine.global.in_pps)}</span>
            </span>
            <span>
              ↑ <b>{bps(o?.engine.global.out_bps)}</b>
            </span>
            <span className="muted hide-sm">{Math.round(o?.engine.records_per_sec ?? 0).toLocaleString("tr-TR")} kayıt/sn</span>
          </div>
          <div className="top-r">
            {active > 0 && (
              <a className="pill red" href="#/incidents">
                {active} aktif saldırı
              </a>
            )}
            {pending > 0 && (
              <a className="pill amber" href="#/mitigations">
                {pending} onay bekliyor
              </a>
            )}
            <button className="btn ghost" onClick={toggleTheme} aria-label="Tema">
              {theme === "dark" ? "☀" : "☾"}
            </button>
          </div>
        </header>
        <main className="content">{page}</main>
      </div>
      <Toasts />
    </div>
  );
}
