import { useEffect, useState } from "react";
import { api, Overview } from "./api";
import { Login, Logo, MeContext, PasswordModal, useMe, useSession } from "./auth";
import { Toasts, usePoll, useRoute } from "./lib";
import OverviewPage from "./pages/Overview";
import IncidentsPage from "./pages/Incidents";
import IncidentDetail from "./pages/IncidentDetail";
import MitigationsPage from "./pages/Mitigations";
import AnalystPage from "./pages/Analyst";
import FindingDetail from "./pages/FindingDetail";
import ExplorerPage from "./pages/Explorer";
import SimulatorPage from "./pages/Simulator";
import SettingsPage from "./pages/Settings";

const roleLabel: Record<string, string> = { admin: "Yönetici", operator: "Operatör", viewer: "İzleyici" };

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
  const session = useSession();
  useTheme();
  if (!session.checked) return null;
  if (!session.me) return <Login onLogin={session.setMe} />;
  return (
    <MeContext.Provider value={session.me}>
      <Shell onLogout={session.logout} />
    </MeContext.Provider>
  );
}

function Shell({ onLogout }: { onLogout: () => void }) {
  const [path, parts] = useRoute();
  const [theme, toggleTheme] = useTheme();
  const [navOpen, setNavOpen] = useState(false);
  const [menu, setMenu] = useState(false);
  const [pw, setPw] = useState(false);
  const ov = usePoll(() => api.get<Overview>("/overview"), 2000);
  const o = ov.data;
  const me = useMe();
  useEffect(() => {
    setNavOpen(false);
    setMenu(false);
  }, [path]);

  const active = o?.engine.active_incidents ?? 0;
  const pending = o?.mitigation.pending ?? 0;
  const signals = o?.engine.pending_signals ?? 0;
  const live = o ? Date.now() / 1000 - o.engine.time < 6 : false;

  const link = (to: string, label: string, count?: number, alert?: boolean) => {
    const on = to === "/" ? path === "/" || path === "" : path.startsWith(to);
    return (
      <a href={"#" + to} className={on ? "on" : ""}>
        {label}
        {count ? <span className={"nav-count" + (alert ? " alert" : "")}>{count}</span> : null}
      </a>
    );
  };

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
    case "explorer":
      page = <ExplorerPage target={parts[1] === "target" ? parts[2] : undefined} />;
      break;
    case "sim":
      page = <SimulatorPage ov={o} />;
      break;
    case "settings":
      page = <SettingsPage section={parts[1] ?? "objects"} />;
      break;
    default:
      page = <div className="empty">Sayfa bulunamadı</div>;
  }

  return (
    <div className={"shell" + (navOpen ? " nav-open" : "")}>
      <aside className="side">
        <div className="brand">
          <Logo />
          <div>
            ddosd<small>DDoS algılama</small>
          </div>
        </div>
        <nav>
          <div className="nav-group">
            <span>İzleme</span>
            {link("/", "Genel bakış")}
            {link("/incidents", "Saldırılar", active, true)}
            {link("/mitigations", "Mitigasyon", pending, true)}
          </div>
          <div className="nav-group">
            <span>Analiz</span>
            {link("/analyst", "AI analist", signals)}
            {link("/explorer", "Trafik gezgini")}
          </div>
          {me.can_admin && (
            <div className="nav-group">
              <span>Yönetim</span>
              {link("/settings", "Ayarlar")}
            </div>
          )}
          {o?.demo && me.can_operate && !me.objects.length && (
            <div className="nav-group">
              <span>Demo</span>
              {link("/sim", "Simülatör")}
            </div>
          )}
        </nav>
        <div className="side-foot">
          <div>
            Mitigasyon: <b className="ink2">{o?.mitigation.mode ?? "-"}</b> · {o?.mitigation.driver ?? "-"}
          </div>
          <div>{o ? "v" + o.version : ""}</div>
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <button className="btn ghost burger" onClick={() => setNavOpen(!navOpen)} aria-label="Menü">
            ☰
          </button>
          <span className={"live" + (live ? " on" : "")}>
            <i />
            {live ? "Canlı" : ov.error ? "Bağlantı yok" : "Bekleniyor"}
          </span>
          {o && o.restart_pending?.length > 0 && me.can_admin && (
            <a className="pill pending" href="#/settings/system" title={o.restart_pending.join(", ")}>
              Yeniden başlatma gerekli
            </a>
          )}
          <div className="right row">
            <button className="btn ghost sm" onClick={toggleTheme} aria-label="Tema değiştir">
              {theme === "dark" ? "Açık tema" : "Koyu tema"}
            </button>
            <div className="menu">
              <button className="btn sm" onClick={() => setMenu(!menu)}>
                {me.username} · {roleLabel[me.role] ?? me.role}
              </button>
              {menu && (
                <div className="menu-pop">
                  {me.objects.length > 0 && <div className="small muted" style={{ padding: "4px 8px" }}>Kapsam: {me.objects.join(", ")}</div>}
                  <button className="btn ghost" onClick={() => setPw(true)}>
                    Parola değiştir
                  </button>
                  <button className="btn ghost" onClick={onLogout}>
                    Çıkış yap
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>
        <main className="content">{page}</main>
      </div>
      {pw && <PasswordModal onClose={() => setPw(false)} />}
      <Toasts />
    </div>
  );
}
