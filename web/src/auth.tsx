import { createContext, FormEvent, useContext, useEffect, useState } from "react";
import { api, ApiError, Me } from "./api";
import { Field, Modal } from "./components/ui";
import { run } from "./lib";

export const MeContext = createContext<Me | null>(null);

/** useMe returns the signed-in user (always set inside the shell). */
export function useMe(): Me {
  return useContext(MeContext)!;
}

/** useSession loads the current user and reacts to 401 responses. */
export function useSession() {
  const [me, setMe] = useState<Me | null>(null);
  const [checked, setChecked] = useState(false);
  useEffect(() => {
    api
      .get<Me>("/auth/me")
      .then(setMe)
      .catch(() => setMe(null))
      .finally(() => setChecked(true));
    const onUnauthorized = () => setMe(null);
    window.addEventListener("ddosd:unauthorized", onUnauthorized);
    return () => window.removeEventListener("ddosd:unauthorized", onUnauthorized);
  }, []);
  const logout = async () => {
    await api.post("/auth/logout").catch(() => undefined);
    setMe(null);
  };
  return { me, setMe, checked, logout };
}

export function Login({ onLogin }: { onLogin: (m: Me) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onLogin(await api.post<Me>("/auth/login", { username, password }));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Sunucuya ulaşılamadı");
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="login">
      <form className="card" onSubmit={submit}>
        <div className="card-body stack">
          <div className="brand" style={{ padding: 0 }}>
            <Logo />
            <div>
              ddosd<small>DDoS algılama ve mitigasyon</small>
            </div>
          </div>
          <Field label="Kullanıcı adı">
            <input autoFocus autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} />
          </Field>
          <Field label="Parola">
            <input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </Field>
          {error && <div className="alert-line">{error}</div>}
          <button className="btn primary" disabled={busy || !username || !password} style={{ justifyContent: "center" }}>
            {busy ? "Giriş yapılıyor…" : "Giriş yap"}
          </button>
          <p className="small muted">İlk kurulumda yönetici parolası data dizinindeki initial-admin-password.txt dosyasına yazılır.</p>
        </div>
      </form>
    </div>
  );
}

export function PasswordModal({ onClose }: { onClose: () => void }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const save = async () => {
    const ok = await run("Parola değiştirildi", () => api.post("/auth/password", { current, next }));
    if (ok) onClose();
  };
  return (
    <Modal
      title="Parola değiştir"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Vazgeç
          </button>
          <button className="btn primary" disabled={!current || next.length < 10 || next !== again} onClick={save}>
            Kaydet
          </button>
        </>
      }
    >
      <div className="stack">
        <Field label="Mevcut parola">
          <input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} />
        </Field>
        <Field label="Yeni parola" hint="En az 10 karakter">
          <input type="password" value={next} onChange={(e) => setNext(e.target.value)} />
        </Field>
        <Field label="Yeni parola (tekrar)" hint={again && again !== next ? "Parolalar eşleşmiyor" : undefined}>
          <input type="password" value={again} onChange={(e) => setAgain(e.target.value)} />
        </Field>
      </div>
    </Modal>
  );
}

export function Logo() {
  return (
    <svg viewBox="0 0 32 32" width="24" height="24" aria-hidden>
      <path d="M16 2 4 7v8c0 7.5 5.1 13.6 12 15 6.9-1.4 12-7.5 12-15V7z" fill="var(--accent)" />
      <path d="M10 16h3l2-5 3 10 2-5h2" stroke="var(--surface)" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
