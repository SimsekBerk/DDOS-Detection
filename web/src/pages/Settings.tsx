import { ReactNode, useEffect, useMemo, useState } from "react";
import { AuditEntry, ChannelConfig, ChannelStatus, ConfigDoc, ConfigResponse, EngineSnapshot, Exporter, HistoryEntry, ObjectConfig, Profile, RuleView, UserRecord, api } from "../api";
import { useMe } from "../auth";
import { DurIn, ListIn, NumIn, RateIn, SecretIn, Section, SelectIn, TextIn, Toggle, formatRate } from "../components/form";
import { Card, Code, Empty, ErrorLine, Field, Modal, PageHead, Sev, Status } from "../components/ui";
import { actionLabel, ago, bps, categoryLabel, dateTime, duration, num, pps, run, toast, usePoll } from "../lib";

// The settings editor keeps one draft of the whole configuration. Every
// section edits that draft; the sticky save bar validates and applies it in
// one versioned change (PUT /config). Rules, users and tokens are separate
// stores and are saved immediately.

type Draft = ConfigDoc;
type Edit = (f: (d: Draft) => void) => void;

const sections: { id: string; label: string; keys?: (keyof ConfigDoc)[] }[] = [
  { id: "objects", label: "Korunan nesneler", keys: ["protected_objects"] },
  { id: "rules", label: "Algılama kuralları" },
  { id: "telemetry", label: "Telemetri", keys: ["collector", "exporters"] },
  { id: "engine", label: "Algılama motoru", keys: ["engine"] },
  { id: "mitigation", label: "Mitigasyon", keys: ["mitigation"] },
  { id: "notifications", label: "Bildirimler", keys: ["notifications"] },
  { id: "analyst", label: "AI analist", keys: ["analyst"] },
  { id: "access", label: "Web ve API", keys: ["api"] },
  { id: "users", label: "Kullanıcılar" },
  { id: "audit", label: "Denetim kaydı" },
  { id: "history", label: "Değişiklik geçmişi" },
  { id: "system", label: "Sistem", keys: ["demo", "rules_dir", "data_dir"] },
];

const clone = <T,>(x: T): T => JSON.parse(JSON.stringify(x));
const same = (a: unknown, b: unknown) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null);

export default function SettingsPage({ section }: { section: string }) {
  const me = useMe();
  const [resp, setResp] = useState<ConfigResponse | null>(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState<string[] | null>(null);

  const load = async () => {
    try {
      const r = await api.get<ConfigResponse>("/config");
      setResp(r);
      setDraft(clone(r.config));
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  };
  useEffect(() => {
    if (me.can_admin) void load();
  }, [me.can_admin]);

  const dirtySections = useMemo(() => {
    if (!resp || !draft) return new Set<string>();
    return new Set(sections.filter((s) => s.keys?.some((k) => !same(resp.config[k], draft[k]))).map((s) => s.id));
  }, [resp, draft]);
  const dirty = dirtySections.size > 0;

  useEffect(() => {
    if (!dirty) return;
    const h = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener("beforeunload", h);
    return () => window.removeEventListener("beforeunload", h);
  }, [dirty]);

  if (!me.can_admin) return <div className="page"><Empty>Ayarlar yalnızca yönetici rolüne açıktır.</Empty></div>;

  const edit: Edit = (f) =>
    setDraft((d) => {
      if (!d) return d;
      const n = clone(d);
      f(n);
      return n;
    });

  const validate = async (): Promise<string[] | null> => {
    try {
      const r = await api.post<{ restart_required: string[] }>("/config/validate", { config: draft });
      return r.restart_required ?? [];
    } catch (e) {
      toast((e as Error).message, "err");
      return null;
    }
  };
  const apply = async () => {
    setBusy(true);
    const r = await run("Yapılandırma uygulandı", () => api.put<{ version: string; restart_required: string[] }>("/config", { config: draft, comment }));
    setBusy(false);
    setConfirm(null);
    if (r) {
      setComment("");
      if (r.restart_required?.length) toast("Bazı değişiklikler yeniden başlatma sonrası geçerli olur: " + r.restart_required.join(", "));
      await load();
    }
  };
  const save = async () => {
    setBusy(true);
    const restart = await validate();
    setBusy(false);
    if (restart === null) return;
    if (restart.length) setConfirm(restart);
    else await apply();
  };

  const cur = sections.find((s) => s.id === section) ?? sections[0];
  let body: ReactNode = <Empty>Yükleniyor…</Empty>;
  if (draft && resp) {
    const props = { d: draft, edit, resp };
    body = {
      objects: <ObjectsSection {...props} />,
      rules: <RulesSection objects={draft.protected_objects} />,
      telemetry: <TelemetrySection {...props} />,
      engine: <EngineSection {...props} />,
      mitigation: <MitigationSection {...props} />,
      notifications: <NotificationsSection {...props} />,
      analyst: <AnalystSection {...props} />,
      access: <AccessSection {...props} />,
      users: <UsersSection objects={resp.config.protected_objects.map((o) => o.name)} />,
      audit: <AuditSection />,
      history: <HistorySection onRestored={load} />,
      system: <SystemSection {...props} />,
    }[cur.id];
  }

  return (
    <div className="page">
      <PageHead title="Ayarlar" desc="Değişiklikler doğrulanır, sürümlenir ve çoğu yeniden başlatma gerektirmeden uygulanır." />
      <ErrorLine error={error} />
      {resp && !resp.writable && (
        <div className="banner warn">
          <div className="small">
            <b>Yapılandırma dosyası yazılamıyor.</b> <span className="mono">{resp.config_path}</span> salt okunur olduğu için değişiklikler kaydedilemez. Docker'da dosyanın bulunduğu dizini yazılabilir bir volume olarak bağlayın (bkz. docs/OPERATIONS.md). Kurallar, kullanıcılar ve token'lar data dizininde tutulduğu için yine yönetilebilir.
          </div>
        </div>
      )}
      {resp && resp.restart_pending.length > 0 && (
        <div className="banner warn">
          <div className="small">
            <b>Yeniden başlatma bekleniyor.</b> Şu alanlar kaydedildi ancak servis yeniden başlatılınca etkinleşir: <span className="mono">{resp.restart_pending.join(", ")}</span>
          </div>
        </div>
      )}
      <div className="settings">
        <nav className="settings-nav" aria-label="Ayar bölümleri">
          {sections.map((s) => (
            <a key={s.id} href={"#/settings/" + s.id} className={s.id === cur.id ? "on" : ""}>
              {s.label}
              {dirtySections.has(s.id) && <i className="dirty-dot" title="Kaydedilmemiş değişiklik" />}
            </a>
          ))}
        </nav>
        <div className="stack" style={{ minWidth: 0 }}>
          {body}
          {dirty && (
            <div className="savebar">
              <span className="small">
                <b>Kaydedilmemiş değişiklik:</b> {sections.filter((s) => dirtySections.has(s.id)).map((s) => s.label).join(", ")}
              </span>
              <input placeholder="Değişiklik notu (ör. ticket no)" value={comment} onChange={(e) => setComment(e.target.value)} />
              <button className="btn" disabled={busy} onClick={() => resp && setDraft(clone(resp.config))}>
                Vazgeç
              </button>
              <button className="btn" disabled={busy} onClick={async () => { const r = await validate(); if (r) toast(r.length ? "Geçerli; yeniden başlatma gerekecek: " + r.join(", ") : "Yapılandırma geçerli"); }}>
                Doğrula
              </button>
              <button className="btn primary" disabled={busy || !resp?.writable} onClick={save} title={resp?.writable ? undefined : "Yapılandırma dosyası salt okunur"}>
                {busy ? "Uygulanıyor…" : "Kaydet ve uygula"}
              </button>
            </div>
          )}
        </div>
      </div>
      {confirm && (
        <Modal
          title="Yeniden başlatma gerekecek"
          onClose={() => setConfirm(null)}
          footer={
            <>
              <button className="btn" onClick={() => setConfirm(null)}>
                Vazgeç
              </button>
              <button className="btn primary" disabled={busy} onClick={apply}>
                Kaydet
              </button>
            </>
          }
        >
          <p>Diğer değişiklikler hemen uygulanır. Şu alanlar ise servis yeniden başlatılınca etkinleşir:</p>
          <ul className="mono small">
            {confirm.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
        </Modal>
      )}
    </div>
  );
}

type SP = { d: Draft; edit: Edit; resp: ConfigResponse };

// ------------------------------------------------------------- objects

const emptyObject: ObjectConfig = { name: "", prefixes: [], profile: "default", link_capacity: 10e9, carpet_prefix_v4: 24, carpet_prefix_v6: 64, notes: "" };

function ObjectsSection({ d, edit, resp }: SP) {
  const [open, setOpen] = useState<number | null>(null);
  const objs = d.protected_objects;
  return (
    <Card
      title="Korunan nesneler"
      flush
      actions={
        <button className="btn sm primary" onClick={() => setOpen(-1)}>
          Nesne ekle
        </button>
      }
    >
      <p className="small muted card-note">Algılama yalnızca bu prefix'lere giden/gelen trafik için yapılır. Profil, kural eşiklerini nesnenin tipine göre ölçekler.</p>
      {objs.length === 0 ? (
        <Empty>Henüz nesne yok</Empty>
      ) : (
        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>Nesne</th>
                <th>Prefix'ler</th>
                <th>Profil</th>
              </tr>
            </thead>
            <tbody>
              {objs.map((o, i) => (
                <tr key={i} className="row-link" onClick={() => setOpen(i)} title="Düzenlemek için tıklayın">
                  <td>
                    <div className="cell-main trunc" style={{ maxWidth: 220 }}>{o.name}</div>
                    {o.notes && <div className="cell-sub trunc" style={{ maxWidth: 220 }}>{o.notes}</div>}
                  </td>
                  <td className="mono small">
                    {o.prefixes.slice(0, 3).map((p) => (
                      <div key={p}>{p}</div>
                    ))}
                    {o.prefixes.length > 3 && <div className="cell-sub">+{o.prefixes.length - 3} daha</div>}
                  </td>
                  <td className="small">
                    {o.profile}
                    <div className="cell-sub">{bps(typeof o.link_capacity === "number" ? o.link_capacity : 0)} bağlantı</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {open !== null && (
        <ObjectModal
          initial={open === -1 ? emptyObject : objs[open]}
          profiles={resp.profiles}
          names={objs.filter((_, i) => i !== open).map((o) => o.name)}
          onClose={() => setOpen(null)}
          onSave={(o) =>
            edit((x) => {
              if (open === -1) x.protected_objects.push(o);
              else x.protected_objects[open] = o;
            })
          }
          onDelete={open === -1 ? undefined : () => edit((x) => void x.protected_objects.splice(open, 1))}
        />
      )}
    </Card>
  );
}

function ObjectModal(p: { initial: ObjectConfig; profiles: string[]; names: string[]; onClose: () => void; onSave: (o: ObjectConfig) => void; onDelete?: () => void }) {
  const [o, setO] = useState<ObjectConfig>(clone(p.initial));
  const set = (patch: Partial<ObjectConfig>) => setO({ ...o, ...patch });
  const dup = p.names.includes(o.name.trim());
  const ok = o.name.trim() !== "" && o.prefixes.length > 0 && !dup;
  return (
    <Modal
      title={p.onDelete ? o.name || "Nesne" : "Yeni nesne"}
      onClose={p.onClose}
      footer={
        <>
          {p.onDelete && (
            <button
              className="btn danger"
              style={{ marginRight: "auto" }}
              onClick={() => {
                if (window.confirm(o.name + " silinsin mi? Bu nesneye ait kapsamlı kullanıcılar etkilenebilir.")) {
                  p.onDelete!();
                  p.onClose();
                }
              }}
            >
              Sil
            </button>
          )}
          <button className="btn" onClick={p.onClose}>
            Vazgeç
          </button>
          <button
            className="btn primary"
            disabled={!ok}
            onClick={() => {
              p.onSave({ ...o, name: o.name.trim() });
              p.onClose();
            }}
          >
            Tamam
          </button>
        </>
      }
    >
      <div className="form">
        <TextIn label="Ad" value={o.name} onChange={(v) => set({ name: v })} hint={dup ? <span className="bad">Bu ad kullanılıyor</span> : "Raporlarda ve kullanıcı kapsamında görünür"} />
        <SelectIn label="Profil" value={o.profile} onChange={(v) => set({ profile: v })} options={p.profiles.includes(o.profile) ? p.profiles : [o.profile, ...p.profiles]} hint="Eşik ölçeği (rules/*.yaml)" />
        <ListIn label="Prefix'ler" value={o.prefixes} onChange={(v) => set({ prefixes: v })} full placeholder={"198.51.100.0/24\n2001:db8::/48"} hint="IPv4 / IPv6 CIDR, her satıra bir tane" />
        <RateIn label="Bağlantı kapasitesi" unit="bps" value={o.link_capacity} onChange={(v) => set({ link_capacity: v })} hint="RTBH eskalasyonu ve doluluk için" />
        <NumIn label="Carpet bombing blok (IPv4)" value={o.carpet_prefix_v4} min={8} max={32} onChange={(v) => set({ carpet_prefix_v4: v })} prefix="/" hint="Dağıtık saldırı toplama bloğu" />
        <NumIn label="Carpet bombing blok (IPv6)" value={o.carpet_prefix_v6} min={16} max={128} onChange={(v) => set({ carpet_prefix_v6: v })} prefix="/" />
        <TextIn label="Not" value={o.notes} onChange={(v) => set({ notes: v })} full />
      </div>
    </Modal>
  );
}

// ------------------------------------------------------------- rules

function RulesSection({ objects }: { objects: ObjectConfig[] }) {
  const r = usePoll(() => api.get<{ rules: RuleView[]; profiles: Record<string, Profile>; files: string[] }>("/rules"), 30000);
  const [q, setQ] = useState("");
  const [cat, setCat] = useState("");
  const [open, setOpen] = useState<RuleView | null>(null);
  const rules = (r.data?.rules ?? []).filter((x) => (!cat || x.category === cat) && (!q || (x.id + " " + x.name).toLowerCase().includes(q.toLowerCase())));
  const cats = [...new Set((r.data?.rules ?? []).map((x) => x.category))];
  const changed = (r.data?.rules ?? []).filter((x) => x.override).length;
  return (
    <Card
      title="Algılama kuralları"
      flush
      actions={
        <button className="btn sm" onClick={async () => { await run("Kurallar yeniden yüklendi", () => api.post("/rules/reload")); r.reload(); }}>
          Dosyalardan yeniden yükle
        </button>
      }
    >
      <p className="small muted card-note">
        {r.data?.rules.length ?? 0} kural · {changed} kuralda yerel değişiklik. Buradaki değişiklikler anında uygulanır ve kural dosyalarından ayrı saklanır; “varsayılana dön” ile kaldırılır.
      </p>
      <div className="row card-note">
        <input placeholder="Kural ara" value={q} onChange={(e) => setQ(e.target.value)} style={{ flex: 1, minWidth: 160 }} />
        <select value={cat} onChange={(e) => setCat(e.target.value)}>
          <option value="">Tüm kategoriler</option>
          {cats.map((c) => (
            <option key={c} value={c}>
              {categoryLabel[c] ?? c}
            </option>
          ))}
        </select>
      </div>
      <ErrorLine error={r.error} />
      <div className="tbl-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th>Kural</th>
              <th>Önem</th>
              <th className="num">Eşik</th>
              <th>Durum</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((x) => (
              <tr key={x.id} className="row-link" onClick={() => setOpen(x)}>
                <td style={{ maxWidth: 360 }}>
                  <div className="cell-main trunc">{x.name}</div>
                  <div className="cell-sub trunc">
                    {categoryLabel[x.category] ?? x.category} · {x.scope === "host" ? "tek hedef" : x.scope === "prefix" ? "blok" : "nesne"} · <span className="mono">{x.id}</span>
                  </div>
                </td>
                <td>
                  <Sev s={x.severity} />
                </td>
                <td className="num small">
                  {thrText(x.base_thresholds)}
                  {x.override && (x.override.pps !== undefined || x.override.bps !== undefined || x.override.fps !== undefined) && <div className="cell-sub">yerel eşik</div>}
                </td>
                <td>{x.active ? <Status s="ok" label="Açık" /> : <Status s="withdrawn" label="Kapalı" />}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {open && <RuleModal rule={open} objects={objects} onClose={() => setOpen(null)} onSaved={() => { r.reload(); setOpen(null); }} />}
    </Card>
  );
}

function thrText(t: { pps: number; bps: number; fps: number }) {
  const parts = [];
  if (t.pps) parts.push(pps(t.pps));
  if (t.bps) parts.push(bps(t.bps));
  if (t.fps) parts.push(formatRate(t.fps) + " flow/s");
  return parts.join(" · ") || "-";
}

function RuleModal({ rule, objects, onClose, onSaved }: { rule: RuleView; objects: ObjectConfig[]; onClose: () => void; onSaved: () => void }) {
  // base_thresholds = thresholds in force (file + local override);
  // thresholds = values from the rule file.
  const cur = rule.base_thresholds;
  const file = rule.thresholds;
  const [enabled, setEnabled] = useState(rule.active);
  const [t, setT] = useState({ pps: cur.pps, bps: cur.bps, fps: cur.fps });
  const changed = enabled !== rule.active || (["pps", "bps", "fps"] as const).some((k) => t[k] !== cur[k]);
  const save = async () => {
    const body: Record<string, unknown> = {};
    if (enabled !== rule.active) body.enabled = enabled;
    (["pps", "bps", "fps"] as const).forEach((k) => {
      // -1 removes the local value so the file's threshold applies again.
      if (t[k] !== cur[k]) body[k] = t[k] === file[k] ? -1 : t[k];
    });
    if (await run("Kural güncellendi", () => api.patch("/rules/" + rule.id, body))) onSaved();
  };
  const reset = async () => {
    if (await run("Kural varsayılana döndü", () => api.patch("/rules/" + rule.id, { reset: true }))) onSaved();
  };
  return (
    <Modal
      wide
      title={rule.name}
      onClose={onClose}
      footer={
        <>
          {rule.override && (
            <button className="btn" style={{ marginRight: "auto" }} onClick={reset}>
              Varsayılana dön
            </button>
          )}
          <button className="btn" onClick={onClose}>
            Vazgeç
          </button>
          <button className="btn primary" onClick={save} disabled={!changed}>
            Uygula
          </button>
        </>
      }
    >
      <p className="small ink2">{rule.description}</p>
      <dl className="kv">
        <dt>Eşleşme</dt>
        <dd className="mono small wrap">{rule.match_summary}</dd>
        <dt>Tetik</dt>
        <dd>
          {rule.sustain_seconds} sn üst üste aşım · bitiş {rule.hold_down_seconds} sn sakin
        </dd>
        <dt>Mitigasyon</dt>
        <dd>{actionLabel[rule.mitigation.action] ?? rule.mitigation.action}</dd>
        {rule.false_positives && (
          <>
            <dt>Yanlış alarm riski</dt>
            <dd className="small">{rule.false_positives}</dd>
          </>
        )}
      </dl>
      <div className="form" style={{ marginTop: 16 }}>
        <Toggle label="Kural etkin" value={enabled} onChange={setEnabled} full />
        <RateIn label="Paket eşiği" unit="pps" value={t.pps} onChange={(v) => setT({ ...t, pps: v })} hint={"Dosyadaki değer " + (file.pps ? pps(file.pps) : "yok")} />
        <RateIn label="Bit eşiği" unit="bps" value={t.bps} onChange={(v) => setT({ ...t, bps: v })} hint={"Dosyadaki değer " + (file.bps ? bps(file.bps) : "yok")} />
        <RateIn label="Flow eşiği" unit="fps" value={t.fps} onChange={(v) => setT({ ...t, fps: v })} hint={"Dosyadaki değer " + (file.fps ? formatRate(file.fps) : "yok")} />
      </div>
      <p className="small muted">0 = bu boyutta eşik yok. Değerler profil ölçeğinden önceki temel eşiklerdir; nesne başına efektif değerler aşağıdadır.</p>
      {objects.length > 0 && (
        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>Nesne</th>
                <th>Profil</th>
                <th className="num">Efektif eşik</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(rule.effective).map(([name, e]) => (
                <tr key={name}>
                  <td>{name}</td>
                  <td className="small">{e.profile}</td>
                  <td className="num small">{e.enabled ? thrText(e) : "profilde kapalı"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Modal>
  );
}

// ------------------------------------------------------------- telemetry

function TelemetrySection({ d, edit }: SP) {
  const ex = usePoll(() => api.get<{ exporters: Exporter[]; listening: string[]; rejected: number; queue_dropped: number }>("/exporters"), 5000);
  const c = d.collector;
  const overrides = d.exporters ?? [];
  const setOv = (i: number, patch: Partial<{ address: string; name: string; sampling_rate: number }>) =>
    edit((x) => {
      x.exporters = x.exporters ?? [];
      x.exporters[i] = { ...x.exporters[i], ...patch };
    });
  return (
    <>
      <Card title="Exporter'lar" flush>
        <ErrorLine error={ex.error} />
        <p className="small muted card-note">
          Dinlenen: <span className="mono">{(ex.data?.listening ?? []).join(", ") || "-"}</span>
          {ex.data && ex.data.rejected > 0 && <> · izin listesi dışında reddedilen paket {num(ex.data.rejected)}</>}
          {ex.data && ex.data.queue_dropped > 0 && <> · kuyruk taşması {num(ex.data.queue_dropped)}</>}
        </p>
        {(ex.data?.exporters ?? []).length === 0 ? (
          <Empty>Henüz flow gelmedi</Empty>
        ) : (
          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Exporter</th>
                  <th>Protokol</th>
                  <th className="num">Kayıt/sn</th>
                  <th className="num">Örnekleme</th>
                  <th>Son görülme</th>
                </tr>
              </thead>
              <tbody>
                {(ex.data?.exporters ?? []).map((e) => {
                  const stale = Date.now() / 1000 - e.last_seen > 60;
                  return (
                    <tr key={e.address}>
                      <td>
                        <div className="cell-main mono">{e.address}</div>
                        <div className="cell-sub">
                          {e.name || "isimsiz"}
                          {e.errors > 0 && ` · ${num(e.errors)} hata`}
                          {e.missing_template > 0 && ` · ${num(e.missing_template)} şablonsuz`}
                        </div>
                      </td>
                      <td className="small">{Object.keys(e.protocols).join(", ")}</td>
                      <td className="num">{num(e.records_per_sec)}</td>
                      <td className="num small">
                        1:{e.sampling_override || e.sampling_reported || e.sampling_learned || 1}
                        <div className="cell-sub">{e.sampling_override ? "elle" : e.sampling_reported ? "exporter" : "varsayılan"}</div>
                      </td>
                      <td className="small">{stale ? <Status s="failed" label={ago(e.last_seen)} /> : ago(e.last_seen)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <Card>
        <Section
          title="Exporter tanımları"
          desc="İsim ve örnekleme oranı tanımlayın. Örnekleme oranı exporter'ın bildirdiği değeri ezer (bildirmeyen cihazlar için gerekli)."
          actions={
            <button className="btn sm" onClick={() => edit((x) => void (x.exporters = [...(x.exporters ?? []), { address: "", name: "", sampling_rate: 0 }]))}>
              Exporter ekle
            </button>
          }
        >
          {overrides.length === 0 && <p className="small muted field full">Tanım yok; tüm exporter'lar kabul edilir ve bildirdikleri örnekleme kullanılır.</p>}
          {overrides.map((o, i) => (
            <div key={i} className="field full">
              <div className="row nowrap-row">
                <input className="mono" placeholder="IP adresi" value={o.address} onChange={(e) => setOv(i, { address: e.target.value })} aria-label="Exporter adresi" />
                <input placeholder="isim" value={o.name} onChange={(e) => setOv(i, { name: e.target.value })} aria-label="Exporter adı" />
                <input inputMode="numeric" placeholder="örnekleme (1:N)" value={o.sampling_rate || ""} onChange={(e) => setOv(i, { sampling_rate: Number(e.target.value) || 0 })} aria-label="Örnekleme oranı" />
                <button className="btn sm ghost" onClick={() => edit((x) => void x.exporters!.splice(i, 1))} aria-label="Kaldır">
                  Kaldır
                </button>
              </div>
            </div>
          ))}
        </Section>
        <Section title="Collector">
          <ListIn label="Dinlenen adresler" value={c.listen} onChange={(v) => edit((x) => void (x.collector.listen = v))} hint="ör. :2055 (NetFlow), :4739 (IPFIX), :6343 (sFlow). Yeniden başlatma gerekir." />
          <ListIn label="İzin verilen exporter'lar" value={c.allow} onChange={(v) => edit((x) => void (x.collector.allow = v))} hint="IP veya prefix. Boş = hepsi kabul edilir. Production için önerilir." />
          <ListIn label="Flow yönlendirme" value={c.forward} onChange={(v) => edit((x) => void (x.collector.forward = v))} hint="Gelen paketleri başka collector'lara kopyalar (host:port). Mevcut sistemle paralel çalışma için." />
          <NumIn label="Varsayılan örnekleme" value={c.default_sampling_rate} min={1} onChange={(v) => edit((x) => void (x.collector.default_sampling_rate = v))} hint="Exporter bildirmezse 1:N" />
          <NumIn label="İşçi sayısı" value={c.workers} min={1} max={256} onChange={(v) => edit((x) => void (x.collector.workers = v))} hint="Paralel decode/sınıflandırma. Yeniden başlatma gerekir." />
          <NumIn label="Kuyruk boyu" value={c.queue_size} min={1024} onChange={(v) => edit((x) => void (x.collector.queue_size = v))} hint="Datagram. Yeniden başlatma gerekir." />
          <NumIn label="Soket okuma tamponu" value={c.read_buffer_bytes} min={0} onChange={(v) => edit((x) => void (x.collector.read_buffer_bytes = v))} suffix="bayt" hint="Yeniden başlatma gerekir." />
        </Section>
      </Card>
    </>
  );
}

// ------------------------------------------------------------- engine

function EngineSection({ d, edit }: SP) {
  const e = d.engine;
  const set = (patch: Partial<Draft["engine"]>) => edit((x) => void (x.engine = { ...x.engine, ...patch }));
  return (
    <Card>
      <Section title="Ölçüm" desc="Hızlar kayan pencere üzerinden hesaplanır. Kısa pencere daha hızlı algılar, uzun pencere daha az dalgalanır.">
        <DurIn label="Ölçüm penceresi" value={e.window} onChange={(v) => set({ window: v })} hint="Önerilen 10s" />
        <DurIn label="Uzun flow yayma süresi" value={e.max_flow_spread} onChange={(v) => set({ max_flow_spread: v })} hint="Uzun süreli flow'lar bu süreye kadar saniyelere dağıtılır" />
        <NumIn label="Saklanan flow kaydı" value={e.recent_flows} min={10000} onChange={(v) => set({ recent_flows: v })} hint="Gezgin ve analist için bellek içi halka. Yeniden başlatma gerekir." />
        <NumIn label="En fazla seri" value={e.max_series} min={1000} onChange={(v) => set({ max_series: v })} hint="Bellek sınırı; aşılırsa tek hedef serileri yerine blok/nesne seviyesinde izlenir" />
      </Section>
      <Section title="Baseline (normal trafik öğrenme)">
        <DurIn label="Baseline zaman sabiti" value={e.baseline_tau} onChange={(v) => set({ baseline_tau: v })} hint="Üstel ortalama; büyük değer = daha yavaş uyum" />
        <DurIn label="Öğrenme süresi" value={e.baseline_learn} onChange={(v) => set({ baseline_learn: v })} hint="Bu süre dolmadan baseline tabanlı kurallar tetiklenmez" />
      </Section>
      <Section title="AI analist sinyalleri" desc="Eşiğin altında kalan ama normalden sapan trafik analiste aday sinyal olarak gönderilir.">
        <NumIn label="Eşiğe yakınlık oranı" value={e.near_miss_ratio} min={0.1} max={1} step={0.05} onChange={(v) => set({ near_miss_ratio: v })} hint="ör. 0.6 = eşiğin %60'ı" />
        <NumIn label="En az z-skoru" value={e.signal_min_z} min={1} onChange={(v) => set({ signal_min_z: v })} hint="Baseline sapması için" />
        <RateIn label="En az paket hızı" unit="pps" value={e.signal_min_pps} onChange={(v) => set({ signal_min_pps: v })} />
        <RateIn label="En az bit hızı" unit="bps" value={e.signal_min_bps} onChange={(v) => set({ signal_min_bps: v })} />
        <NumIn label="Kalıcılık" value={e.signal_min_seconds} min={1} onChange={(v) => set({ signal_min_seconds: v })} suffix="sn" hint="Sapma bu kadar sürmeli (gürültü bastırma)" />
      </Section>
      <Section title="Olaylar">
        <DurIn label="Yeniden açma süresi" value={e.incident_reopen} onChange={(v) => set({ incident_reopen: v })} hint="Bu süre içinde aynı hedefe gelen saldırı aynı olaya eklenir" />
        <DurIn label="Kanıt toplama aralığı" value={e.evidence_every} onChange={(v) => set({ evidence_every: v })} />
      </Section>
    </Card>
  );
}

// ------------------------------------------------------------- mitigation

function MitigationSection({ d, edit }: SP) {
  const m = d.mitigation;
  const set = (patch: Partial<Draft["mitigation"]>) => edit((x) => void (x.mitigation = { ...x.mitigation, ...patch }));
  return (
    <Card>
      <Section title="Politika">
        <SelectIn
          label="Mod"
          value={m.mode}
          onChange={(v) => set({ mode: v })}
          options={[
            ["manual", "Manuel onay"],
            ["auto", "Otomatik"],
            ["off", "Kapalı (yalnızca algılama)"],
          ]}
          hint={m.mode === "auto" ? "Güvenlik kontrollerinden geçen kural önerileri onaysız uygulanır. RTBH ve AI önerileri her zaman onay ister." : "Öneriler onay kuyruğuna düşer."}
        />
        <SelectIn
          label="Sürücü"
          value={m.driver}
          onChange={(v) => set({ driver: v })}
          options={[
            ["dryrun", "Dry-run (yalnızca kayıt)"],
            ["exabgp", "ExaBGP (BGP FlowSpec / RTBH)"],
            ["webhook", "Webhook (harici orkestratör)"],
          ]}
        />
        <DurIn label="Varsayılan süre (TTL)" value={m.default_ttl} onChange={(v) => set({ default_ttl: v })} hint="Kural bu süre sonunda otomatik geri çekilir" />
        <DurIn label="Saldırı bitince geri çek" value={m.withdraw_after} onChange={(v) => set({ withdraw_after: v })} hint="Olay bittikten sonra bekleme" />
        <NumIn label="En fazla aktif kural" value={m.max_active} min={1} onChange={(v) => set({ max_active: v })} />
        <Toggle label="RTBH'ye izin ver" value={m.allow_rtbh} onChange={(v) => set({ allow_rtbh: v })} hint="Hedefi tamamen karadeliğe atar; yalnızca onayla uygulanır" />
      </Section>
      <Section title="Güvenlik kontrolleri" desc="Yanlışlıkla geniş blokların kapatılmasını önler.">
        <NumIn label="En dar IPv4 prefix" value={m.min_prefix_v4} min={8} max={32} prefix="/" onChange={(v) => set({ min_prefix_v4: v })} hint="ör. 24 → /23 ve daha geniş bloklar reddedilir" />
        <NumIn label="En dar IPv6 prefix" value={m.min_prefix_v6} min={16} max={128} prefix="/" onChange={(v) => set({ min_prefix_v6: v })} />
        <ListIn label="Asla mitigasyon uygulanmayacak adresler" value={m.never_mitigate} onChange={(v) => set({ never_mitigate: v })} full hint="DNS, router loopback, yönetim ağları vb." />
      </Section>
      {m.driver === "exabgp" && (
        <Section title="ExaBGP">
          <TextIn label="Komut dosyası / FIFO" mono value={m.exabgp.command_file} onChange={(v) => set({ exabgp: { ...m.exabgp, command_file: v } })} hint="ExaBGP'nin okuduğu named pipe" />
          <TextIn label="RTBH next-hop" mono value={m.exabgp.rtbh_next_hop} onChange={(v) => set({ exabgp: { ...m.exabgp, rtbh_next_hop: v } })} placeholder="192.0.2.1" />
          <TextIn label="RTBH community" mono value={m.exabgp.rtbh_community} onChange={(v) => set({ exabgp: { ...m.exabgp, rtbh_community: v } })} placeholder="65535:666" />
        </Section>
      )}
      {m.driver === "webhook" && (
        <Section title="Webhook">
          <TextIn label="URL" mono value={m.webhook.url} onChange={(v) => set({ webhook: { ...m.webhook, url: v } })} full placeholder="https://orchestrator.example.net/ddos" />
          <SecretIn label="HMAC anahtarı" value={m.webhook.secret} onChange={(v) => set({ webhook: { ...m.webhook, secret: v } })} />
        </Section>
      )}
    </Card>
  );
}

// ------------------------------------------------------------- notifications

const channelTypes: [string, string][] = [
  ["slack", "Slack"],
  ["teams", "Microsoft Teams"],
  ["telegram", "Telegram"],
  ["email", "E-posta"],
  ["syslog", "Syslog / SIEM"],
  ["webhook", "Webhook"],
];
const eventLabel: Record<string, string> = {
  "incident.started": "Saldırı başladı",
  "incident.ended": "Saldırı bitti",
  "vector.added": "Yeni saldırı vektörü",
  "mitigation.pending": "Mitigasyon onay bekliyor",
  "mitigation.active": "Mitigasyon uygulandı",
  "mitigation.withdrawn": "Mitigasyon geri çekildi",
  "mitigation.failed": "Mitigasyon hatası",
  "finding.created": "AI analist bulgusu",
};

function NotificationsSection({ d, edit, resp }: SP) {
  const st = usePoll(() => api.get<ChannelStatus[]>("/notifications"), 10000);
  const [open, setOpen] = useState<number | null>(null);
  const chans = d.notifications.channels ?? [];
  const status = (n: string) => (st.data ?? []).find((s) => s.name === n);
  return (
    <Card
      title="Bildirim kanalları"
      flush
      actions={
        <button className="btn sm primary" onClick={() => setOpen(-1)}>
          Kanal ekle
        </button>
      }
    >
      <p className="small muted card-note">Saldırı, mitigasyon ve analist olayları seçilen kanallara gönderilir. Kaydetmeden önce “Test gönder” ile deneyebilirsiniz.</p>
      {chans.length === 0 ? (
        <Empty>Kanal yok</Empty>
      ) : (
        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>Kanal</th>
                <th>En düşük önem</th>
                <th className="num">Gönderilen</th>
                <th>Durum</th>
              </tr>
            </thead>
            <tbody>
              {chans.map((c, i) => {
                const s = status(c.name);
                return (
                  <tr key={i} className="row-link" onClick={() => setOpen(i)}>
                    <td>
                      <div className="cell-main">{c.name}</div>
                      <div className="cell-sub">
                        {channelTypes.find((t) => t[0] === c.type)?.[1] ?? c.type} · {c.events?.length ? c.events.length + " olay" : "varsayılan olaylar"}
                      </div>
                    </td>
                    <td>
                      <Sev s={c.min_severity || "low"} />
                    </td>
                    <td className="num">
                      {num(s?.sent)}
                      {s?.failed ? <div className="cell-sub">{num(s.failed)} hata</div> : null}
                    </td>
                    <td className="small" style={{ maxWidth: 240 }}>
                      {!c.enabled ? <Status s="withdrawn" label="Kapalı" /> : s?.last_error ? <span className="bad trunc" title={s.last_error}>{s.last_error}</span> : <Status s="ok" label={s?.last_sent ? "Son " + ago(s.last_sent) : "Açık"} />}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {open !== null && (
        <ChannelModal
          initial={open === -1 ? { name: "", type: "slack", enabled: true, min_severity: "medium", events: [] } : chans[open]}
          events={resp.notification_events}
          names={chans.filter((_, i) => i !== open).map((c) => c.name)}
          onClose={() => setOpen(null)}
          onSave={(c) =>
            edit((x) => {
              x.notifications.channels = x.notifications.channels ?? [];
              if (open === -1) x.notifications.channels.push(c);
              else x.notifications.channels[open] = c;
            })
          }
          onDelete={open === -1 ? undefined : () => edit((x) => void x.notifications.channels!.splice(open, 1))}
        />
      )}
    </Card>
  );
}

function ChannelModal(p: { initial: ChannelConfig; events: string[]; names: string[]; onClose: () => void; onSave: (c: ChannelConfig) => void; onDelete?: () => void }) {
  const [c, setC] = useState<ChannelConfig>(clone(p.initial));
  const set = (patch: Partial<ChannelConfig>) => setC({ ...c, ...patch });
  const ev = c.events ?? [];
  const dup = p.names.includes(c.name.trim());
  const test = () => run("Test bildirimi gönderildi", () => api.post("/notifications/test", c));
  return (
    <Modal
      wide
      title={p.onDelete ? c.name : "Yeni bildirim kanalı"}
      onClose={p.onClose}
      footer={
        <>
          {p.onDelete && (
            <button
              className="btn danger"
              style={{ marginRight: "auto" }}
              onClick={() => {
                if (window.confirm(c.name + " silinsin mi?")) {
                  p.onDelete!();
                  p.onClose();
                }
              }}
            >
              Sil
            </button>
          )}
          <button className="btn" onClick={test} disabled={!c.name}>
            Test gönder
          </button>
          <button className="btn" onClick={p.onClose}>
            Vazgeç
          </button>
          <button
            className="btn primary"
            disabled={!c.name.trim() || dup}
            onClick={() => {
              p.onSave({ ...c, name: c.name.trim() });
              p.onClose();
            }}
          >
            Tamam
          </button>
        </>
      }
    >
      <div className="form">
        <TextIn label="Ad" value={c.name} onChange={(v) => set({ name: v })} hint={dup ? <span className="bad">Bu ad kullanılıyor</span> : undefined} />
        <SelectIn label="Tür" value={c.type} onChange={(v) => set({ type: v, protocol: v === "syslog" ? c.protocol || "udp" : c.protocol, smtp_port: v === "email" ? c.smtp_port || 587 : c.smtp_port })} options={channelTypes} />
        <SelectIn
          label="En düşük önem"
          value={c.min_severity || "low"}
          onChange={(v) => set({ min_severity: v })}
          options={[
            ["low", "Düşük ve üstü"],
            ["medium", "Orta ve üstü"],
            ["high", "Yüksek ve üstü"],
            ["critical", "Yalnızca kritik"],
          ]}
        />
        <Toggle label="Kanal etkin" value={c.enabled} onChange={(v) => set({ enabled: v })} />
        {(c.type === "slack" || c.type === "teams") && <TextIn label="Incoming webhook URL" mono full value={c.url} onChange={(v) => set({ url: v })} placeholder="https://hooks.slack.com/services/…" />}
        {c.type === "webhook" && (
          <>
            <TextIn label="URL" mono full value={c.url} onChange={(v) => set({ url: v })} placeholder="https://soar.example.net/hooks/ddos" />
            <SecretIn label="HMAC anahtarı" value={c.secret} onChange={(v) => set({ secret: v })} hint="X-DDoS-Signature başlığı ile imzalanır" />
          </>
        )}
        {c.type === "telegram" && (
          <>
            <SecretIn label="Bot token" value={c.bot_token} onChange={(v) => set({ bot_token: v })} />
            <TextIn label="Chat ID" mono value={c.chat_id} onChange={(v) => set({ chat_id: v })} />
          </>
        )}
        {c.type === "syslog" && (
          <>
            <TextIn label="Sunucu (host:port)" mono value={c.address} onChange={(v) => set({ address: v })} placeholder="siem.example.net:514" />
            <SelectIn label="Protokol" value={c.protocol || "udp"} onChange={(v) => set({ protocol: v })} options={["udp", "tcp"]} hint="RFC 5424, facility local0" />
          </>
        )}
        {c.type === "email" && (
          <>
            <TextIn label="SMTP sunucu" mono value={c.smtp_host} onChange={(v) => set({ smtp_host: v })} />
            <NumIn label="SMTP port" value={c.smtp_port || 587} min={1} max={65535} onChange={(v) => set({ smtp_port: v })} hint="587 = STARTTLS" />
            <TextIn label="Kullanıcı" value={c.username} onChange={(v) => set({ username: v })} />
            <SecretIn label="Parola" value={c.password} onChange={(v) => set({ password: v })} />
            <TextIn label="Gönderen" value={c.from} onChange={(v) => set({ from: v })} placeholder="ddos@example.net" />
            <ListIn label="Alıcılar" value={c.to} onChange={(v) => set({ to: v })} />
          </>
        )}
        <Field label="Olaylar" hint="Hiçbiri seçilmezse saldırı başlangıç/bitiş, onay bekleyen ve hatalı mitigasyon olayları gönderilir." full>
          <div className="check-grid">
            {p.events.map((e) => (
              <label key={e} className="check">
                <input type="checkbox" checked={ev.includes(e)} onChange={(x) => set({ events: x.target.checked ? [...ev, e] : ev.filter((y) => y !== e) })} />
                {eventLabel[e] ?? e}
              </label>
            ))}
          </div>
        </Field>
      </div>
    </Modal>
  );
}

// ------------------------------------------------------------- analyst

function AnalystSection({ d, edit }: SP) {
  const a = d.analyst;
  const set = (patch: Partial<Draft["analyst"]>) => edit((x) => void (x.analyst = { ...x.analyst, ...patch }));
  return (
    <Card>
      <Section title="AI analist" desc="Analist yalnızca özet veriye bakar, her flow'u LLM'e göndermez ve hiçbir aksiyonu kendisi uygulamaz.">
        <Toggle label="Analist etkin" value={a.enabled} onChange={(v) => set({ enabled: v })} />
        <Toggle label="Bekleyen sinyalleri otomatik analiz et" value={a.auto_run} onChange={(v) => set({ auto_run: v })} />
        <SelectIn
          label="Sağlayıcı"
          value={a.provider}
          onChange={(v) => set({ provider: v })}
          options={[
            ["heuristic", "Kural tabanlı (LLM yok)"],
            ["anthropic", "Claude API"],
            ["openai_compat", "Yerel / OpenAI uyumlu (Ollama, vLLM)"],
          ]}
          hint={a.provider === "anthropic" ? "ANTHROPIC_API_KEY ortam değişkeni gerekir" : undefined}
        />
        {a.provider === "anthropic" && <TextIn label="Model" mono value={a.model} onChange={(v) => set({ model: v })} placeholder="claude-opus-5-5" />}
        {a.provider === "anthropic" && <SelectIn label="Düşünme seviyesi" value={a.effort || "medium"} onChange={(v) => set({ effort: v })} options={["low", "medium", "high"]} />}
        <DurIn label="Otomatik çalışma aralığı" value={a.interval} onChange={(v) => set({ interval: v })} />
        <SelectIn
          label="Rapor dili"
          value={a.language || "tr"}
          onChange={(v) => set({ language: v })}
          options={[
            ["tr", "Türkçe"],
            ["en", "English"],
          ]}
        />
        <NumIn label="En fazla araç turu" value={a.max_turns} min={1} max={50} onChange={(v) => set({ max_turns: v })} />
        <NumIn label="En fazla çıktı token" value={a.max_tokens} min={1024} onChange={(v) => set({ max_tokens: v })} />
      </Section>
      {a.provider === "openai_compat" && (
        <Section title="Yerel model">
          <TextIn label="Base URL" mono value={a.openai_compat.base_url} onChange={(v) => set({ openai_compat: { ...a.openai_compat, base_url: v } })} placeholder="http://127.0.0.1:11434/v1" full />
          <TextIn label="Model" mono value={a.openai_compat.model} onChange={(v) => set({ openai_compat: { ...a.openai_compat, model: v } })} placeholder="qwen2.5:32b-instruct" />
          <TextIn label="API key ortam değişkeni" mono value={a.openai_compat.api_key_env} onChange={(v) => set({ openai_compat: { ...a.openai_compat, api_key_env: v } })} hint="Anahtar dosyaya yazılmaz" />
        </Section>
      )}
    </Card>
  );
}

// ------------------------------------------------------------- access

function AccessSection({ d, edit }: SP) {
  const a = d.api;
  const set = (patch: Partial<Draft["api"]>) => edit((x) => void (x.api = { ...x.api, ...patch }));
  return (
    <Card>
      <Section title="Web arayüzü ve REST API">
        <TextIn label="Dinleme adresi" mono value={a.listen} onChange={(v) => set({ listen: v })} hint="Yeniden başlatma gerekir" />
        <TextIn label="Dış adres (base URL)" mono value={a.base_url} onChange={(v) => set({ base_url: v })} placeholder="https://ddos.example.net" hint="Bildirimlerdeki bağlantılar için" />
        <DurIn label="Oturum süresi" value={a.session_ttl} onChange={(v) => set({ session_ttl: v })} />
      </Section>
      <Section title="TLS" desc="Sertifika verilirse HTTPS ile sunulur. Production'da TLS veya önünde TLS sonlandıran bir proxy kullanın.">
        <TextIn label="Sertifika dosyası" mono value={a.tls_cert} onChange={(v) => set({ tls_cert: v })} placeholder="/etc/ddosd/tls.crt" />
        <TextIn label="Anahtar dosyası" mono value={a.tls_key} onChange={(v) => set({ tls_key: v })} placeholder="/etc/ddosd/tls.key" />
      </Section>
      <p className="small muted">Kullanıcılar ve API token'ları “Kullanıcılar” bölümünden yönetilir. Prometheus metrikleri <span className="mono">/metrics</span>, sağlık kontrolleri <span className="mono">/healthz</span> ve <span className="mono">/readyz</span> adreslerindedir.</p>
    </Card>
  );
}

// ------------------------------------------------------------- users

const roleText: Record<string, string> = { viewer: "İzleyici", operator: "Operatör", admin: "Yönetici" };

function UsersSection({ objects }: { objects: string[] }) {
  const me = useMe();
  const u = usePoll(() => api.get<UserRecord[]>("/users"), 15000);
  // Keep only the name so the dialog always shows the latest record
  // (e.g. a token created inside it).
  const [open, setOpen] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const openUser = (u.data ?? []).find((x) => x.username === open);
  return (
    <Card
      title="Kullanıcılar"
      flush
      actions={
        <button className="btn sm primary" onClick={() => setCreating(true)}>
          Kullanıcı ekle
        </button>
      }
    >
      <p className="small muted card-note">İzleyici: yalnızca görüntüler. Operatör: mitigasyon onaylar, analizi çalıştırır. Yönetici: ayarlar ve kullanıcılar. Nesne kapsamı verilen kullanıcı yalnızca o müşterinin verisini görür.</p>
      <ErrorLine error={u.error} />
      <div className="tbl-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th>Kullanıcı</th>
              <th>Rol</th>
              <th>Kapsam</th>
              <th>Son giriş</th>
            </tr>
          </thead>
          <tbody>
            {(u.data ?? []).map((x) => (
              <tr key={x.username} className="row-link" onClick={() => setOpen(x.username)}>
                <td>
                  <div className="cell-main">
                    {x.username}
                    {x.username === me.username && <span className="muted small"> (siz)</span>}
                  </div>
                  <div className="cell-sub">{x.disabled ? "pasif" : x.tokens.length ? x.tokens.length + " API token" : "aktif"}</div>
                </td>
                <td className="small">{roleText[x.role] ?? x.role}</td>
                <td className="small" style={{ maxWidth: 220 }}>
                  <div className="trunc">{x.objects?.length ? x.objects.join(", ") : "tüm nesneler"}</div>
                </td>
                <td className="small">{x.last_login ? ago(x.last_login) : "hiç"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {creating && <UserModal user={null} objects={objects} self={me.username} onClose={() => setCreating(false)} onChanged={u.reload} />}
      {openUser && <UserModal key={openUser.username} user={openUser} objects={objects} self={me.username} onClose={() => setOpen(null)} onChanged={u.reload} />}
    </Card>
  );
}

function UserModal(p: { user: UserRecord | null; objects: string[]; self: string; onClose: () => void; onChanged: () => void }) {
  const [name, setName] = useState(p.user?.username ?? "");
  const [role, setRole] = useState(p.user?.role ?? "viewer");
  const [scope, setScope] = useState<string[]>(p.user?.objects ?? []);
  const [disabled, setDisabled] = useState(p.user?.disabled ?? false);
  const [pass, setPass] = useState("");
  const [tokenName, setTokenName] = useState("");
  const [newToken, setNewToken] = useState<string | null>(null);
  const isNew = !p.user;
  const valid = /^[a-zA-Z0-9._@-]{2,64}$/.test(name) && (!isNew || pass.length >= 10) && (pass === "" || pass.length >= 10);
  const save = async () => {
    const r = await run("Kullanıcı kaydedildi", () => api.put("/users/" + encodeURIComponent(name), { role, objects: scope, disabled, password: pass || undefined }));
    if (r) {
      p.onChanged();
      p.onClose();
    }
  };
  const del = async () => {
    if (!window.confirm(name + " silinsin mi?")) return;
    if (await run("Kullanıcı silindi", () => api.del("/users/" + encodeURIComponent(name)))) {
      p.onChanged();
      p.onClose();
    }
  };
  const createToken = async () => {
    const r = await run("Token oluşturuldu", () => api.post<{ token: string }>(`/users/${encodeURIComponent(name)}/tokens`, { name: tokenName }));
    if (r) {
      setNewToken(r.token);
      setTokenName("");
      p.onChanged();
    }
  };
  const delToken = async (id: string) => {
    if (await run("Token silindi", () => api.del(`/users/${encodeURIComponent(name)}/tokens/${id}`))) p.onChanged();
  };
  return (
    <Modal
      wide
      title={isNew ? "Yeni kullanıcı" : name}
      onClose={p.onClose}
      footer={
        <>
          {!isNew && name !== p.self && (
            <button className="btn danger" style={{ marginRight: "auto" }} onClick={del}>
              Sil
            </button>
          )}
          <button className="btn" onClick={p.onClose}>
            Kapat
          </button>
          <button className="btn primary" disabled={!valid} onClick={save}>
            Kaydet
          </button>
        </>
      }
    >
      <div className="form">
        <TextIn label="Kullanıcı adı" value={name} onChange={setName} disabled={!isNew} hint={isNew ? "harf, rakam, . _ @ -" : undefined} />
        <SelectIn
          label="Rol"
          value={role}
          onChange={setRole}
          options={[
            ["viewer", "İzleyici"],
            ["operator", "Operatör"],
            ["admin", "Yönetici"],
          ]}
        />
        <TextIn label={isNew ? "Parola" : "Yeni parola"} type="password" value={pass} onChange={setPass} hint={pass && pass.length < 10 ? <span className="bad">En az 10 karakter</span> : isNew ? "En az 10 karakter" : "Boş bırakılırsa değişmez"} />
        <Toggle label="Hesap pasif" value={disabled} onChange={setDisabled} hint="Giriş ve token kullanımı engellenir" />
        <Field label="Nesne kapsamı" hint="Seçilmezse tüm nesneleri görür. Kapsamlı kullanıcılar altyapı ayarlarını göremez." full>
          <div className="check-grid">
            {p.objects.map((o) => (
              <label key={o} className="check">
                <input type="checkbox" checked={scope.includes(o)} onChange={(e) => setScope(e.target.checked ? [...scope, o] : scope.filter((x) => x !== o))} />
                {o}
              </label>
            ))}
          </div>
        </Field>
      </div>
      {!isNew && (
        <div className="fs">
          <div className="fs-head">
            <div>
              <h3>API token'ları</h3>
              <p className="small muted">Otomasyon için: <span className="mono">Authorization: Bearer &lt;token&gt;</span>. Token kullanıcının rol ve kapsamıyla çalışır.</p>
            </div>
          </div>
          {newToken && <Code label="Yeni token — yalnızca şimdi gösterilir" text={newToken} />}
          {(p.user?.tokens ?? []).length > 0 && (
            <div className="tbl-wrap">
              <table className="tbl">
                <tbody>
                  {p.user!.tokens.map((t) => (
                    <tr key={t.id}>
                      <td>
                        <div className="cell-main">{t.name}</div>
                        <div className="cell-sub mono">{t.prefix}…</div>
                      </td>
                      <td className="small">oluşturuldu {dateTime(t.created_at)}</td>
                      <td className="small">{t.last_used ? "son kullanım " + ago(t.last_used) : "kullanılmadı"}</td>
                      <td className="r">
                        <button className="btn sm danger" onClick={() => delToken(t.id)}>
                          İptal et
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <div className="row" style={{ marginTop: 10 }}>
            <input placeholder="token adı (ör. grafana)" value={tokenName} onChange={(e) => setTokenName(e.target.value)} style={{ flex: 1, minWidth: 160 }} />
            <button className="btn" disabled={!tokenName} onClick={createToken}>
              Token oluştur
            </button>
          </div>
        </div>
      )}
    </Modal>
  );
}

// ------------------------------------------------------------- audit

const actionText: Record<string, string> = {
  "auth.login": "Giriş",
  "auth.logout": "Çıkış",
  "auth.password": "Parola değişikliği",
  "config.update": "Yapılandırma değişikliği",
  "config.restore": "Yapılandırma geri yükleme",
  "rule.update": "Kural değişikliği",
  "rule.reload": "Kuralları yeniden yükleme",
  "user.save": "Kullanıcı kaydı",
  "user.delete": "Kullanıcı silme",
  "token.create": "Token oluşturma",
  "token.delete": "Token silme",
  "mitigation.create": "Mitigasyon talebi",
  "mitigation.action": "Mitigasyon işlemi",
  "analyst.run": "Analiz çalıştırma",
  "analyst.ask": "Analiste soru",
  "analyst.apply": "Öneri uygulama",
  "notification.test": "Bildirim testi",
};

function AuditSection() {
  const [user, setUser] = useState("");
  const [action, setAction] = useState("");
  const a = usePoll(() => api.get<AuditEntry[]>(`/audit?limit=300&user=${encodeURIComponent(user)}&action=${encodeURIComponent(action)}`), 10000, [user, action]);
  return (
    <Card title="Denetim kaydı" flush>
      <p className="small muted card-note">Tüm değiştirici işlemler ve girişler kaydedilir (son 5000 kayıt).</p>
      <div className="row card-note">
        <input placeholder="kullanıcı" value={user} onChange={(e) => setUser(e.target.value)} />
        <select value={action} onChange={(e) => setAction(e.target.value)}>
          <option value="">tüm işlemler</option>
          {Object.entries(actionText).map(([k, v]) => (
            <option key={k} value={k}>
              {v}
            </option>
          ))}
        </select>
      </div>
      <ErrorLine error={a.error} />
      {(a.data ?? []).length === 0 ? (
        <Empty>Kayıt yok</Empty>
      ) : (
        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>Zaman</th>
                <th>Kullanıcı</th>
                <th>İşlem</th>
                <th>Ayrıntı</th>
              </tr>
            </thead>
            <tbody>
              {(a.data ?? []).map((x, i) => (
                <tr key={i}>
                  <td className="small nowrap">{dateTime(x.t)}</td>
                  <td>
                    <div className="cell-main">{x.user || "-"}</div>
                    <div className="cell-sub mono">{x.client}</div>
                  </td>
                  <td className="small">
                    {actionText[x.action] ?? x.action}
                    {!x.ok && <div className="bad">başarısız</div>}
                  </td>
                  <td className="small wrap" style={{ maxWidth: 360 }}>
                    {[x.target, x.detail, x.error].filter(Boolean).join(" · ")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

// ------------------------------------------------------------- history

function HistorySection({ onRestored }: { onRestored: () => void }) {
  const h = usePoll(() => api.get<HistoryEntry[]>("/config/history"), 15000);
  const [view, setView] = useState<{ id: string; yaml: string } | null>(null);
  const restore = async (id: string) => {
    if (!window.confirm(id + " sürümüne geri dönülsün mü? Mevcut yapılandırma da geçmişe kaydedilir.")) return;
    if (await run("Sürüm geri yüklendi", () => api.post(`/config/history/${id}/restore`))) {
      h.reload();
      onRestored();
    }
  };
  const list = h.data ?? [];
  return (
    <Card title="Değişiklik geçmişi" flush>
      <p className="small muted card-note">Arayüzden yapılan her kayıt bir sürüm oluşturur (son 100). Bir sürüme dönmek de yeni bir sürüm olarak kaydedilir.</p>
      <ErrorLine error={h.error} />
      {list.length === 0 ? (
        <Empty>Henüz arayüzden değişiklik yapılmadı</Empty>
      ) : (
        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>Sürüm</th>
                <th>Kim</th>
                <th>Not</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {list.map((x, i) => (
                <tr key={x.id}>
                  <td>
                    <div className="cell-main">{dateTime(x.time)}</div>
                    <div className="cell-sub mono">
                      {x.id}
                      {i === 0 && " · güncel"}
                    </div>
                  </td>
                  <td className="small">{x.actor}</td>
                  <td className="small wrap" style={{ maxWidth: 320 }}>
                    {x.comment || <span className="muted">-</span>}
                    {x.restart_required?.length ? <div className="cell-sub">yeniden başlatma: {x.restart_required.join(", ")}</div> : null}
                  </td>
                  <td className="r nowrap">
                    <button className="btn sm ghost" onClick={async () => setView(await api.get(`/config/history/${x.id}`))}>
                      Görüntüle
                    </button>
                    {i > 0 && (
                      <button className="btn sm" onClick={() => restore(x.id)}>
                        Geri dön
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {view && (
        <Modal wide title={"Sürüm " + view.id} onClose={() => setView(null)}>
          <pre className="yaml">{view.yaml}</pre>
        </Modal>
      )}
    </Card>
  );
}

// ------------------------------------------------------------- system

type SystemInfo = {
  version: string;
  uptime: number;
  engine: EngineSnapshot;
  collector: { listening: string[]; rejected: number; queue_dropped: number };
  restart_pending: string[];
  notifications: ChannelStatus[];
  config_path: string;
};

function SystemSection({ d, edit }: SP) {
  const s = usePoll(() => api.get<SystemInfo>("/system"), 5000);
  const x = s.data;
  const e = x?.engine;
  return (
    <>
      <Card title="Durum">
        <ErrorLine error={s.error} />
        {x && e && (
          <dl className="kv">
            <dt>Sürüm</dt>
            <dd>{x.version}</dd>
            <dt>Çalışma süresi</dt>
            <dd>{duration(x.uptime)}</dd>
            <dt>Flow işleme</dt>
            <dd>
              {num(e.records_per_sec)} kayıt/sn · toplam {num(e.records_total)}
              {e.dropped_records > 0 && <span className="bad"> · {num(e.dropped_records)} düşürüldü</span>}
            </dd>
            <dt>Değerlendirme</dt>
            <dd>
              {e.eval_millis.toFixed(1)} ms/sn · {num(e.series)} seri{e.series_overflow ? <span className="bad"> · seri sınırı aşıldı ({num(e.series_overflow)})</span> : null}
            </dd>
            <dt>Kurallar</dt>
            <dd>
              {e.rules_active}/{e.rules} etkin
            </dd>
            <dt>Flow deposu</dt>
            <dd>
              {num(e.flowstore_len)}/{num(e.flowstore_cap)} kayıt · en eski {ago(e.oldest_flow)}
            </dd>
            <dt>Collector</dt>
            <dd className="mono small">{x.collector.listening.join(", ") || "dinlemiyor"}</dd>
            <dt>Yapılandırma</dt>
            <dd className="mono small wrap">{x.config_path}</dd>
          </dl>
        )}
      </Card>
      <Card>
        <Section title="Dizinler" desc="Yeniden başlatma gerektirir.">
          <TextIn label="Kural dizini" mono value={d.rules_dir} onChange={(v) => edit((c) => void (c.rules_dir = v))} />
          <TextIn label="Veri dizini" mono value={d.data_dir} onChange={(v) => edit((c) => void (c.data_dir = v))} />
        </Section>
        <Section title="Demo simülatörü" desc="Production'da kapalı olmalıdır.">
          <Toggle label="Simülatör etkin" value={d.demo.enabled} onChange={(v) => edit((c) => void (c.demo.enabled = v))} hint="Yeniden başlatma gerekir" />
          <SelectIn label="Kodlayıcı" value={d.demo.encoder} onChange={(v) => edit((c) => void (c.demo.encoder = v))} options={["netflow5", "netflow9", "ipfix", "sflow"]} />
          <TextIn label="Hedef collector" mono value={d.demo.target} onChange={(v) => edit((c) => void (c.demo.target = v))} />
          <NumIn label="Örnekleme" value={d.demo.sampling_rate} min={1} onChange={(v) => edit((c) => void (c.demo.sampling_rate = v))} />
        </Section>
      </Card>
    </>
  );
}
