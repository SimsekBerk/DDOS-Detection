# DDoS Detection (ddosd)

Flow tabanlı (NetFlow v5/v9, IPFIX, sFlow v5) bir DDoS algılama ve mitigasyon orkestrasyon platformu. Üzerinde, eşik altında kalan saldırıları yorumlayan bir **AI analist** katmanı çalışır. Operatör, veri merkezi ve kurumsal ağlar için tasarlandı.

```
Router'lar ──NetFlow/IPFIX/sFlow──► collector ─► algılama motoru ─► olaylar ─► mitigasyon (FlowSpec / RTBH / scrubbing)
                                                     │ eşik altı sinyaller            │
                                                     ▼                                ▼
                                               AI analist                      bildirimler (Slack, Teams, Telegram,
                                     (heuristic · Claude · yerel LLM)          e-posta, syslog, webhook)
                                     ─► bulgu + öneri (insan onayı)
```

**Ölçülen değerler** ([docs/BENCHMARK.md](docs/BENCHMARK.md)): 27 saldırı senaryosu × 4 telemetri modunda **108/108** doğru algılama; algılama süresi sFlow ile **3–11 sn**, NetFlow/IPFIX (10 sn timeout) ile **12–20 sn**; 48 simüle saat normal trafikte **0 yanlış olay**; tek düğümde **2M flow/sn** kayıpsız.

## Özellikler

- **Telemetri:** NetFlow v5/v9, IPFIX (options template ile örnekleme öğrenme dahil), sFlow v5 (ham paket başlığı, VLAN/MPLS/IPv6 uzantıları). Tüm portlarda format otomatik tanınır. Exporter sağlığı (kayıp tahmini, şablonsuz veri, örnekleme oranı), exporter izin listesi ve başka collector'lara flow yönlendirme.
- **Algılama motoru:** 1 sn kovalar, kayan pencere, uzun flow'ları zamana yayma, statik eşik + EWMA baseline, doğrulama koşulları (benzersiz kaynak/hedef, paket boyu), histerezis, host / prefix (carpet bombing) / nesne kapsamları, çok vektörlü olaylar, hiyerarşik korelasyon (aynı saldırı tek olay), adli kanıt.
- **52 kural, 8 profil (L3/L4):** amplifikasyon (DNS, NTP, SSDP, memcached, CLDAP, SNMP, WS-Discovery, SLP, CoAP …), TCP (SYN, SYN-ACK, ACK, RST, FIN, NULL, XMAS, PSH-ACK, bağlantı seli), UDP/QUIC, ICMP (BlackNurse dahil), fragment, GRE/ESP/alışılmadık protokoller, carpet bombing, hacimsel toplamlar, giden saldırılar ve açık yansıtıcılar → [docs/RULES.md](docs/RULES.md)
- **Mitigasyon:** kanıttan en dar FlowSpec; güvenlik bariyerleri (korunan alan, `never_mitigate`, minimum prefix, aktif kural limiti); onay kuyruğu, TTL, otomatik geri çekme; `dryrun`, `exabgp`, `webhook` sürücüleri; ExaBGP, GoBGP, Junos, IOS-XR çıktısı.
- **AI analist:** özet veri üzerinde salt okunur araçlarla çalışan ajan; "dedektör neden kaçırdı?" açıklaması, kanıtlı bulgular, tek tıkla onaya gönderilen öneriler. Sağlayıcılar: `heuristic` (LLM yok), `anthropic` (Claude API), `openai_compat` (Ollama/vLLM; veri dışarı çıkmaz) → [docs/AI-ANALYST.md](docs/AI-ANALYST.md)
- **Üretim hazırlığı:**
  - Kullanıcılar, roller (izleyici / operatör / yönetici), nesne kapsamlı müşteri hesapları, API token'ları, denetim kaydı.
  - Arayüzden yapılandırma: doğrulama, canlı uygulama, sürüm geçmişi ve geri alma, gizli alan maskeleme.
  - Bildirimler: Slack, Microsoft Teams, Telegram, e-posta, syslog (RFC 5424), HMAC imzalı webhook.
  - Prometheus `/metrics`, `/healthz`, `/readyz`, TLS, Docker ve systemd kurulumu → [docs/OPERATIONS.md](docs/OPERATIONS.md)
- **Web arayüzü** (Türkçe, koyu/açık tema, mobil uyumlu): genel bakış, saldırılar ve olay detayı (CSV ve Markdown rapor), mitigasyon onayları, AI analist, trafik gezgini ve hedef analizi, ayarlar.
- **Simülatör ve benchmark:** 27 senaryo; gerçek NetFlow/IPFIX/sFlow paketleri üretir, ağınızda saldırı trafiği üretmez. `ddos-bench` ile doğruluk, algılama süresi, yanlış alarm ve kapasite ölçümü.

## Hızlı başlangıç

```bash
# Demo: sentetik trafik + saldırı senaryoları → http://localhost:8090
go run ./cmd/ddosd -config config.demo.yaml
```

Giriş: kullanıcı `admin`. Parola ilk açılışta rastgele üretilir ve şu dosyaya yazılır:

```bash
cat data-demo/initial-admin-password.txt
```

Ardından **Simülatör** sayfasından bir senaryo başlatın (ör. DNS Amplification) ve **Saldırılar**, **Mitigasyon**, **AI analist** sayfalarını izleyin. Parolayı unutursanız servis kapalıyken `go run ./cmd/ddosd -config config.demo.yaml -reset-admin admin` çalıştırın.

Kendi ağınız için:

```bash
cp config.example.yaml config.yaml      # prefixler, profiller, never_mitigate, izin listesi
make ui build && ./bin/ddosd -config config.yaml
# veya Docker:
mkdir -p config && cp config.example.yaml config/config.yaml && sudo chown -R 10001 config
docker compose -f deploy/docker-compose.yml up -d
```

Router örnekleri [docs/ROUTER-CONFIG.md](docs/ROUTER-CONFIG.md), adım adım devreye alma [docs/TESTING.md](docs/TESTING.md), üretim işletimi [docs/OPERATIONS.md](docs/OPERATIONS.md) dosyasında.

Gereksinimler: Go 1.24 veya üzeri. UI'ı yeniden derlemek için Node 20 gerekir; derlenmiş UI `web/dist` içinde repoya dahildir.

## Dokümantasyon

| Doküman | İçerik |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Üretim ve tek düğüm mimarisi, algılama bütçesi, korelasyon, yapılandırmanın canlı uygulanması |
| [docs/RULES.md](docs/RULES.md) | Kural şeması, en iyi uygulamalar, tam kural kataloğu, ayarlama |
| [docs/AI-ANALYST.md](docs/AI-ANALYST.md) | Analist akışı, araçlar, sağlayıcılar, güvenlik |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Boyutlandırma, kurulum, kullanıcılar ve roller, yapılandırma, bildirimler, metrikler, yedekleme, sertleştirme |
| [docs/BENCHMARK.md](docs/BENCHMARK.md) | Ölçüm yöntemi, sonuçlar, GenieATM ile karşılaştırma |
| [docs/ROUTER-CONFIG.md](docs/ROUTER-CONFIG.md) | Cisco, Juniper, Huawei, MikroTik, Arista, Linux; FlowSpec/RTBH alıcı yapılandırması |
| [docs/TESTING.md](docs/TESTING.md) | Demo → uzak simülatör → gölge mod → BGP lab → canlı; otomatik testler |

## Proje yapısı

```
cmd/ddosd           daemon: collector + motor + mitigasyon + analist + bildirim + API/UI
cmd/ddos-sim        komut satırı trafik/saldırı simülatörü
cmd/ddos-bench      doğruluk, algılama süresi, yanlış alarm ve kapasite ölçümü
internal/decoder    NetFlow v5/v9, IPFIX, sFlow v5 çözücüler
internal/collector  UDP dinleyiciler, worker havuzu, izin listesi, flow yönlendirme, exporter sağlığı
internal/engine     seriler, baseline, kurallar, korelasyon, olaylar, sinyaller, kanıt
internal/rules      kural/profil şeması, derleyici, kurallar arası ilişkiler
internal/flowstore  son flow halka tamponu, top-N / kırılım / örnek sorguları
internal/mitigation FlowSpec/RTBH üretimi, bariyerler, onay, sürücüler
internal/analyst    AI analist: araçlar, prompt, anthropic/openai_compat/heuristic
internal/notify     bildirim kanalları
internal/auth       kullanıcılar, roller, oturumlar, API token'ları
internal/audit      denetim kaydı
internal/app        bileşenleri bağlar; yapılandırmayı doğrular, canlı uygular, sürümler
internal/api        REST API, metrikler, gömülü UI
internal/bench      benchmark düzeneği
internal/sim        sentetik trafik ve senaryolar (encoder'lar dahil)
rules/              YAML kural setleri ve profiller
web/                React + TypeScript arayüz (web/dist derlenmiş)
deploy/             docker-compose, ExaBGP örneği
docs/               mimari ve operasyon dokümanları
```

## API

Uç noktalar (aksi belirtilmedikçe) `/api/v1` altındadır. Nesne kapsamlı kullanıcılar yalnızca kendi nesnelerinin verisini görür. Kimlik doğrulama oturum çereziyle (`POST /auth/login`) veya `Authorization: Bearer <token>` ile yapılır. Oturumla yapılan değiştirici isteklerde `X-Requested-With: ddosd` başlığı zorunludur.

| Uç nokta | Rol | Açıklama |
|---|---|---|
| `POST /auth/login`, `/auth/logout`, `GET /auth/me`, `POST /auth/password` | herkes | oturum |
| `GET /overview`, `/timeseries`, `/signals`, `/target?ip=` | izleyici | durum, trafik geçmişi, aday sinyaller, hedef analizi |
| `GET /incidents`, `/incidents/{id}`, `/incidents/export.csv`, `/incidents/{id}/report.md` | izleyici | olaylar ve raporlar |
| `POST /flows/top`, `/flows/breakdown`, `/flows/samples` | izleyici | trafik gezgini |
| `GET /rules`, `GET /mitigations`, `GET /analyst/findings` | izleyici | kurallar, mitigasyonlar, bulgular |
| `POST /mitigations`, `POST /mitigations/{id}/approve\|reject\|withdraw\|extend` | operatör | mitigasyon |
| `POST /analyst/run`, `/analyst/incident/{id}`, `/analyst/ask`, `/analyst/findings/{id}/apply/{idx}` | operatör | AI analist |
| `GET/PUT /config`, `POST /config/validate`, `GET /config/history`, `POST /config/history/{id}/restore` | yönetici | yapılandırma |
| `PATCH /rules/{id}`, `POST /rules/reload` | yönetici | kural eşiği ve aç/kapa |
| `GET /users`, `PUT/DELETE /users/{name}`, `POST/DELETE /users/{name}/tokens` | yönetici | kullanıcılar ve token'lar |
| `GET /audit`, `GET /notifications`, `POST /notifications/test` | yönetici | denetim kaydı, bildirimler |
| `GET /metrics` (kök dizinde) | kapsamsız izleyici | Prometheus metrikleri |
| `GET /healthz`, `/readyz` (kök dizinde) | herkes | sağlık kontrolleri |

## Geliştirme

```bash
make test                 # go test ./...
make test-race            # race detector ile
make bench                # ddos-bench: doğruluk, yanlış alarm, kapasite
cd web && npm run dev     # UI geliştirme sunucusu (API'yi :8090'a proxy'ler)
make ui build             # UI + binary'ler
```
