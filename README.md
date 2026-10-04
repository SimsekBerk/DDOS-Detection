# DDoS Detection (ddosd)

Router'ların flow verisiyle (NetFlow v5/v9, IPFIX, sFlow v5) çalışan, trafiğin yolunda durmayan (out-of-path) bir **DDoS tespit ve yönlendirme orkestrasyonu** platformu. Saldırıyı tespit eder, kanıtıyla birlikte raporlar ve trafiği DDoS önleme/scrubbing ürününe yönlendirmek için BGP FlowSpec, RTBH veya webhook komutu üretir. Trafiği kendisi temizlemez. Üzerinde, eşik altında kalan anormallikleri inceleyip açıklayan bir **AI analist** katmanı çalışır.

Hedef pazar ve rakip: Genie Networks **GenieATM** (aynı out-of-path modeli); ayrıca NETSCOUT Arbor, Kentik, FastNetMon, Wanguard. Karşılaştırma: [docs/BENCHMARK.md](docs/BENCHMARK.md).

> **Bu README devir için yazıldı.** Önce [Hızlı başlangıç](#2-hızlı-başlangıç) ile demoyu çalıştırın, sonra [Mimari](#4-mimari) ve [Kod turu](#5-kod-turu) bölümlerini okuyun. Açık işler ve bilinen sınırlamalar [§13](#13-bilinen-sınırlamalar-ve-yol-haritası) ve [§14](#14-devir-notları)'te.

## İçindekiler

1. [Kapsam: ne yapar, ne yapmaz](#1-kapsam-ne-yapar-ne-yapmaz)
2. [Hızlı başlangıç](#2-hızlı-başlangıç)
3. [Çalıştırma modları](#3-çalıştırma-modları)
4. [Mimari](#4-mimari)
5. [Kod turu](#5-kod-turu)
6. [Temel tasarım kararları](#6-temel-tasarım-kararları)
7. [Yapılandırma](#7-yapılandırma)
8. [Kurallar, mitigasyon ve AI analist](#8-kurallar-mitigasyon-ve-ai-analist)
9. [Kimlik, yetki ve güvenlik](#9-kimlik-yetki-ve-güvenlik)
10. [API ve gözlemlenebilirlik](#10-api-ve-gözlemlenebilirlik)
11. [Test ve ölçüm](#11-test-ve-ölçüm)
12. [Geliştirme](#12-geliştirme)
13. [Bilinen sınırlamalar ve yol haritası](#13-bilinen-sınırlamalar-ve-yol-haritası)
14. [Devir notları](#14-devir-notları)
15. [Doküman haritası](#15-doküman-haritası)

---

## 1. Kapsam: ne yapar, ne yapmaz

```
Router'lar ──NetFlow/IPFIX/sFlow──► collector ─► algılama motoru ─► olay ─► mitigasyon orkestratörü ─► FlowSpec / RTBH / webhook
                                          │              │                         │                      → scrubbing / DDoS önleme ürünü
                                          │              │ eşik altı sinyaller      └► bildirimler (Slack, Teams, Telegram, e-posta, syslog, webhook)
                                          │              ▼
                                          │        AI analist (kural tabanlı · Claude API · yerel LLM) ─► bulgu + öneri (insan onayı)
                                          └► flow deposu (son N saniye, adli inceleme)
```

**Yapar**

- L3/L4 DDoS saldırılarını tespit eder: amplifikasyon (DNS, NTP, SSDP, memcached, CLDAP, SNMP, WS-Discovery, CoAP …), TCP (SYN, SYN-ACK, ACK, RST, FIN, NULL, XMAS, PSH-ACK, bağlantı seli), UDP/QUIC, ICMP (BlackNurse dahil), fragment, GRE/IP-in-IP/alışılmadık protokoller, carpet bombing (bir /24'e yayılmış saldırı), hacimsel toplamlar ve **müşterilerden çıkan (outbound)** saldırılar. 52 kural, 8 profil.
- Her olay için kanıt toplar: en çok trafik gönderen kaynaklar ve portlar, paket boyu dağılımı, TCP bayrakları, örnek flow'lar.
- Saldırıya özel en dar FlowSpec kuralını veya RTBH duyurusunu üretir. Bunları onay kuyruğundan veya otomatik olarak router'a ya da webhook ile scrubbing ürününe gönderir.
- Eşik altı kalan ama normalden sapan trafiği AI analiste aday sinyal olarak verir. Analist bu sinyalleri inceler, açıklar ve öneri üretir.
- Çok kullanıcılı ve çok kiracılı çalışır: roller, müşteriye özel nesne kapsamı, API token'ları, denetim kaydı. Ayarlar arayüzden sürümlü olarak yönetilir.

**Yapmaz**

- Trafiği kendisi temizlemez (scrubbing yok). Tespit eder ve yönlendirme komutu üretir. GenieATM de aynı modeldedir.
- L7 saldırılarını (HTTP flood, Slowloris, DNS water torture) flow verisiyle güvenilir şekilde ayıramaz. Bunlar WAF veya DNS korumasının işidir.
- Ham flow'u uzun süre saklamaz. Bellekte son birkaç on saniyelik flow (adli inceleme) ve 24 saatlik trafik geçmişi tutar.
- Şu an tek düğümde çalışır; kümeleme ve yüksek erişilebilirlik yok ([§13](#13-bilinen-sınırlamalar-ve-yol-haritası)).

### Mevcut durum (ölçülen)

Ayrıntı ve yöntem: [docs/BENCHMARK.md](docs/BENCHMARK.md).

| Ölçüt | Sonuç |
|---|---|
| Algılama doğruluğu (27 senaryo × 4 telemetri modu) | **108/108**, yanlış hedef 0 |
| Algılama süresi | sFlow **3–11 sn**; NetFlow/IPFIX (active timeout 10 sn) **12–20 sn**; NetFlow 60 sn timeout'ta 18–64 sn |
| Normal trafikte yanlış olay (48 simüle saat, gerçekçi TCP bayraklarıyla) | **0** |
| Kapasite, tek exporter, UDP uçtan uca | **2M kayıt/sn kayıpsız** |
| Operatör ölçeği (2.000 prefix, 100 bin aktif host, 1:1000 örnekleme) | Tepe 330 bin kayıt/sn'de motor doluluğu %12; +700 Mpps saldırıda %41; tek düğüm sınırı ~1,4–2,5M kayıt/sn |
| Gerçek trafik doğrulaması | 200 bilinen ping → ddosd'de birebir 200 paket / 205.600 bayt |
| Kod | Go ~17.600 satır, TypeScript ~4.500 satır, 54 test/fuzz/benchmark fonksiyonu |

---

## 2. Hızlı başlangıç

**Gereksinimler:** Go **1.24.4** veya üzeri (`go.mod` 1.24.4'e sabit; bkz. [§12](#12-geliştirme)). UI'ı yeniden derlemek için Node 20. Derlenmiş UI `web/dist` içinde repoda olduğu için sadece Go ile de çalışır.

```bash
git clone https://github.com/SimsekBerk/DDOS-Detection.git
cd DDOS-Detection
go run ./cmd/ddosd -config config.demo.yaml      # → http://localhost:8090
```

- **Giriş:** kullanıcı `admin`. Parola ilk açılışta rastgele üretilir ve `data-demo/initial-admin-password.txt` dosyasına yazılır:
  ```bash
  cat data-demo/initial-admin-password.txt
  ```
- **Parola unutulursa** servisi durdurup şunu çalıştırın:
  ```bash
  go run ./cmd/ddosd -config config.demo.yaml -reset-admin admin
  ```
- **Demoyu deneyin:**
  1. **Simülatör** sayfasından bir senaryo başlatın (ör. DNS Amplification).
  2. **Saldırılar**, **Mitigasyon** ve **AI analist** sayfalarını izleyin.
  3. **Ayarlar** bölümünü gezin.
- Demo tamamen **sentetik** trafikle çalışır. Simülatör saldırı paketi üretmez, yalnızca saldırıyı anlatan flow kayıtlarını `127.0.0.1:2055`'e gönderir; ağa yük bindirmez.

Doğrulama (5 dakika):

```bash
make test         # tüm birim ve entegrasyon testleri
make bench        # 108 senaryo + yanlış alarm + kapasite (birkaç dakika)
```

---

## 3. Çalıştırma modları

| Mod | Config | Trafik kaynağı | Arayüz | Ne için |
|---|---|---|---|---|
| **Demo** | `config.demo.yaml` | Dahili simülatör (sentetik) | `:8090` | Ürünü tanıtmak, geliştirme |
| **Preprod (bu makine)** | `config.preprod.example.yaml` → `config.preprod.yaml` | `ddos-probe` ile bu makinenin gerçek trafiği | `127.0.0.1:8092` | Gerçek veriyle uçtan uca doğrulama |
| **Üretim** | `config.example.yaml` → `config.yaml` | Router'ların NetFlow/IPFIX/sFlow export'u | `:8080` (TLS önerilir) | Gerçek ağ |

**Preprod.** Ayrıntı için [docs/TESTING.md](docs/TESTING.md) §1b.

```bash
cp config.preprod.example.yaml config.preprod.yaml          # alt ağı ve ağ geçidini girin
make build
./bin/ddosd -config config.preprod.yaml                      # parola: data-preprod/initial-admin-password.txt
./bin/ddos-probe -i en0 -collector 127.0.0.1:9995            # ayrı terminalde
```

- `ddos-probe` şu an yalnızca macOS'ta çalışır. `/dev/bpf*` okuma yetkisi gerekir: Wireshark kuruluysa kullanıcı `access_bpf` grubundadır, değilse `sudo` gerekir.
- Wi-Fi ve switch'li ağlarda bir makine yalnızca kendi trafiğini ve broadcast/multicast'i görür. Tüm ağı görmek için ağ geçidinin flow export'u bu makineye yönlendirilmelidir.

**Üretim.** Ayrıntı için [docs/OPERATIONS.md](docs/OPERATIONS.md).

```bash
cp config.example.yaml config.yaml          # prefix'ler, profiller, never_mitigate, collector.allow
make ui build && ./bin/ddosd -config config.yaml
```

Docker ile:

```bash
mkdir -p config && cp config.example.yaml config/config.yaml && sudo chown -R 10001 config
docker compose -f deploy/docker-compose.yml up -d
```

Router yapılandırma örnekleri (Cisco, Juniper, Huawei, MikroTik, Arista, Linux): [docs/ROUTER-CONFIG.md](docs/ROUTER-CONFIG.md). Sunucu boyutlandırma, örnekleme önerileri ve ayarlar: [docs/OPERATIONS.md](docs/OPERATIONS.md) §1.

**Binary'ler** (`make build` → `bin/`):

| Komut | Görevi | Önemli bayraklar |
|---|---|---|
| `ddosd` | Daemon: collector + motor + mitigasyon + analist + bildirim + API/UI | `-config`, `-reset-admin <kullanıcı>`, `-ui-dir` (UI'ı diskten sun), `-log-json`, `-debug`, `-version` |
| `ddos-sim` | Simülatörün komut satırı sürümü; başka makineden bir collector'a senaryo gönderir | `-list`, `-collector`, `-scenario`, `-target`, `-prefixes`, `-encoder`, `-sampling`, `-duration` |
| `ddos-probe` | Pasif paket sensörü (macOS): arayüz trafiğini IPFIX flow'a çevirir | `-i`, `-collector`, `-active`, `-inactive`, `-promisc` (yalnızca yetkili mirror port) |
| `ddos-bench` | Doğruluk, algılama süresi, yanlış alarm, kapasite, boyutlandırma | `detect`, `baseline`, `throughput`, `sizing`, `all` |

---

## 4. Mimari

Tek bir Go süreci. Bileşenler `internal/app` içinde birbirine bağlanır. Çoklu PoP üretim mimarisi (Kafka, ClickHouse, shard'lı motor) hedef olarak [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)'de tanımlıdır; bu repo onun tek düğüm uygulamasıdır.

```
UDP :2055/:4739/:6343 ─► collector ──────────────────► engine ──────────────────────────► incidents ─► mitigation ─► driver (dryrun│exabgp│webhook)
                          │ izin listesi                │ ingest: flow deposu + toplamlar    │           │ bariyerler, onay, TTL
                          │ exporter başına worker      │   + parçalı seriler (paralel)      │           └► notify
                          │ decode (v5/v9/IPFIX/sFlow)  │ evaluate (her sn): A paralel,      │
                          │ sınıflandırma (kural bitleri)│   B sıralı karar + korelasyon      └► analyst (aday sinyaller, araçlar)
                          └ flow yönlendirme (replika)  └ signals (eşik altı sapmalar)
                                                                   ▲
api (REST + /metrics + gömülü React UI) ── auth (oturum, token, RBAC, kiracı) ── audit ── app (config doğrula/uygula/sürümle)
```

Kaydın yolculuğu:

1. **Collector** datagram'ı alır ve izin listesini kontrol eder. Datagram'ı exporter adresine göre bir worker'a verir; aynı router'ın paketleri sıra ve şablon tutarlılığı için hep aynı worker'a gider. İsteniyorsa datagram başka collector'lara kopyalanır.
2. **Worker** datagram'ı çözer ve kayıtları sınıflandırır. Kayıt hangi korunan nesneye ait, yönü ne (inbound/outbound) ve hangi kurallara uyuyor; kural uyumları 128 bitlik bir maske olarak kayda yazılır. Kayıtlar 1.024'lük partiler halinde motora gider.
3. **Motor (ingest)** partileri birleştirir (16 bine kadar). Kayıtları flow deposuna, trafik toplamlarına ve (kural, hedef) serilerine ekler. Seriler parçalara bölündüğü için bu adım paralel çalışır.
4. **Motor (evaluate, her saniye)**
   - Her seri için pencere hızı, statik eşik, baseline ve doğrulama koşulları hesaplanır (paralel).
   - Ardından sırayla karar verilir: vektör başlat/bitir, sinyal üret, boşta kalan seriyi sil.
   - Genel ve geniş kapsamlı vektörler, özel vektörler tarafından açıklanmıyorsa açılır (hiyerarşik korelasyon).
5. **Olay** hedef başına tutulur; aynı hedefe gelen vektörler tek olayda toplanır. Olay açılınca kanıt toplanır, mitigasyon talebi ve bildirim oluşur.
6. **Mitigasyon** talebi güvenlik bariyerlerinden geçer, `manual` modda onay bekler, sürücüye gider ve TTL dolunca ya da olay bitince geri çekilir.

---

## 5. Kod turu

Okuma sırası önerisi; parantez içinde başlangıç noktaları.

| Paket | Sorumluluk | Başlangıç noktası |
|---|---|---|
| `cmd/ddosd` | Bayraklar, `app` + `api` başlatma, parola kurtarma | `main.go` |
| `internal/app` | Bileşenleri kurar; config'i doğrular, **canlı uygular**, sürümler, geri yükler; olay → mitigasyon/bildirim kancaları | `app.go`: `New`, `Apply`, `persist`, `Restore` |
| `internal/config` | Şema, varsayılanlar, doğrulama, gizli alan maskeleme, yeniden başlatma gerektiren alanlar | `config.go`: `Normalize`, `validate`, `Masked`, `RestoreSecrets`, `RestartRequired` |
| `internal/collector` | UDP dinleyiciler, worker havuzu, izin listesi, yönlendirme, exporter istatistikleri | `collector.go`: `Run`, `readLoop`, `worker`, `handle` |
| `internal/decoder` | NetFlow v5/v9, IPFIX (options template ile örnekleme), sFlow v5 (ham başlık) | `decoder.go`: `Decode`; `template.go`; `sflow.go`: `ParseEthernet` |
| `internal/rules` | Kural/profil şeması, derleme, eşleşme, kurallar arası alt küme/ayrıklık ilişkisi | `rules.go`: `Load`, `compile`, `Matches`, `Within`, `Disjoint` |
| `internal/engine` | Algılamanın kalbi | `engine.go`: `Classify`, `ingest`, `ingestShard`, `evaluate`, `evalShard`, `resolvePending`, `coverage`, `startVector`, `TargetState`; `shards.go` (parçalı seri tablosu); `series.go` (saniyelik halka, baseline); `objects.go` (prefix LPM); `incidents.go`; `signals.go`; `totals.go` (trafik geçmişi); `reconfig.go` |
| `internal/flowstore` | Sıkıştırılmış, işaretçisiz flow halkası; top-N, kırılım, örnek sorguları | `store.go`: `Append`, `scan`; `query.go`: `TopN`, `Breakdown`, `Samples` |
| `internal/mitigation` | Kanıttan FlowSpec/RTBH üretimi, bariyerler, onay kuyruğu, TTL, sürücüler, vendor çıktıları | `mitigation.go`: `VectorStarted`, `guard`, `submit`; `drivers.go`; `render.go` |
| `internal/analyst` | Aday sinyal kapısı, salt okunur araçlar, sağlayıcılar (heuristic, Claude, OpenAI uyumlu yerel LLM) | `analyst.go`: `Loop`, `Start`, `run`; `tools.go`; `prompt.go` |
| `internal/notify` | Bildirim kanalları, filtreleme, HMAC | `notify.go` |
| `internal/auth`, `internal/audit` | Kullanıcılar (bcrypt), oturum, token, roller, kiracı kapsamı; append-only denetim kaydı | `auth.go`, `audit.go` |
| `internal/api` | REST rotaları ve erişim seviyeleri, izleme/aksiyon/yönetim uçları, dışa aktarma, Prometheus | `api.go` (rota tablosu), `monitor.go`, `actions.go`, `admin.go`, `export.go`, `metrics.go` |
| `internal/sim` | Senaryolar ve NetFlow/IPFIX/sFlow kodlayıcılar | `sim.go`: `Scenarios`, `baselineSpecs`; `encode.go` |
| `internal/bench` | Simüle saatli ölçüm düzeneği, router flow önbelleği taklidi, boyutlandırma | `bench.go`, `throughput.go`, `sizing.go` |
| `internal/probe` | BPF ile paket yakalama, flow önbelleği, IPFIX export | `probe.go`, `cache.go`, `capture_darwin.go` |
| `web/` | React 18 + TypeScript + Vite arayüz; `web/dist` binary'ye gömülür | `src/App.tsx` (rotalar), `src/api.ts` (tipler), `src/pages/*`, `src/components/*` |
| `rules/` | YAML kural setleri ve profiller | `00-profiles.yaml` … `60-outbound.yaml` |

---

## 6. Temel tasarım kararları

Devralan kişinin bilmesi gereken, kodda görünmeyen gerekçeler:

1. **Tespit + yönlendirme, temizleme değil.** Ürün bir scrubber değildir. "Mitigasyon", trafiği scrubbing ürününe yönlendirmek veya router'da en dar FlowSpec kuralını kurmak için komut üretmektir. RTBH son çaredir ve hep onay ister.
2. **LLM hızlı yolda değildir.** Algılama ve mitigasyon kararları deterministik motorda verilir. AI analist yalnızca özet veriye salt okunur araçlarla bakar ve öneri üretir; öneriler insan onayından geçer. Sayıları LLM üretmez, araçlar üretir.
3. **Flow bayrak semantiği.** NetFlow/IPFIX kayıtlarında TCP bayrakları bağlantı boyunca birleşir (OR). Normal bir bağlantı `SYN|ACK|PSH|FIN` görünür. Bayrak kuralları bu yüzden saldırının *taşımadığı* bayrakları da belirtir.
   - Gerçek trafik testinde bu konu 259 sahte "XMAS" olayına yol açıyordu.
   - `TestNormalConnectionFlagsAreNotAttacks` testi bunu korur. Ayrıntı: [docs/RULES.md](docs/RULES.md).
4. **Hiyerarşik korelasyon.** `generic: true` kurallar ("hosta tüm UDP" gibi) ve prefix/nesne kapsamlı kurallar, aktif özel vektörler trafiğin ≥%70'ini açıklıyorsa raporlanmaz.
   - Bir vektör ancak eşleşme kümesi diğerinin alt kümesiyse onu açıklayabilir (`rules.Set.Within`).
   - Ayrık vektörlerin hızları toplanır (`Disjoint`).
   - Böylece aynı /24'e gelen farklı türdeki eşzamanlı saldırılar birbirini bastırmaz.
5. **Örnekleme farkındalığı.** Tüm eşikler, örnekleme oranıyla ölçeklenmiş tahmini gerçek trafik üzerinden değerlendirilir. Az örnekle karar verilmez (`min_samples`).
6. **Histerezis ve sinyal gürültüsü.**
   - Başlangıç: `sustain` süresi boyunca eşik aşılmalı ve pencerede en az 2 aktif saniye olmalı.
   - Bitiş: `hold_down` süresince eşiğin %70'inin altında kalınmalı.
   - Aday sinyaller kalıcılık ve "yükselen trafik" şartı arar. Servis açıldıktan sonraki öğrenme döneminde daha yüksek bir eşik kullanılır.
7. **Ölçek için veri yapısı.**
   - Seriler carpet prefix'e göre parçalıdır; ingest ve değerlendirme kilitsiz paraleldir, paylaşılan durum değişiklikleri sırayla uygulanır.
   - Flow deposu işaretçisizdir, çöp toplayıcı onu taramaz.
   - Prefix eşleşmesi prefix sayısından bağımsızdır.
   - Açıklama metinleri yalnızca gerektiğinde üretilir.
   - Bu noktalara dokunurken `ddos-bench sizing` ile ölçün ([§11](#11-test-ve-ölçüm)).
8. **Config canlı uygulanır.** Arayüzden yapılan değişiklik önce diske yazılır, sonra bileşenlere uygulanır, her kayıt bir sürümdür. Yalnızca dinleme adresleri, worker/kuyruk boyları, TLS, dizinler, flow deposu boyu ve demo ayarı yeniden başlatma gerektirir.

---

## 7. Yapılandırma

- **Şablonlar:** `config.example.yaml` (üretim; tüm alanlar açıklamalı), `config.demo.yaml`, `config.preprod.example.yaml`.
- **Şema ve varsayılanlar:** `internal/config/config.go` (`applyDefaults`, `validate`).
- **Arayüzden yönetim:** Ayarlar ekranında korunan nesneler, kurallar, telemetri, motor, mitigasyon, bildirimler, AI analist, web/API, kullanıcılar, denetim kaydı, değişiklik geçmişi ve sistem bölümleri var.
  - Değişiklikler tek taslakta toplanır; **Doğrula** ve **Kaydet ve uygula** ile uygulanır.
  - Her kayıt `data_dir/config-history/` altında bir sürüm oluşturur (son 100) ve geri yüklenebilir.
  - Arayüzden kaydedilen YAML yeniden yazılır, dosyadaki yorumlar kaybolur. Önceki hali `*-onceki.yaml` olarak saklanır.
- **Gizli alanlar** (parolalar, token'lar, HMAC anahtarları) API ve arayüzde `********` döner; değiştirilmezse kayıtlı değer korunur.
- **Kural eşiği ve aç/kapa** değişiklikleri kural dosyalarından ayrı, `data_dir/rule_overrides.json` dosyasında tutulur.
- **Ölçek ayarları** ([docs/OPERATIONS.md](docs/OPERATIONS.md) §1):
  - `engine.max_series` ≈ aktif host × 8. Varsayılan 250 bin küçük/orta ağlar içindir.
  - `engine.recent_flows` ≈ tepe kayıt/sn × 30–60.
  - `collector.workers` ≥ router sayısı.
- **Ortam değişkenleri:** `ANTHROPIC_API_KEY` (Claude sağlayıcısı); yerel LLM için anahtarın okunacağı değişkenin adı `analyst.openai_compat.api_key_env` ile verilir.

---

## 8. Kurallar, mitigasyon ve AI analist

**Kurallar** ([docs/RULES.md](docs/RULES.md))

- 52 kural ve 8 profil var: `default`, `residential`, `datacenter`, `web`, `dns_server`, `gaming`, `vpn_gateway`, `infrastructure`.
- Her kuralda şunlar tanımlıdır:
  - eşleşme (protokol, port, bayrak, paket boyu, fragment),
  - statik eşik (pps/bps/fps) ve isteğe bağlı baseline,
  - doğrulama koşulları (benzersiz kaynak/hedef, paket boyu),
  - `sustain` / `hold_down`,
  - önerilen aksiyon ve gerekçe/yanlış alarm notları.
- Profiller eşikleri nesne tipine göre ölçekler veya kural kapatır.
- Kural dosyası değişince servis durmadan "Dosyalardan yeniden yükle" yapılabilir.

**Mitigasyon** (`internal/mitigation`)

- **Modlar:** `manual` (onay kuyruğu), `auto` (bariyerlerden geçen kural önerileri otomatik uygulanır; RTBH ve AI önerileri yine onay ister), `off`.
- **Sürücüler:** `dryrun`, `exabgp` (FlowSpec/RTBH komut dosyası), `webhook` (HMAC imzalı JSON; scrubbing/SOAR entegrasyonu).
- **Bariyerler:** hedef korunan bir nesnede olmalı; `never_mitigate` listesi; en dar prefix (/24, /48); aktif kural sınırı; mükerrer kontrolü; TTL.
- **Vendor çıktıları:** ExaBGP, GoBGP, Junos, IOS-XR önizlemesi.

**AI analist** ([docs/AI-ANALYST.md](docs/AI-ANALYST.md))

- **Sağlayıcılar:**
  - `heuristic`: LLM yok, şablon tabanlı; varsayılan.
  - `anthropic`: Claude API, model `claude-opus-5-5`, adaptive thinking.
  - `openai_compat`: Ollama/vLLM gibi yerel modeller; veri ağdan çıkmaz.
- **Görevler:** bekleyen sinyalleri analiz etmek, olay raporu yazmak, serbest soru cevaplamak.
- **Çıktı:** önem, güven, hipotez, "dedektör neden kaçırdı", kanıt ve öneriler (eşik değişikliği, FlowSpec/RTBH/scrub talebi).
- Araçlar salt okunurdur. Analistin tek yan etkisi bulgu kaydetmektir.

---

## 9. Kimlik, yetki ve güvenlik

- **Kimlik doğrulama:**
  - Kullanıcı/parola (bcrypt, en az 10 karakter) ile HttpOnly + SameSite=Strict oturum çerezi; varsayılan oturum süresi 12 saat.
  - Otomasyon için `Authorization: Bearer <token>`. Token yalnızca bir kez gösterilir, sunucuda SHA-256 özeti saklanır.
- **Roller:** `viewer` (izler), `operator` (mitigasyon onaylar, analiz çalıştırır, simülatör), `admin` (ayarlar, kurallar, kullanıcılar). Son yönetici silinemez veya yetkisi düşürülemez.
- **Kiracı kapsamı:** Kullanıcıya korunan nesne atanırsa yalnızca o nesnelerin verisini görür. Altyapı uçları (exporter'lar, simülatör, sistem, `/metrics`) kapsamlı kullanıcılara kapalıdır.
- **Diğer korumalar:**
  - Oturumla yapılan değiştirici isteklerde `X-Requested-With: ddosd` başlığı zorunludur (CSRF koruması).
  - Bir istemciden 10 hatalı girişten sonra o istemci 10 dakika engellenir.
  - Arayüz Content-Security-Policy başlığıyla sunulur.
  - TLS için `api.tls_cert` / `api.tls_key` kullanılır.
- **Denetim kaydı:** Girişler ve tüm değiştirici işlemler `data_dir/audit.jsonl` dosyasına append-only yazılır ve Ayarlar → Denetim kaydı ekranında görünür.
- **Collector:** `collector.allow` ile yalnızca kendi router'larınızı kabul edin. Exporter (4.096) ve exporter başına şablon (1.024) sınırları sahte kaynaklı flow enjeksiyonuna karşı bellek korumasıdır.
- Sertleştirme kontrol listesi: [docs/OPERATIONS.md](docs/OPERATIONS.md) §9.

---

## 10. API ve gözlemlenebilirlik

Uç noktalar (aksi belirtilmedikçe) `/api/v1` altındadır. Rota tablosu `internal/api/api.go` dosyasındadır.

| Uç nokta | Rol | Açıklama |
|---|---|---|
| `POST /auth/login`, `/auth/logout`, `GET /auth/me`, `POST /auth/password` | herkes | oturum |
| `GET /overview`, `/timeseries`, `/signals`, `/series/top`, `/target?ip=` | izleyici | durum, trafik geçmişi, aday sinyaller, eşiğe en yakın seriler, hedef analizi |
| `GET /incidents`, `/incidents/{id}`, `/incidents/export.csv`, `/incidents/{id}/report.md` | izleyici | olaylar, kanıt, CSV ve Markdown rapor |
| `POST /flows/top`, `/flows/breakdown`, `/flows/samples` | izleyici | trafik gezgini |
| `GET /rules`, `GET /mitigations`, `GET /analyst/status`, `/analyst/findings` | izleyici | kurallar, mitigasyonlar, bulgular |
| `POST /mitigations`, `POST /mitigations/{id}/approve\|reject\|withdraw\|extend` | operatör | mitigasyon |
| `POST /analyst/run`, `/analyst/incident/{id}`, `/analyst/ask`, `/analyst/findings/{id}/apply/{idx}` | operatör | AI analist |
| `GET /sim`, `POST /sim/start\|stop\|baseline` | operatör | demo simülatörü |
| `GET/PUT /config`, `POST /config/validate`, `GET /config/history[/{id}]`, `POST /config/history/{id}/restore` | yönetici | yapılandırma |
| `PATCH /rules/{id}`, `POST /rules/reload` | yönetici | kural eşiği, aç/kapa, yeniden yükleme |
| `GET /users`, `PUT/DELETE /users/{name}`, `POST/DELETE /users/{name}/tokens[/{id}]` | yönetici | kullanıcılar ve token'lar |
| `GET /audit`, `GET /notifications`, `POST /notifications/test` | yönetici | denetim kaydı, bildirim durumu ve testi |
| `GET /metrics` (kök) | kapsamsız izleyici | Prometheus |
| `GET /healthz`, `/readyz` (kök) | herkes | sağlık kontrolleri |

- **Metrikler** (`ddosd_*`): flow hızı, kuyruk/motor kayıpları, değerlendirme süresi, seri sayısı ve taşma, exporter sağlığı, nesne trafiği, aktif olay/sinyal/mitigasyon, bildirim teslimi.
- Önerilen Prometheus alarmları: [docs/OPERATIONS.md](docs/OPERATIONS.md) §7.

---

## 11. Test ve ölçüm

```bash
make test        # go test ./...
make test-race   # go test -race -short ./...
make fuzz        # decoder fuzz, 60 sn
make bench       # ddos-bench all -json bench-results.json
cd web && npm run build    # TypeScript tip kontrolü + üretim derlemesi
```

**Test kapsamı.** Paket bazında döküm: [docs/TESTING.md](docs/TESTING.md).

- **decoder:** round-trip ve fuzz testleri.
- **rules:** eşleşmeler, profiller, kurallar arası ilişkiler, normal bağlantı bayrakları.
- **engine:** algılama ve bitiş, carpet, eşzamanlı carpet, sinyaller, paralel değerlendirmenin seri yolla eşdeğerliği, LPM'in eski yöntemle eşdeğerliği.
- **collector:** UDP alımı, yönlendirme, izin listesi.
- **flowstore:** sıkıştırma ve ön elemenin eşdeğerliği.
- **auth, audit, notify, config, app, mitigation, analyst:** ilgili mantığın birim testleri.
- **api:** RBAC, CSRF, kiracı kapsamı, config uygulama ve geri yükleme, yeniden başlatma uyarısı, metrikler, bildirim testi.
- **bench:** senaryo regresyonu ve yanlış alarm.

**Ölçüm (`ddos-bench`).** Senaryolar gerçek decoder ve motordan geçer. Saat simüle edilir ve router flow önbelleğinin timeout davranışı taklit edilir; bu yüzden 2 saatlik bir yanlış alarm testi birkaç saniye sürer.

```bash
go run ./cmd/ddos-bench detect                                   # 27 senaryo × 4 telemetri
go run ./cmd/ddos-bench baseline -baseline-minutes 120 -phases 6 # 48 simüle saat yanlış alarm
go run ./cmd/ddos-bench throughput                               # decode, motor, UDP uçtan uca
go run ./cmd/ddos-bench sizing -network-pps 330e6 -sampling 1000 -prefixes 2000 -hosts 100000 -rate 330000 [-attack-pps 300e6]
```

Bir değişiklikten sonra beklenen asgari sonuçlar şunlardır; altına düşmesi regresyondur:

- `detect`: 108/108.
- `baseline`: 24 koşuda 0 olay.
- `sizing`: tepe senaryoda motor doluluğu %100'ün çok altında.

---

## 12. Geliştirme

- **Go sürümü:** `go.mod` `go 1.24.4`'e, `golang.org/x/crypto` v0.40.0'a sabittir. Yeni bağımlılık eklerken `go get` Go direktifini yükseltebilir; `go.mod`'u kontrol edin ve gerekiyorsa uyumlu bir sürüm seçin.
- **Doğrudan bağımlılıklar:** `anthropic-sdk-go` (Claude), `yaml.v3`, `x/crypto` (bcrypt). Paket yakalama Go standart kütüphanesindeki BPF desteğiyle yapılır; cgo/libpcap yok.
- **UI:**
  - `cd web && npm ci && npm run dev` ile Vite geliştirme sunucusu açılır ve `/api`'yi `localhost:8090`'a yönlendirir (`DDOSD_API` ile değiştirilebilir).
  - Üretim derlemesi `web/dist`'e yazılır ve **repoya commit edilir**; binary bu dizini gömer. UI değişikliğinden sonra `npm run build` çalıştırıp `web/dist`'i de commit edin.
  - Hızlı deneme için derlemeden `ddosd -ui-dir web/dist` kullanılabilir.
- **Dil:** Arayüz metinleri, dokümanlar ve log dışı kullanıcı mesajları Türkçe; kod, kod yorumları ve log mesajları İngilizce.
- **Commit öncesi:**
  ```bash
  gofmt -l cmd internal   # boş olmalı
  go vet ./...
  make test-race
  cd web && npm run build
  ```
  Algılama veya performansa dokunduysanız `ddos-bench detect`, `baseline` ve `sizing` de çalıştırın.
- **Docker:** `Dockerfile` çok aşamalıdır (Node 20 ile UI, Go 1.24 ile binary'ler, alpine üzerinde root olmayan kullanıcı, uid 10001). `deploy/docker-compose.yml` yapılandırma dizinini yazılabilir bağlar, ExaBGP isteğe bağlı `bgp` profilindedir.

---

## 13. Bilinen sınırlamalar ve yol haritası

| Konu | Durum | Öneri / sıradaki adım |
|---|---|---|
| Tek düğüm, yüksek erişilebilirlik yok | Tek süreç | Kısa vadede 2 sunucu (router'lar ikisine export eder). Uzun vadede Kafka + ClickHouse ile shard'lı collector/motor ([docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) §2) |
| Ağ bağlamı | BGP/BMP, SNMP/gNMI yok | GenieATM ile en büyük fark. ASN, arayüz ve route anomalileri için öncelik 1 |
| Baseline | EWMA | Haftanın saatine göre mevsimsel profil (168 dilim) |
| Scrubber entegrasyonu | Genel HMAC'li webhook | A10 TPS, Radware DefensePro, Huawei AntiDDoS için hazır adaptörler. Ana aksiyonu "scrubbing'e yönlendir" olarak öne çıkarmak |
| Bildirim | SNMP trap yok | Eklenmeli |
| Kimlik | Yerel kullanıcılar + token | OIDC/SAML |
| Uzun dönem veri | Bellekte son N sn flow + 24 sa trafik geçmişi | Flow arşivi ve raporlama (ClickHouse) |
| `ddos-probe` | Yalnızca macOS | Linux için AF_PACKET; o zamana kadar Linux'ta softflowd/pmacct |
| Config arayüzü | YAML yorumları kaybolur | Yorum korumalı YAML yazımı |
| Docker | İmaj bu geliştirme ortamında derlenip denenmedi (Docker servisi yoktu) | İlk iş olarak `docker compose up` ile doğrulanmalı |
| Ölçümler | Sentetik trafik, dizüstü bilgisayar (Apple M3 Pro, 11 çekirdek) | Gölge modda gerçek ağda ve hedef sunucuda doğrulanmalı. GenieATM ile paralel karşılaştırma yöntemi: [docs/BENCHMARK.md](docs/BENCHMARK.md) §5 |

---

## 14. Devir notları

**Açık işler**

1. **Hedef ağ için boyutlandırmayı kesinleştirmek.** Hedef ağ: 9 router, 2,8 Tbps / 330 Mpps tepe. Kesinleştirmek için şunlar gerekli:
   - GenieATM panelindeki "Flows (fps)" tepe değeri,
   - router'ların export protokolü ve örnekleme oranı,
   - korunan prefix/müşteri sayısı.

   Mevcut öneri: 16 çekirdek, 32 GB RAM, 10 GbE, iki sunucu ([docs/OPERATIONS.md](docs/OPERATIONS.md) §1).
2. **Preprod'u tüm ağa açmak.** Preprod ağında ağ geçidinin flow export'unu ddosd'ye yönlendirmek gerekiyor (ağ yöneticisi yetkisi). `config.preprod.example.yaml` ağ geçidinden gelen flow'u kabul edecek şekilde hazır.
3. **GenieATM ile sahada karşılaştırma.** İki ürün aynı flow'larla en az 2 hafta paralel çalıştırılmalı ([docs/BENCHMARK.md](docs/BENCHMARK.md) §5).

**Çalışma ortamı ve sık karşılaşılanlar**

- **Yerel durum dosyaları repoda yok:** `data-demo/`, `data-preprod/`, `config.yaml`, `config.preprod.yaml`, `config/` ve `bin/` `.gitignore`'dadır. Bu dizinlerde kullanıcı hesapları ve parola özetleri bulunur; paylaşmayın.
- **Parola:** İlk yönetici parolası `<data_dir>/initial-admin-password.txt` dosyasındadır. Kaybedilirse `ddosd -reset-admin admin` kullanın.
- **Port çakışması:** Demo 8090, preprod 8092/9995, üretim 8080 kullanır. Aynı makinede birden fazlasını çalıştırırken collector portlarının (2055/4739/6343) çakışmamasına dikkat edin.
- **Seri sınırı:** Büyük ağlarda `engine.max_series` varsayılanı (250 bin) yetmez. Dolduğunda yeni host serileri açılmaz; `ddosd_engine_series_overflow_total` metriğini izleyin.
- **Örnekleme:** 100G+ arayüzlerde sFlow 1:2048–1:8192, NetFlow/IPFIX 1:1000–1:2000 ve active timeout 10 sn önerilir. Varsayılan 60 sn active timeout algılamayı 60 sn'ye kadar geciktirir.
- **Simülatör:** Yalnızca flow kaydı üretir, ağa saldırı trafiği göndermez. Üretimdeki bir collector'a gerçek müşteri IP'si hedefli senaryo göndermeyin; `auto` mod ve `exabgp` sürücüsüyle gerçek bir duyuru yapılabilir.

---

## 15. Doküman haritası

| Doküman | İçerik |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Üretim (çoklu PoP) ve tek düğüm mimarisi, algılama süresi bütçesi, korelasyon, yapılandırmanın canlı uygulanması |
| [docs/RULES.md](docs/RULES.md) | Kural şeması, en iyi uygulamalar, flow bayrak semantiği, tam kural kataloğu, profiller, ayarlama |
| [docs/AI-ANALYST.md](docs/AI-ANALYST.md) | Analist akışı, araçlar, sağlayıcılar, güvenlik |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Boyutlandırma, kurulum (systemd/Docker), roller, yapılandırma, bildirimler, metrikler, yedekleme, sertleştirme, sorun giderme |
| [docs/TESTING.md](docs/TESTING.md) | Demo → gerçek trafikle preprod → uzak simülatör → gölge mod → BGP lab → canlı; otomatik testler; ölçüm araçları |
| [docs/BENCHMARK.md](docs/BENCHMARK.md) | Ölçüm yöntemi ve sonuçlar, bulunan ve düzeltilen sorunlar, GenieATM ile özellik ve performans karşılaştırması |
| [docs/ROUTER-CONFIG.md](docs/ROUTER-CONFIG.md) | Cisco, Juniper, Huawei, MikroTik, Arista, Linux flow export; FlowSpec/RTBH alıcı yapılandırması |
