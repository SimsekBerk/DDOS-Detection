# DDoS Detection (ddosd)

Flow tabanlı (NetFlow v5/v9, IPFIX, sFlow v5) bir DDoS algılama ve mitigasyon orkestrasyon platformu. Üzerinde, eşik altında kalan saldırıları yorumlayan bir **AI analist** katmanı çalışır. Operatör ve veri merkezi ağları için tasarlandı.

```
Router'lar ──NetFlow/IPFIX/sFlow──► collector ─► algılama motoru ─► olaylar ─► mitigasyon (FlowSpec / RTBH / scrubbing)
                                                     │ eşik altı sinyaller
                                                     ▼
                                               AI analist (heuristic · Claude · yerel LLM) ─► bulgu + öneri (insan onayı)
```

## Özellikler

- **Telemetri**
  - NetFlow v5/v9, IPFIX (options template ile örnekleme öğrenme dahil) ve sFlow v5 (ham paket başlığı, VLAN/MPLS/IPv6 uzantı başlıkları).
  - Tüm portlarda format otomatik tanınır.
  - Exporter sağlığı izlenir: sıra numarası boşluğundan tahmini kayıp, şablonsuz veri, örnekleme oranı.
- **Algılama motoru**
  - 1 sn kovalar ve kayan pencere.
  - Uzun flow'lar süreleri boyunca zamana yayılır.
  - Statik eşik ve EWMA baseline (saldırı sırasında öğrenme donar).
  - Doğrulama koşulları: benzersiz kaynak/hedef, paket boyu, örnek sayısı.
  - Histerezis (sustain / hold-down).
  - Host, prefix (carpet bombing) ve nesne kapsamları.
  - Çok vektörlü olaylar.
  - Adli kanıt: top kaynaklar/portlar/ağlar, paket boyu histogramı, TCP flag'leri, örnek flow'lar.
- **52 kural, 8 profil (L3/L4):** amplifikasyon (DNS, NTP, SSDP, memcached, CLDAP, SNMP, WS-Discovery, SLP, CoAP …), TCP (SYN, SYN-ACK, ACK, RST, FIN, NULL, XMAS, PSH-ACK, bağlantı seli), UDP/QUIC, ICMP (BlackNurse dahil), fragment, GRE/ESP/alışılmadık protokoller, carpet bombing, hacimsel toplamlar, outbound saldırılar ve açık yansıtıcılar → [docs/RULES.md](docs/RULES.md)
- **Mitigasyon**
  - Kural şablonu ve kanıttan en dar FlowSpec üretilir.
  - Güvenlik bariyerleri: korunan alan, `never_mitigate`, minimum prefix uzunluğu, aktif kural limiti, mükerrer kontrolü.
  - Onay kuyruğu, TTL, olay bitince otomatik geri çekme.
  - Sürücüler: `dryrun`, `exabgp`, `webhook` (HMAC imzalı).
  - ExaBGP, GoBGP, Junos ve IOS-XR çıktısı.
- **AI analist**
  - Salt okunur araçlarla özet veri üzerinde ajan döngüsü.
  - "Dedektör neden kaçırdı?" açıklaması, kanıtlı bulgular, tek tıkla uygulanabilir öneriler.
  - Sağlayıcılar: `heuristic` (LLM yok), `anthropic` (Claude API), `openai_compat` (Ollama/vLLM) → [docs/AI-ANALYST.md](docs/AI-ANALYST.md)
- **Web arayüzü** (Türkçe, koyu/açık tema): genel bakış, saldırılar ve olay detayı, mitigasyon onayları, AI analist, kural setleri, korunan nesneler ve hedef analizi, flow explorer, telemetri kaynakları, simülatör, sistem.
- **Simülatör:** 27 senaryo. Gerçek NetFlow/IPFIX/sFlow paketleri üretir; hem arayüzden hem `ddos-sim` CLI'ından çalışır. Ağınızda gerçek saldırı trafiği üretmez.

## Hızlı başlangıç

```bash
# Demo: sentetik trafik + saldırı senaryoları → http://localhost:8090
go run ./cmd/ddosd -config config.demo.yaml
```

Ardından **Simülatör** sayfasından bir senaryo başlatın (ör. DNS Amplification). Sırasıyla **Saldırılar**, **Mitigasyon** ve **AI Analist** sayfalarını izleyin.

Kendi ağınız için:

```bash
cp config.example.yaml config.yaml      # prefixler, profiller, never_mitigate
make build && ./bin/ddosd -config config.yaml
# veya Docker:
docker compose -f deploy/docker-compose.yml up -d
```

Router örnekleri [docs/ROUTER-CONFIG.md](docs/ROUTER-CONFIG.md) dosyasında, adım adım test planı ise [docs/TESTING.md](docs/TESTING.md) dosyasında.

Gereksinimler: Go 1.24 veya üzeri. UI'ı yeniden derlemek için Node 20 gerekir; derlenmiş UI `web/dist` içinde repoya dahildir.

## Dokümantasyon

| Doküman | İçerik |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Üretim ve demo mimarisi, algılama bütçesi, olay yaşam döngüsü, ölçekleme |
| [docs/RULES.md](docs/RULES.md) | Kural şeması, en iyi uygulamalar, tam kural kataloğu, ayarlama |
| [docs/AI-ANALYST.md](docs/AI-ANALYST.md) | Analist akışı, araçlar, sağlayıcılar, güvenlik, değerlendirme |
| [docs/ROUTER-CONFIG.md](docs/ROUTER-CONFIG.md) | Cisco, Juniper, Huawei, MikroTik, Arista, Linux; FlowSpec/RTBH alıcı yapılandırması |
| [docs/TESTING.md](docs/TESTING.md) | Demo → uzak simülatör → gölge mod → BGP lab → canlı |

## Proje yapısı

```
cmd/ddosd          daemon: collector + motor + mitigasyon + analist + API/UI
cmd/ddos-sim       komut satırı trafik/saldırı simülatörü
internal/decoder   NetFlow v5/v9, IPFIX, sFlow v5 çözücüler
internal/collector UDP dinleyiciler, exporter sağlığı
internal/engine    seriler, baseline, kurallar, olaylar, sinyaller, kanıt
internal/rules     kural/profil şeması ve derleyici
internal/flowstore son flow halka tamponu, top-N / kırılım / örnek sorguları
internal/mitigation FlowSpec/RTBH üretimi, bariyerler, onay, sürücüler
internal/analyst   AI analist: araçlar, prompt, anthropic/openai_compat/heuristic
internal/api       REST API + gömülü UI
internal/sim       sentetik trafik ve senaryolar (encoder'lar dahil)
rules/             YAML kural setleri ve profiller
web/               React + TypeScript arayüz (web/dist derlenmiş)
deploy/            docker-compose, ExaBGP örneği
docs/              mimari ve operasyon dokümanları
```

## API

Tüm uç noktalar `/api/v1` altındadır. `api.password` tanımlıysa basic auth zorunludur.

| Uç nokta | Açıklama |
|---|---|
| `GET /overview` | motor anlık görüntüsü, sayaçlar |
| `GET /timeseries?object=&range=&step=` | trafik geçmişi |
| `GET /incidents`, `GET /incidents/{id}` | olaylar, kanıt, mitigasyonlar, bulgular |
| `GET /signals?pending=true` | aday sinyaller |
| `GET /target?ip=` | bir hedef için tüm kuralların canlı durumu |
| `POST /flows/top`, `/flows/breakdown`, `/flows/samples` | flow explorer |
| `GET /rules`, `PATCH /rules/{id}`, `POST /rules/reload` | kural yönetimi |
| `GET/POST /mitigations`, `POST /mitigations/{id}/approve\|reject\|withdraw\|extend` | mitigasyon |
| `POST /analyst/run`, `/analyst/incident/{id}`, `/analyst/ask`, `GET /analyst/findings/{id}`, `POST /analyst/findings/{id}/apply/{idx}` | AI analist |
| `GET /sim`, `POST /sim/start\|stop\|baseline` | demo simülatörü |

## Geliştirme

```bash
make test                 # go test ./...
cd web && npm run dev     # UI geliştirme sunucusu (API'yi :8090'a proxy'ler)
make ui build             # UI + binary
```
