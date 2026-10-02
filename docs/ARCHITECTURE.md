# Mimari

Bu doküman iki şeyi anlatır:

1. **Üretim (production) mimarisi:** Operatör ölçeğinde (çoklu PoP, milyonlarca flow/sn) çalışacak hedef yapı.
2. **Demo mimarisi:** Bu repodaki, tek binary olarak kendi ağınızda çalıştırabileceğiniz uygulama. Demo, üretim mimarisinin aynı mantıksal bileşenlerini tek süreçte çalıştırır; ölçek için değiştirilmesi gereken yerler en sonda tablo halinde verilmiştir.

---

## 1. Tasarım ilkeleri

| İlke | Açıklama |
|---|---|
| **Hızlı yol deterministiktir** | Algılama ve mitigasyon kararı her zaman kural + istatistik motorunda verilir. LLM bu yolda **yoktur**; gecikme, tutarsızlık ve uydurma riski kabul edilemez. |
| **LLM yorumlayıcıdır** | AI analist katmanı özet veriye bakar, eşik altı kalmış ("kıl payı") sinyalleri inceler, açıklar, raporlar ve **öneri** üretir. Uygulama her zaman insan onayından geçer. |
| **Örnekleme farkındalığı** | Tüm eşikler, örnekleme oranıyla ölçeklenmiş *tahmini* gerçek trafik üzerinden değerlendirilir. Az örnekle verilen kararlar için minimum örnek sayısı aranır. |
| **En dar etki alanlı mitigasyon** | Önce FlowSpec ile vektöre özel filtre (hedef /32 + protokol + port + paket boyu), RTBH en son çare. Her kuralın TTL'i, geri alma yolu ve "asla dokunma" listesi vardır. |
| **Histerezis** | Saldırı başlangıcı "N saniye üst üste eşik üstü", bitişi "M saniye boyunca eşiğin %X'inin altında" ile belirlenir; alarm çırpınması (flapping) engellenir. |
| **Her şey açıklanabilir** | Her olay; hangi kuralın, hangi eşiğin, hangi ölçümle tetiklendiğini ve ilk kanıtları (top kaynaklar, portlar, paket boyları) saklar. |

---

## 2. Üretim mimarisi

```
                ┌──────────────────────────── Telemetri kaynakları ────────────────────────────┐
                │  Edge/Core routerlar: sFlow v5 · NetFlow v5/v9 · IPFIX (NetStream/jFlow dahil)  │
                │  BMP (BGP tablosu) · SNMP/gNMI (arayüz sayaçları) · opsiyonel paket sensörü     │
                └───────────────┬───────────────────────────────┬──────────────────────────────┘
                                │ UDP                           │ BMP/gNMI
                     ┌──────────▼──────────┐          ┌─────────▼─────────┐
                     │  Flow Collector'lar │          │  Routing/Telemetri│
                     │ (PoP başına, yatay) │          │     toplayıcı     │
                     │ decode · normalize  │          └─────────┬─────────┘
                     │ sampling ölçekleme  │                    │
                     │ zenginleştirme:     │◄───────────────────┘ (prefix→ASN, arayüz adı)
                     │ korunan nesne, ASN  │
                     └──────────┬──────────┘
                                │ protobuf
                ┌───────────────▼────────────────┐
                │ Kafka / Redpanda               │  topic: flows (partition = hedef prefix hash)
                └──┬──────────────┬───────────┬──┘
                   │              │           │
     ┌─────────────▼───┐  ┌───────▼──────┐  ┌─▼────────────────────────┐
     │ Algılama motoru │  │ ClickHouse   │  │ İstatistik / aday sinyal │
     │ (shard'lı)      │  │ ham flow +   │  │ üreticisi (eşik altı     │
     │ kural + baseline│  │ rollup'lar   │  │ sapmalar, z-skor)        │
     └───────┬─────────┘  └──────┬───────┘  └────────────┬─────────────┘
             │ olaylar            │ sorgu                 │ adaylar
     ┌───────▼─────────┐          │              ┌────────▼──────────┐
     │ Olay yöneticisi │◄─────────┼──────────────┤  AI Analist       │
     │ (lifecycle,     │          │ read-only    │  (yerel LLM veya  │
     │ çoklu vektör)   │          └─────────────►│  Claude API)      │
     └───────┬─────────┘                         └────────┬──────────┘
             │ mitigasyon talebi                          │ bulgu + öneri
     ┌───────▼──────────────────────────────┐             │
     │ Mitigasyon orkestratörü               │◄────────────┘ (öneri → onay kuyruğu)
     │ politika · bariyerler · onay · TTL    │
     └───┬──────────────┬───────────────┬────┘
         │ BGP FlowSpec │ RTBH          │ API/GRE
   ┌─────▼─────┐  ┌─────▼─────┐  ┌──────▼─────────────┐
   │ GoBGP /   │  │ BGP       │  │ Scrubbing merkezi  │
   │ ExaBGP    │  │ speaker   │  │ (on-prem/bulut)    │
   └───────────┘  └───────────┘  └────────────────────┘

     API (REST + SSE/WebSocket) · RBAC · çok kiracılı portal · audit log · Prometheus metrikleri
```

### 2.1 Bileşenler

**Flow collector**
- Desteklenen protokoller: sFlow v5 (flow sample + expanded), NetFlow v5, NetFlow v9, IPFIX. NetStream ve jFlow, v9/IPFIX ile uyumludur.
- Şablon (template) önbelleği `(exporter, observation domain/source id, template id)` anahtarıyla tutulur. Şablon gelmeden gelen veri kümeleri sayılır ve atlanır.
- **Örnekleme oranı:** Önce flow kaydından (`samplingInterval`, sFlow `sampling_rate`) alınır, sonra options template'ten, en son yapılandırmadaki exporter override'ından. Bulunamazsa 1 kabul edilir ve UI'da uyarı gösterilir.
- Sıra numarası boşlukları (sequence gap) exporter başına sayılır: bu, UDP kaybının en iyi göstergesidir.

**Normalizasyon ve zenginleştirme**
- Yön tespiti: hedef korunan bir prefix içindeyse *inbound*, kaynak öyleyse *outbound*.
- Korunan nesne eşleşmesi: en uzun prefix eşleşmesi (LPM). Üretimde radix trie, demoda sıralı prefix listesi.
- Üretimde ek olarak BMP'den ASN ve AS-path, GeoIP, arayüz adları (SNMP/gNMI) eklenir.

**Mesaj yolu**
- Kafka/Redpanda, partition anahtarı **hedef /24 (v6 için /48) hash'i** olur. Böylece aynı hedefin ve aynı carpet bombing prefix'inin tüm trafiği aynı algılama shard'ına düşer. Bu, durum paylaşımı gerektirmeden yatay ölçeklemeyi sağlar.

**Algılama motoru**
- 1 saniyelik kovalar (bucket) ve kayan pencere (varsayılan 10 sn).
- Flow süresine yayma: Bir flow kaydının paket ve byte'ları `[alınma − süre, alınma]` aralığındaki kovalara eşit dağıtılır. Böylece 60 sn'lik active-timeout kaydı tek saniyede ani sıçrama gibi görünmez.
- **Kapsamlar:** `host` (tek hedef IP), `prefix` (carpet bombing için /24 veya /64), `object` (müşteri ya da korunan nesnenin tamamı).
- **Tetikleyiciler:**
  - Statik eşik (pps, bps, fps).
  - Dinamik baseline: EWMA ortalama ve varyans. Saldırı sırasında öğrenme dondurulur.
  - Ek koşullar: minimum benzersiz kaynak, ortalama paket boyu, minimum örnek sayısı.
- Profiller (datacenter, dns_server, residential vb.) kural eşiklerini nesne tipine göre ölçekler veya kuralı kapatır.

**Olay yöneticisi**
- Olay **hedef başına** tutulur. Aynı hedefe gelen birden fazla vektör (ör. DNS amp + NTP amp + SYN flood) tek olayın vektörleri olarak toplanır. Bu çok vektörlü saldırıların doğru temsilidir.
- Yaşam döngüsü: `active → mitigating → ended`.
  - Bitiş için tüm vektörlerin `hold_down` süresince eşiğin %70'inin altında kalması gerekir.
  - Olay bittikten sonra 2 dakika içinde aynı hedefe yeni bir tetik gelirse olay yeniden açılır.
- Adli kanıt: Tetiklenme anında ve aktif olduğu sürece 10 sn'de bir son flow'lardan top kaynaklar, kaynak portlar, paket boyu histogramı, TCP flag dağılımı ve exporter/arayüz dağılımı çıkarılır.

**Mitigasyon orkestratörü** (ayrıntı: §5)
- Kuraldaki mitigasyon şablonu, olayın hedefi ve kanıtlarıyla somut bir FlowSpec ya da RTBH talebine dönüşür.
- Bariyerlerden geçer, ardından `manual` (onay bekler) veya `auto` modda sürücüye gider.
- Sürücüler: `dryrun`, `exabgp` (ExaBGP API komut dosyası), `webhook` (scrubbing veya SOAR entegrasyonu). Üretimde GoBGP gRPC sürücüsü önerilir.

**Depolama** (üretim)
- ClickHouse tablosu `flows_raw`: 90 gün TTL, `ORDER BY (dst_prefix, ts)`.
- Materialized view'lar: `flows_1m` (2 yıl) ve `object_vector_1s` (7 gün).
- Olaylar, bulgular ve mitigasyonlar PostgreSQL'de, audit log append-only olarak tutulur.

**AI analist** (ayrıntı: §6)

**API ve UI**
- REST `/api/v1/*` ve canlı akış için SSE.
- Üretimde OIDC ile RBAC; demoda basic auth.
- Çok kiracılık: her sorgu kiracının prefix kümesiyle zorunlu olarak filtrelenir.

---

## 3. Algılama bütçesi: ne kadar hızlı algılarız?

```
Algılama süresi ≈ export gecikmesi + pencere doluluğu + sustain süresi + değerlendirme tick'i
```

| Telemetri | Export gecikmesi | Önerilen ayar | Tipik algılama süresi |
|---|---|---|---|
| sFlow | ~1 sn (paket örnekleri anında gelir) | 1:1000–1:4000 örnekleme, counter interval 10–20 sn | **3–6 sn** |
| IPFIX / NetFlow v9 | active timeout | active 10 sn, inactive 15 sn | **12–20 sn** |
| NetFlow v9 (varsayılan 60 sn active) | 60 sn | kısaltılmalı | 60+ sn |

Önerilenler:
- Mümkünse sFlow kullanın.
- NetFlow/IPFIX kullanıyorsanız active timeout'u 10 sn yapın; çoğu platformda en düşük değer budur.
- `docs/ROUTER-CONFIG.md` dosyasında örnek yapılandırmalar var.

---

## 4. Kural modeli

Her kural şunları tanımlar:

```yaml
id: amp_dns                     # tekil kimlik
direction: inbound              # inbound | outbound
scope: host                     # host | prefix | object
match:                          # flow eşleşme kriterleri (protokol, port, flag, paket boyu, fragment...)
thresholds: {pps, bps, fps}     # HERHANGİ biri aşılırsa tetik adayı
baseline: {enabled, factor, min_pps, min_bps}   # dinamik tetik (statik ile birlikte)
conditions:                     # ek doğrulama: min_unique_sources, min/max ortalama paket boyu, min_samples
trigger: {sustain, hold_down}   # histerezis
mitigation: {flowspec: {...}, rtbh: {...}}       # önerilen aksiyon şablonu
```

Tetik mantığı:

```
rate = pencere toplamı / pencere süresi           (örnekleme ile ölçeklenmiş)
static_hit   = rate.pps ≥ T.pps  ∨  rate.bps ≥ T.bps  ∨  rate.fps ≥ T.fps
baseline_hit = baseline öğrenildi ∧ rate ≥ max(min_floor, factor × baseline)
koşullar     = benzersiz kaynak ≥ N ∧ ortalama paket boyu ∈ [min,max] ∧ örnek sayısı ≥ min_samples
tetik        = (static_hit ∨ baseline_hit) ∧ koşullar, art arda `sustain` saniye
```

Kural kataloğu ve gerekçeleri için: [RULES.md](RULES.md).

---

## 5. Mitigasyon ve güvenlik bariyerleri

Sıralama en dar etkiden en genişe doğrudur:

1. **FlowSpec, vektöre özel:**
   - Eşleşme: `destination <hedef>/32`, `protocol udp`, `source-port =53`, `packet-length >=512`.
   - Aksiyon: `discard` veya `rate-limit`.
   - Spoof'lu ve dağıtık saldırılarda kaynak IP ile eşleşme **yapılmaz**.
2. **FlowSpec, prefix seviyesi:** Carpet bombing'de hedef /24, protokol ve port.
3. **Scrubbing'e yönlendirme:** Webhook veya BGP ile (üretim).
4. **RTBH** (`65535:666`, RFC 7999): Yalnızca /32 veya /128 için, yalnızca saldırı hacmi bağlantı kapasitesinin belirli bir oranını aştığında ve yalnızca onayla. RTBH kurbanı tamamen erişilemez kılar, yani saldırganın işini bitirir; bu yüzden son çaredir.

**Bariyerler** (her talep için sırayla kontrol edilir):
- Hedef, korunan bir nesnenin içinde mi? Değilse reddedilir.
- `never_mitigate` listesinde mi (DNS resolver'lar, router loopback'leri, upstream peering IP'leri)? Öyleyse reddedilir.
- FlowSpec hedef prefix uzunluğu en az /24 (v6 için /48) olmalı; daha genişse reddedilir.
- Aktif kural sayısı `max_active` değerini aşıyorsa reddedilir.
- RTBH yalnızca host kapsamında ve escalation koşulu sağlanırsa uygulanır.
- Her kuralın TTL'i vardır. Olay bittikten sonra `withdraw_after` süre geçince otomatik geri çekilir.
- `manual` modda her talep onay kuyruğuna düşer. AI analistin önerileri **her zaman** onay ister, mod `auto` olsa bile.

---

## 6. AI analist katmanı

### 6.1 Rolü
Kıdemli bir NOC analisti gibi çalışır. Her flow'a değil, **özet tabloya** bakar:
- Dedektörün alarm vermediği ama referanstan sapmış durumları (aday sinyaller) inceler.
- Kendi seçtiği araçlarla detaya iner (zaman serisi, top-N, dağılımlar, örnek flow'lar).
- Bağlamla ilişkilendirir (nesne profili, kural eşikleri, mevcut olaylar).
- Yapılandırılmış bir bulgu üretir: önem, güven, hipotez, kanıt, **dedektörün neden kaçırdığı** ve öneriler (eşik ayarı, yeni kural, FlowSpec adayı, whitelist, aksiyon gerekmez).

### 6.2 Akış
```
[her N dk] aday sinyal üreticisi ──► yeni aday yoksa LLM çağrılmaz (maliyet 0)
                │ adaylar
                ▼
        LLM: önceliklendir → "şunu inceleyeyim" → araç çağrıları (salt okunur, özet veri)
                │
                ▼
        submit_finding (yapılandırılmış JSON) → UI'da bulgu + öneriler (onay butonlu)
```

**Araçlar** (hepsi salt okunur ve özet döndürür):
- `get_overview`
- `list_candidate_signals`
- `get_timeseries`
- `top_n`
- `traffic_breakdown`
- `sample_flows` (en fazla 50 kayıt)
- `get_incidents`
- `get_rule_for_target` (efektif eşikler: "neden tetiklenmedi?")
- `get_object_context`
- `submit_finding`

### 6.3 Güvenlik
- **Sayıları LLM üretmez.** Bulgudaki her rakam bir araç çıktısına dayanır; kanıt listesinde hangi çağrıdan geldiği yazılır.
- **Prompt injection'a karşı:** Araç çıktılarındaki serbest metin alanları (exporter adı, nesne notu vb.) veri olarak işaretlenir. Sistem prompt'u, araç çıktısındaki talimatların uygulanmamasını söyler. LLM'in yazma yetkisi yoktur; tek yan etkisi bulgu kaydetmektir.
- **Bütçe:** Çalışma başına en fazla tur ve token sınırı. Tur sınırına yaklaşınca model bulguyu göndermeye zorlanır.
- **Gizlilik:** Yerel LLM modunda veri hiçbir zaman ağ dışına çıkmaz. Claude API modunda gönderilen veri yalnızca özet ve en fazla 50 örnek flow'dur. Demo için sentetik veri önerilir.

### 6.4 Sağlayıcılar
| Sağlayıcı | Ne zaman | Not |
|---|---|---|
| `anthropic` | Demo, yüksek kalite | Resmi Go SDK, `claude-opus-5-5`, adaptive thinking, sunucu taraflı refusal fallback |
| `openai_compat` | Yerel (Ollama, vLLM, LM Studio) | `/v1/chat/completions` ve tool calling; veri dışarı çıkmaz |
| `heuristic` | LLM yok | Deterministik şablon raporu; demo anahtar olmadan da çalışır |

---

## 7. Ölçekleme notları (üretim)

- **Collector:** UDP `SO_REUSEPORT` ve çekirdek başına okuyucu. Tek düğüm 1–2M flow/sn hedeflenir.
- **Algılama:** Kafka partition başına bir worker, durum (state) shard'a özel. Anahtar sayısı patladığında host kapsamı yalnızca "aktif" hedefler için tutulur (pencere içinde trafik görmeyen anahtarlar silinir).
- **Benzersiz kaynak sayımı:** Demoda üst sınırlı küme, üretimde HyperLogLog.
- **Top-N:** Demoda son flow halka tamponunda tarama, üretimde Space-Saving sketch ve ClickHouse.
- **Baseline:** Demoda EWMA ortalama/varyans, üretimde haftanın saati (168 slot) mevsimsel profil ve tatil/etkinlik takvimi.

---

## 8. Demo mimarisi (bu repo)

```
ddosd (tek Go binary)
 ├─ collector   UDP :2055 (NetFlow v5/v9/IPFIX), :4739 (IPFIX), :6343 (sFlow)
 ├─ decoder     netflow5 · netflow9 · ipfix · sflow (+ ham paket başlığı ayrıştırma)
 ├─ engine      tek goroutine'lik aggregator: kovalar, kurallar, baseline, olaylar, adaylar
 ├─ flowstore   son N flow halka tamponu (adli inceleme, top-N, flow explorer)
 ├─ mitigation  bariyerler, onay kuyruğu, dryrun/exabgp/webhook sürücüleri, vendor syntax önizleme
 ├─ analyst     aday sinyal kapısı, araçlar, anthropic/openai_compat/heuristic sağlayıcılar
 ├─ api         REST + SSE, basic auth, gömülü React UI
 └─ sim         (opsiyonel) sentetik trafik ve saldırı senaryoları; gerçek NetFlow/IPFIX/sFlow paketleri üretir
ddos-sim        aynı simülatörün komut satırı versiyonu (başka bir makineden collector'a göndermek için)
```

Demo ile üretim arasındaki farklar:

| Konu | Demo | Üretim |
|---|---|---|
| Mesaj yolu | Go channel | Kafka/Redpanda |
| Ham flow deposu | Bellek içi halka tampon (varsayılan 500k kayıt) | ClickHouse |
| Olay/bulgu deposu | JSON snapshot (`data/`) | PostgreSQL |
| Ölçek | Tek düğüm, yaklaşık 100–300k flow/sn | Shard'lı, yatay |
| BGP | ExaBGP komut dosyası veya dry-run | GoBGP gRPC, çoklu route reflector |
| Auth | Basic auth | OIDC + RBAC + audit |
| Baseline | EWMA | Mevsimsel profil |
