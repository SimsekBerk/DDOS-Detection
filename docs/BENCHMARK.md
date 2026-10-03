# Benchmark: ddosd ve GenieATM

**Tarih:** 3 Ekim 2026 · **Sürüm:** bu repodaki `main` · **Ortam:** Apple M3 Pro (11 çekirdek), macOS, Go 1.24

## Özet

| Ölçüt | ddosd (ölçülen) | GenieATM (üretici beyanı) |
|---|---|---|
| Algılama doğruluğu (27 senaryo × 4 telemetri) | **108/108**, yanlış hedef 0 | Yayımlanmış test yok |
| Algılama süresi, sFlow 1:1000 | **3–11 sn** (medyan 6) | "Saniyeler içinde" (sayı yok) |
| Algılama süresi, NetFlow/IPFIX (10 sn active timeout) | **12–20 sn** (medyan 15) | Aynı fiziksel sınır: export süresi |
| Normal trafikte yanlış olay (48 simüle saat) | **0** | Yayımlanmış veri yok |
| AI analist için aday sinyal gürültüsü | 48 saatte 1–3 (saatte ≤0,06) | — (LLM analist yok) |
| Flow kapasitesi | Tek düğüm, tek exporter: **2M kayıt/sn kayıpsız** | Sistem genelinde "24M flow/sn'ye kadar" (dağıtık Collector'larla); eski appliance modelleri 20k–50k flow/sn |
| Decode (tek çekirdek) | NetFlow v9 7,5M · IPFIX 7,2M · sFlow 10,9M kayıt/sn | Yayımlanmamış |
| Ölçümün tekrarlanabilirliği | `ddos-bench` ile herkes tekrarlayabilir | Kapalı |

**Önemli uyarı:** GenieATM'i bu çalışmada çalıştırma imkânımız olmadı. GenieATM için bağımsız ve yayımlanmış bir benchmark da yok (NSS Labs 2020'de kapandı; analist raporları bulut scrubbing servislerini değerlendiriyor). Tablodaki GenieATM değerleri üreticinin pazarlama materyallerinden ve eski tekliflerden alınmıştır, doğrulanmamıştır. ddosd değerleri sentetik trafikle ölçülmüştür. İki ürünü adil şekilde karşılaştırmanın tek yolu aynı router'lardan aynı flow'larla paralel çalıştırmaktır; yöntem §5'te.

---

## 1. Yöntem

### 1.1 Algılama doğruluğu ve süresi

`ddos-bench detect` her senaryoyu her telemetri modunda ayrı bir motor örneğiyle çalıştırır:

1. **Isınma (7 dk):** 600 Mbps normal trafik (web, DNS, NTP, QUIC, ICMP, giden trafik karışımı; 10 dakikalık dalga). TCP flow'ları gerçek router export'larındaki gibi bağlantı boyunca birleştirilmiş bayraklar taşır: tamamlanmış (`SYN|ACK|PSH|FIN`), uzun süren (`SYN|ACK|PSH`, `ACK|PSH`), RST ile kesilen ve ECN'li bağlantılar. Baseline bu sürede öğrenilir.
2. **Saldırı (90 sn):** senaryonun trafiği normal trafiğe eklenir.
3. **Soğuma (4 dk):** yalnızca normal trafik; olayın kapanması beklenir.

Trafik gerçek NetFlow v9 / IPFIX / sFlow paketleri olarak kodlanır, gerçek decoder ve motordan geçer. Saat simüle edilir; router flow önbelleğinin active/inactive timeout davranışı taklit edilir (uzun flow'lar timeout dolunca export edilir). Bu yüzden ölçülen algılama süresi, gerçek router'daki export gecikmesini de içerir.

| Telemetri modu | Örnekleme | Export |
|---|---|---|
| sFlow 1:1000 | 1:1000 | anlık (paket örneği) |
| IPFIX 1:1 (10s/15s) | yok | active 10 sn, inactive 15 sn |
| NetFlow v9 1:1000 (10s/15s) | 1:1000 | active 10 sn, inactive 15 sn |
| NetFlow v9 1:1 (60s/15s) | yok | active 60 sn (birçok router'ın varsayılanı) |

**Geçme kriteri:** saldırı senaryolarında beklenen kural(lar) doğru hedefte tetiklenmeli ve başka hedefte olay açılmamalı. Eşik altı senaryolarda (AI analist için) olay açılmamalı, beklenen türde aday sinyal üretilmeli.

**Senaryolar (27):** DNS, NTP, SSDP, memcached, CLDAP, WS-Discovery amplifikasyonu; carpet bombing (NTP amp ve SYN, /24); UDP fragment; ICMP echo; BlackNurse; GRE; IP-in-IP; TCP SYN, SYN-ACK yansıtma, ACK, RST, NULL, XMAS; QUIC/UDP-443; UDP flood; küçük paketli UDP; giden SYN (botnet üyesi müşteri) ve giden yansıtıcı (açık NTP sunucusu); eşik altı DNS amp, az kaynaklı yüksek hacim ve yavaş yükselen UDP (AI analist senaryoları). Saldırı büyüklükleri 12k–900k pps arasındadır.

### 1.2 Yanlış alarm

`ddos-bench baseline -baseline-minutes 120 -phases 6`: yalnızca normal trafik, her telemetri modunda 120 dakika, normal trafik dalgasının 6 farklı başlangıç fazında (toplam 24 koşu, 48 simüle saat). Açılan her olay yanlış alarmdır.

### 1.3 Kapasite

`ddos-bench throughput`:

- **Decode:** tek çekirdekte, bellekten paket çözme.
- **Motor:** tek çekirdekte sınıflandırma + toplama + değerlendirme (52 kural, flow tamponu dahil).
- **Uçtan uca:** UDP loopback üzerinden hedef hızda IPFIX gönderilir; collector (4 worker) → motor. Kayıp = gönderilen − işlenen.

---

## 2. Sonuçlar

### 2.1 Algılama

| Telemetri | Geçen | Saldırı koşusu | Algılama süresi min / medyan / p90 / max | Olay bitişi (saldırı bittikten sonra) |
|---|---|---|---|---|
| sFlow 1:1000 | 27/27 | 24 | 3 / 6 / 9 / 11 sn | 66–130 sn |
| IPFIX 1:1 (10s/15s) | 27/27 | 24 | 12 / 15 / 17 / 20 sn | 67–139 sn |
| NetFlow v9 1:1000 (10s/15s) | 27/27 | 24 | 12 / 15 / 17 / 20 sn | 63–139 sn |
| NetFlow v9 1:1 (60s/15s) | 27/27 | 24 | 18 / 21 / 62 / 62 sn | 80–145 sn |
| **Toplam** | **108/108** | | | |

- Yanlış hedefte olay: **0**.
- Olay bitişi kuralın `hold_down` süresinden (60–120 sn) gelir; bu, kısa aralarla tekrar eden saldırılarda olayın çırpınmasını önlemek için bilinçli bir tercihtir.
- 96 saldırı koşusunun 12'sinde aynı olaya ek olarak genel bir vektör (`udp_flood_host`, `total_host` veya `amp_generic_lowport`) eklendi: CLDAP ve memcached'de port bilgisi taşımayan fragment'lar, ACK flood'da ise ACK kuralına uymayan trafik özel vektörlerce açıklanamadığı için. Ayrı olay açılmaz.

Senaryo bazında algılama süresi (sn):

| Senaryo | sFlow 1:1000 | IPFIX (10s/15s) | NetFlow v9 1:1000 (10s/15s) | NetFlow v9 (60s/15s) |
|---|---|---|---|---|
| DNS amp | 7 | 16 | 15 | 22 |
| NTP amp | 5 | 14 | 14 | 20 |
| memcached amp | 3 | 12 | 12 | 18 |
| CLDAP amp | 6 | 15 | 15 | 21 |
| SSDP amp | 6 | 15 | 15 | 21 |
| WS-Discovery amp | 6 | 15 | 15 | 21 |
| Carpet NTP (/24) | 5 | 14 | 14 | 20 |
| Carpet SYN (/24) | 6 | 15 | 15 | 21 |
| TCP SYN | 3 | 12 | 12 | 18 |
| ACK flood | 11 | 20 | 20 | 26 |
| RST flood | 6 | 15 | 15 | 21 |
| SYN-ACK yansıtma | 7 | 15 | 16 | 22 |
| TCP NULL | 6 | 15 | 15 | 21 |
| TCP XMAS | 4 | 14 | 13 | 20 |
| UDP flood | 6 | 15 | 15 | 21 |
| Küçük paketli UDP | 6 | 15 | 15 | 21 |
| QUIC flood | 6 | 15 | 15 | 21 |
| UDP fragment | 8 | 12 | 14 | 62 |
| ICMP echo | 6 | 14 | 14 | 48 |
| BlackNurse | 5 | 12 | 12 | 62 |
| GRE | 9 | 12 | 13 | 62 |
| IP-in-IP | 7 | 12 | 12 | 62 |
| Giden SYN (botnet) | 11 | 20 | 20 | 26 |
| Giden yansıtıcı | 7 | 17 | 17 | 23 |

60 sn active timeout'ta port bilgisi taşımayan saldırılar (fragment, ICMP, GRE, IP-in-IP) en yavaş algılananlardır: her kaynak tek bir uzun flow oluşturur ve router bu flow'u ancak active timeout dolunca export eder (48–62 sn). Rastgele portlu TCP/UDP saldırıları çok sayıda kısa flow ürettiği için inactive timeout (15 sn) ile daha erken görünür. **Pratik sonuç:** NetFlow/IPFIX kullanıyorsanız active timeout'u 10 sn yapın, mümkünse sFlow kullanın.

### 2.2 Yanlış alarm

| Telemetri | Koşu | Süre | Yanlış olay | Aday sinyal |
|---|---|---|---|---|
| sFlow 1:1000 | 6 faz | 12 saat | 0 | 0 |
| IPFIX 1:1 (10s/15s) | 6 faz | 12 saat | 0 | 1 |
| NetFlow v9 1:1000 (10s/15s) | 6 faz | 12 saat | 0 | 0 |
| NetFlow v9 1:1 (60s/15s) | 6 faz | 12 saat | 0 | 0 |
| **Toplam** | 24 | **48 saat** | **0** | **1** |

Aday sinyaller olay değildir; AI analistin incelemesi için kuyruğa düşer. Normal trafikteki rastgelelik nedeniyle tekrarlarda 48 saatte 1–3 sinyal görülür.

### 2.3 Kapasite

| Aşama | Sonuç |
|---|---|
| Decode, tek çekirdek | NetFlow v9 **7,48M**, IPFIX **7,21M**, sFlow **10,94M** kayıt/sn |
| Motor, tek çekirdek (52 kural, 1.283 seri) | **2,21M** kayıt/sn |
| Uçtan uca UDP, hedef 0,5M / 1M / 2M kayıt/sn | %0 kayıp |
| Uçtan uca UDP, hedef 3M / 4M kayıt/sn | 2,58M kayıt/sn'de doyma (%14 / %35 kayıp, worker kuyruğunda) |

Tek exporter'ın tüm datagram'ları sıra ve şablon tutarlılığı için tek worker'a düşer; doyma noktası bu worker'dır. Birden çok router'dan gelen trafik worker'lara dağılır ve çekirdek sayısıyla ölçeklenir. Motor kuyruğunda hiç kayıp olmadı.

### 2.4 Dayanıklılık

- Decoder fuzz testi: 60 sn'de **21,7M** rastgele/bozuk paket, çökme veya panik yok.
- Tüm paketler `go test -race` ile yarış durumu (data race) olmadan geçer.
- Sahte kaynaklı flow yağmuruna karşı sınırlar: exporter sayısı (4.096), exporter başına şablon (1.024), izlenen seri (`max_series`), izin listesi.

---

## 3. Testlerin bulduğu ve düzeltilen sorunlar

Bu benchmark yalnızca ölçüm için değil, ürünü düzeltmek için kullanıldı. Bulunan sorunlar:

| Sorun | Belirti | Düzeltme | Sonuç |
|---|---|---|---|
| NetFlow/IPFIX'te kaçan amplifikasyon | Toplu export'ta "son saniyede trafik" şartı sağlanmıyordu | Sustain: pencerede en az 2 aktif saniye | 108/108 |
| Aynı saldırı için birden fazla olay | Genel kurallar ve nesne kapsamı ayrıca tetikleniyordu | `generic` kurallar + hiyerarşik korelasyon | yanlış hedef 0 |
| Eşzamanlı farklı carpet saldırıları | Carpet SYN aktifken carpet UDP amplifikasyonu hiç raporlanmıyordu | Korelasyon yalnızca alt küme ilişkisindeki kurallar arasında (`rules.Set.Within`) | regresyon testi eklendi |
| Gereksiz genel vektörler | 108 koşunun 16'sında; her biri ayrı mitigasyon talebi | Ayrık vektörlerin hızları toplanıyor, dar kurallar önce değerlendiriliyor | 16 → 11 |
| `tcp_conn_flood` yanlış tetik | Normal web trafiğinde tetikleniyordu | Kural yeniden yazıldı (tamamlanmış bağlantı flag'leri) | 0 yanlış olay |
| Aday sinyal gürültüsü | Saatte 58–72 sinyal | Kalıcılık, "yükselen trafik" şartı, açılışta öğrenme dönemi eşiği | 48 saatte 1–3 |
| Uçtan uca kayıp | 1M kayıt/sn'de kayıp | Sınıflandırma collector worker'larına taşındı, toplu gönderim | 2M kayıt/sn'de %0 |
| Ayar ekranı (tarayıcı testi) | Kural eşiği ters gösteriliyordu; syslog testi protokolsüz başarısız; yeni token listede görünmüyordu; geri alınan değişiklikte "yeniden başlatma gerekli" kalıyordu | Hepsi düzeltildi, API testleri eklendi | |
| Arayüz taşmaları | 1024 px'te tablolar ve KPI değerleri, mobilde mitigasyon kartları ekrandan taşıyordu | Tablo/kart düzeni; 375 / 768 / 1024 / 1440 px'te otomatik taşma taraması | 22 sayfada taşma yok |
| Normal bağlantılar "TCP XMAS" saldırısı sanılıyordu | Gerçek trafikle preprod testinde bulundu: flow kayıtlarında bayraklar bağlantı boyunca birleşir, tamamlanmış bir HTTPS bağlantısı `SYN\|ACK\|PSH\|FIN` görünür ve SYN+FIN kuralına uyar. Simülatörün normal trafiği gerçekçi bayraklarla üretilince benchmark da 8 saatte 259 sahte olay gösterdi | `tcp_xmas_synfin` (ACK yok), `tcp_rst_flood` (SYN/PSH yok) ve `tcp_synack_reflection` (PSH yok) kuralları gerçek saldırı imzasına göre daraltıldı; simülatörün normal trafiği gerçekçi bayraklar taşıyor; regresyon testi eklendi | 259 → 0 sahte olay; 108/108 korundu |
| Docker'da ayar kaydedilemiyordu | Yapılandırma salt okunur tek dosya olarak bağlıydı; `data_dir` volume'a gitmiyordu | Yazılabilir yapılandırma dizini, yerinde yazma geri dönüşü, arayüzde uyarı | |

---

## 4. Özellik karşılaştırması

✓ var · ~ kısmen · ✗ yok · ? kamuya açık bilgi yok

| Yetenek | GenieATM | ddosd |
|---|---|---|
| NetFlow v5/v9, IPFIX, sFlow (NetStream/jFlow dahil) | ✓ | ✓ |
| SNMP ve BGP verisiyle korelasyon | ✓ | ✗ (yol haritası: BMP, SNMP) |
| Statik eşik + dinamik baseline | ✓ (ML/ARIMA) | ✓ (EWMA; mevsimsel profil yok) |
| Carpet bombing | ✓ | ✓ (prefix kapsamı + benzersiz hedef koşulu) |
| Arayüz/BGP anomalileri (CRC, hijack, route değişimi) | ✓ | ✗ |
| Hazır L3/L4 kural kataloğu, gerekçe ve yanlış alarm notlarıyla | ? | ✓ (52 kural, 8 profil, açık YAML) |
| "Neden tetiklenmedi?" hedef analizi (anlık hız, efektif eşik, baseline, koşul) | ? | ✓ |
| FlowSpec ve RTBH | ✓ | ✓ (onay kuyruğu, TTL, otomatik geri çekme, güvenlik bariyerleri) |
| Vendor yapılandırma önizlemesi (ExaBGP, GoBGP, Junos, IOS-XR) | ? | ✓ |
| Üçüncü parti scrubber'lara yerleşik entegrasyon (A10, F5, Huawei, Radware) | ✓ | ~ (genel HMAC'li webhook) |
| Bulut scrubbing'e BGP ile yönlendirme | ✓ | ~ (RTBH/webhook üzerinden) |
| Çok kiracılı müşteri portalı | ✓ (ayrı ürün: MSP Server) | ✓ (aynı üründe nesne kapsamlı kullanıcılar ve token'lar; marka/SLA özelleştirmesi yok) |
| Rol tabanlı yetki ve denetim kaydı | ✓ | ✓ |
| Tek oturum açma (OIDC/SAML) | ? | ✗ (yol haritası) |
| Bildirimler | e-posta, SNMP trap, syslog, webhook | e-posta, syslog, HMAC'li webhook, Slack, Teams, Telegram (SNMP trap yok) |
| REST API | ✓ (doküman kapalı) | ✓ (açık), Prometheus metrikleri, sağlık kontrolleri |
| Arayüzden yapılandırma, sürüm geçmişi ve geri alma | ~ (yönetim arayüzü var; sürümleme bilgisi yok) | ✓ (canlı uygulama, 100 sürüm, gizli alan maskeleme) |
| Uzun dönem flow analitiği ve adli arşiv | ✓ (ayrı ürün: GenieAnalytics) | ~ (bellek içi son 500k flow, 24 saat trafik geçmişi) |
| Abone/OTT görünürlüğü (DNS/RADIUS/NAT eşleme) | ✓ (Deep Trace) | ✗ |
| LLM tabanlı analist (açıklama, eşik altı inceleme, öneri) | ✗ | ✓ (Claude API veya yerel LLM; veri dışarı çıkmadan) |
| Dağıtık collector, yük dengeleme, yüksek erişilebilirlik | ✓ (FLB, Controller/Collector) | ✗ (tek düğüm; flow yönlendirme ile paralel çalışma) |
| Ölçek | 24M flow/sn'ye kadar (beyan) | tek düğümde 2M flow/sn (ölçülen) |
| Kurulum | Appliance / VM | Tek binary veya Docker |
| Tekrarlanabilir benchmark aracı | ✗ | ✓ (`ddos-bench`) |
| Fiyat ve doküman erişimi | Kapalı, form ile | Kendi ürününüz |

### 4.1 ddosd nerede önde

1. **Açıklanabilirlik ve AI analist.** Eşik altında kalan saldırıları ("kıl payı") inceleyen, nedenini açıklayan ve öneri üreten bir analist katmanı GenieATM'de yok. Yerel LLM desteğiyle veri kurumdan çıkmaz.
2. **Ölçülebilirlik.** Algılama süresi, doğruluk ve yanlış alarm değerleri yayımlanmış ve tekrarlanabilir; GenieATM yalnızca "saniyeler içinde" diyor.
3. **Tek üründe bütünlük.** Çok kiracılık, analiz ekranları ve analist aynı üründe; GenieATM'de MSP Server ve GenieAnalytics ayrı ürünler.
4. **Operasyonel modernlik.** Arayüzden sürümlü yapılandırma, Prometheus, Slack/Teams/Telegram, açık API ve tek binary kurulum.

### 4.2 GenieATM nerede önde

1. **Ölçek ve dağıtık mimari.** 24M flow/sn sistem ölçeği, yük dengeleyici ve yüksek erişilebilirlik. ddosd şu an tek düğüm.
2. **Ağ bağlamı.** SNMP ve BGP ile korelasyon, arayüz ve routing anomalileri, Deep Trace ile abone görünürlüğü.
3. **Ekosistem.** Scrubbing cihazlarına hazır entegrasyonlar ve 650+ müşteride saha olgunluğu.
4. **Uzun dönem analitik.** Yıllarca saklanan 1 sn çözünürlüklü veri (GenieAnalytics).

### 4.3 Farkı kapatmak için öncelik sırası

| Öncelik | İş | Etkisi |
|---|---|---|
| 1 | BMP/BGP ve SNMP/gNMI girdisi (ASN, arayüz, route anomalileri) | Ağ bağlamı farkını kapatır |
| 2 | Kafka + ClickHouse ile shard'lı collector/motor, aktif/aktif yüksek erişilebilirlik | Operatör ölçeği (≥10M flow/sn) |
| 3 | Mevsimsel baseline (haftanın saati, 168 dilim) | Büyük ağlarda yanlış alarm |
| 4 | Scrubber API entegrasyonları (A10 TPS, Radware DefensePro, Huawei) ve SNMP trap | Kurumsal entegrasyon |
| 5 | OIDC/SAML ve kiracı portalı özelleştirmesi | Kurumsal kimlik, MSSP |
| 6 | Uzun dönem flow arşivi ve raporlama | Adli inceleme, kapasite planlama |

---

## 5. GenieATM ile sahada adil karşılaştırma

Gerçek bir karşılaştırma için iki ürün aynı trafiği görmelidir:

1. ddosd'yi gölge modda kurun (`mitigation.mode: manual`, `driver: dryrun`).
2. Aynı flow'ları iki ürüne verin:
   - Router'dan iki collector'a export (çoğu platform birden fazla hedef destekler), **veya**
   - GenieATM collector'ının önüne ddosd koyup `collector.forward` ile datagram'ları GenieATM'e kopyalayın (ddosd datagram'ı alır almaz, decode etmeden kopyalar).
3. Aynı korunan nesneleri ve eşik politikasını iki ürüne tanımlayın.
4. En az 2 hafta boyunca karşılaştırın:
   - **Ortak olaylar:** başlangıç zamanı farkı (algılama süresi), vektör sınıflandırması, önerilen mitigasyon.
   - **Yalnızca bir üründe görülen olaylar:** her biri NOC tarafından "gerçek saldırı" veya "yanlış alarm" olarak işaretlenir.
   - **Kaçan saldırılar:** upstream veya müşteri şikâyetiyle doğrulanan ama ürünün yakalamadığı olaylar.
5. Kontrollü test için `ddos-sim` ile her iki collector'a aynı senaryoları gönderin (ağınızda gerçek saldırı trafiği üretmez):

```bash
go run ./cmd/ddos-sim -collector <ddosd>:2055 -prefixes <test-prefix> -scenario dns_amp,carpet_ntp,syn_flood -target <test-ip> -duration 2m
```

ddosd, 4. adımdaki olay listesini CSV olarak verir (Saldırılar → CSV indir; `GET /api/v1/incidents/export.csv`).

---

## 6. Sınırlamalar

- Trafik sentetiktir. Gerçek ağlardaki trafik çeşitliliği, yanlış alarm oranını bu ölçümden yüksek gösterebilir; saha değeri gölge modda ölçülmelidir.
- Algılama süreleri simüle export ile ölçüldü; gerçek router'larda export zamanlaması ve ağ gecikmesi birkaç saniye ekleyebilir.
- Kapasite ölçümü bir dizüstü bilgisayarda loopback üzerinden yapıldı. Üretim NIC'i, çekirdek ayarları (`rmem_max`) ve çok exporter'lı yük farklı sonuç verir.
- GenieATM değerleri üretici beyanıdır ve bu çalışmada doğrulanmamıştır.

## 7. Tekrarlama

```bash
go run ./cmd/ddos-bench detect -json detect.json
go run ./cmd/ddos-bench baseline -baseline-minutes 120 -phases 6 -json baseline.json
go run ./cmd/ddos-bench throughput -json throughput.json
make fuzz
```

GenieATM bilgilerinin kaynakları: Genie Networks ürün sayfaları ve broşürleri ([genie-networks.com](https://www.genie-networks.com/)), CYBERSEC 2026 etkinlik notu, eski bir Huawei teklif dokümanındaki model değerleri, Gartner Peer Insights (3 değerlendirme).
