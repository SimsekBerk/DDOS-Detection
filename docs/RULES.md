# Kural setleri

`rules/` dizinindeki YAML dosyaları, **L7 hariç tüm L3/L4 DDoS vektörlerini** kapsayan 52 kural ve 8 koruma profili içerir. Kurallar açılışta yüklenir. UI'daki "Diskten yeniden yükle" düğmesiyle ya da `POST /api/v1/rules/reload` ile süreç durdurulmadan yeniden okunur.

| Dosya | İçerik |
|---|---|
| `00-profiles.yaml` | Profiller: eşik ölçekleri, kapatılan kurallar, kural bazlı ayarlar |
| `10-reflection-amplification.yaml` | DNS, NTP, SSDP, memcached, CLDAP, SNMP, CharGEN/QOTD, NetBIOS/Portmap/MSSQL, WS-Discovery/ARMS/CoAP, SLP/mDNS/Ubiquiti/DHDiscover/TFTP/Jenkins, BACnet/IPMI/NAT-PMP/Plex/Lantronix/XDMCP/RIPv1, STUN; ayrıca bilinmeyen yansıtma vektörleri için genel bir kural |
| `20-tcp.yaml` | SYN, SYN-ACK yansıtma, ACK, RST, ACK'siz FIN, NULL, XMAS/SYN+FIN, PSH-ACK, bağlantı seli, genel TCP; BGP/kontrol düzlemi |
| `30-udp-icmp.yaml` | Genel UDP, küçük paketli UDP (pps), QUIC/UDP-443, DNS sorgu seli; ICMP echo/echo-reply, BlackNurse, büyük ICMP, genel ICMP |
| `40-fragment-ipproto.yaml` | UDP/TCP/genel fragment; GRE, ESP/AH, alışılmadık IP protokolleri |
| `50-carpet-volumetric.yaml` | Carpet bombing (amp/UDP/SYN/ICMP/fragment, prefix kapsamı); host ve nesne toplamı |
| `60-outbound.yaml` | Açık DNS ve diğer UDP yansıtıcılar, outbound UDP/SYN/ICMP flood |

## Kurallar hangi en iyi uygulamalara göre yazıldı

1. **Vektöre özel imza.** Yansıtma saldırıları *kaynak* porta göre eşleşir; hedef port rastgeledir. TCP floodları flag kombinasyonuyla ayrılır: "sadece SYN", "SYN+ACK", "sadece ACK" ve benzerleri. Paket boyu koşulları, imzaya uymayan meşru trafiği dışarıda bırakır. Örnek: NTP monlist cevabı 468 byte iken normal NTP paketi 76–90 byte'tır.
2. **Örnekleme farkındalığı.** Eşikler, örnekleme oranıyla ölçeklenmiş *tahmini gerçek* trafik üzerinden değerlendirilir. `min_samples` (varsayılan 3) yetersiz örnekle karar verilmesini engeller.
3. **Çift tetik.** Statik eşik *veya* dinamik baseline (`factor × EWMA`, `min_pps`/`min_bps` tabanıyla) tetikler. Küçük baseline'larda yanlış alarmı taban değerler önler. Saldırı sırasında baseline öğrenmesi durur, aykırı değerler kırpılır (μ+3σ).
4. **Doğrulama koşulları.** Yansıtma için `min_unique_sources` aranır: binlerce yansıtıcı tek bir meşru sunucudan ayrılır. Carpet bombing için `min_unique_destinations` aranır: tek hosta yönelik saldırı prefix kuralını tetiklemez. Koşulu sağlanmayan tetikler kaybolmaz; AI analiste `conditions_unmet` sinyali olarak iletilir.
5. **Histerezis.**
   - Başlangıç: pencere ortalaması `sustain` değerlendirme boyunca üst üste eşiği aşmalı **ve** pencerede en az 2 ayrı saniyede trafik görülmeli. Böylece kayan pencerede kalan tek bir sıçrama tetik üretmez; NetFlow/IPFIX'in toplu (bursty) export'u ise doğru sayılır.
   - Bitiş: `hold_down` süresince eşiğin %70'inin altında kalmalı.
6. **Kapsam.**
   - `host`: tek IP.
   - `prefix`: carpet bombing, varsayılan /24 ve /64.
   - `object`: müşterinin tamamı.

   Aynı hedefe gelen tüm vektörler tek olayda toplanır.

   **Genel kurallar ve korelasyon.** `generic: true` işaretli kurallar ("hosta tüm UDP", "nesneye toplam trafik" gibi) güvenlik ağıdır. Aynı saldırıyı daha özel bir kural zaten yakaladıysa ve o vektörler trafiğin en az %70'ini açıklıyorsa genel vektör ayrıca raporlanmaz. Bir vektör yalnızca kendi trafiği diğer kuralın trafiğinin alt kümesiyse onu açıklayabilir: DNS amplifikasyonu "tüm UDP"yi açıklar, carpet SYN ise carpet UDP amplifikasyonunu açıklamaz. Böylece aynı /24'e eşzamanlı gelen farklı türdeki saldırılar ayrı vektörler olarak görünür.
7. **En dar mitigasyon.**
   - Spoof'lu saldırılarda FlowSpec kaynak IP kullanmaz; hedef /32, protokol, kaynak port ve paket boyu kullanılır.
   - SYN, ACK, PSH-ACK, QUIC ve DNS sorgu seli gibi meşru trafiğe benzeyen vektörlerde aksiyon **scrubbing**'dir. Discard servisi keser, yani saldırganın işini yapar.
   - ICMP ve fragment için tamamen kapatmak yerine **rate-limit** uygulanır, çünkü PMTUD ve EDNS bunlara ihtiyaç duyar.
   - RTBH yalnızca host kapsamında, bağlantı kapasitesinin belirli bir yüzdesi aşıldığında ve her zaman manuel onayla uygulanır.
8. **Profil.** Tek bir global eşik hem bir DNS resolver'ı hem de bir ev kullanıcısı için doğru olamaz. Nesne tipine göre profil seçin; kural bazlı istisnalar profil içinde tanımlanır.
9. **Flow bayrak semantiği.** NetFlow/IPFIX kayıtlarında TCP bayrakları bağlantı boyunca birleşir (OR); sFlow ise tek tek paket örnekler. Tamamlanmış normal bir bağlantı `SYN|ACK|PSH|FIN` görünür. Bayrak tabanlı kurallar bu yüzden saldırının *taşımadığı* bayrakları da belirtir: sahte SYN, XMAS ve FIN paketleri ACK taşımaz, RST seli SYN/PSH taşımaz, yansıtılan SYN-ACK veri (PSH) taşımaz. `TestNormalConnectionFlagsAreNotAttacks` testi normal bağlantı bayraklarının hiçbir saldırı kuralına uymadığını doğrular.
10. **Açıklanabilirlik.** Her kuralda `rationale`, `false_positives` ve `references` alanları bulunur. Olay ekranında tetik nedeni ölçümüyle birlikte gösterilir, örneğin "bps 649Mbps ≥ eşik 400Mbps".

## Kural şeması

```yaml
- id: amp_ntp                       # tekil kimlik
  name: NTP Amplification (monlist)
  category: reflection_amplification
  description: ...
  direction: inbound                # inbound | outbound
  scope: host                       # host | prefix | object
  generic: false                    # true: genel güvenlik ağı kuralı (özel vektörler açıklıyorsa bastırılır)
  severity: high                    # low | medium | high | critical
  enabled: true
  match:
    protocols: [udp]                # isim veya numara; not_protocols da var
    src_ports: ["123"]              # "53", "1024-65535"
    dst_ports: []
    tcp_flags: { all: [syn], none: [ack], any: [], empty: false }
    icmp_types: [8, 128]
    icmp_codes: []
    fragment: true|false
    min_packet_size: 200            # flow kaydının ortalama paket boyu
    max_packet_size: 0
    ip_version: 0                   # 4 | 6 | 0 (hepsi)
  thresholds: { pps: 10k, bps: 100Mbps, fps: 0 }      # HERHANGİ biri
  baseline: { enabled: true, factor: 8, min_pps: 2k, min_bps: 20Mbps }
  conditions:
    min_unique_sources: 10
    min_unique_destinations: 0      # prefix/object kapsamı
    min_avg_packet_size: 200
    max_avg_packet_size: 0
    min_samples: 3
  trigger: { sustain: 3s, hold_down: 60s }
  mitigation:
    action: flowspec-discard        # flowspec-discard | flowspec-rate-limit | scrub | rtbh | alert
    rate: 0                         # rate-limit için bps
    packet_length: true             # match.min_packet_size'ı FlowSpec'e ekle
    rtbh_escalation: 0.8            # tepe bps ≥ link_capacity × 0.8 → RTBH önerisi (onaylı)
    note: ...
  rationale: ...
  false_positives: ...
  references: [...]
```

Efektif eşik şöyle hesaplanır: `kural eşiği × profil.scale × profil.overrides[kural].scale`. Override içinde `pps`, `bps` veya `fps` verilirse doğrudan o değer kullanılır. UI'dan yapılan eşik değişiklikleri ve aç/kapa işlemleri `data/rule_overrides.json` dosyasına yazılır, YAML dosyalarına dokunulmaz.

## Ayarlama (tuning) önerileri

1. **İlk 1–2 hafta "gölge mod"da çalışın:** `mitigation.mode: manual`, `driver: dryrun`. Olaylara ve aday sinyallere bakın.
2. **Yanlış alarm görürseniz:** önce profili düzeltin. Örneğin resolver'ları `dns_server`, tünel uçlarını `vpn_gateway` profiline alın. Global eşiği yükseltmek son çaredir.
3. **"Korunan Nesneler → Hedef analizi"** ekranı bir IP için tüm kuralların oranını, baseline'ını ve koşul durumunu gösterir. "Neden tetiklenmedi?" sorusunun cevabı buradadır.
4. **AI analistin `threshold_change` önerileri** gözlenen tepe değere göre gerekçelendirilir ve tek tıkla uygulanabilir. Uygulanan değişiklik override olarak saklanır ve geri alınabilir.

## Kapsam dışı (L7)

HTTP flood'lar, Slowloris/RUDY, TLS renegotiation, DNS water torture (rastgele alt alan adı) ve uygulama mantığı saldırıları flow verisiyle güvenilir şekilde ayrılamaz. Bunlar için WAF, reverse proxy veya DNS'e özel koruma (RRL, NXDOMAIN analizi) gerekir. `udp_dns_query_flood`, `udp_quic_flood` ve `tcp_conn_flood` bu saldırıların yalnızca **L4 hacim** belirtisini yakalar.

## Katalog

### Yansıma / Amplifikasyon (13)

| Kural | Eşleşme | Kapsam | Eşik (temel) | Baseline | Koşullar | Sustain / hold | Aksiyon |
|---|---|---|---|---|---|---|---|
| `amp_dns`<br>DNS Amplification | `proto=udp sport=53 pkt>=512` | inbound/host | 20kpps · 200Mbps | ×8 (min 5kpps / 50Mbps) | ≥20 kaynak, ort ≥512B | 3s / 60s | FlowSpec discard (RTBH eskalasyon %80) |
| `amp_ntp`<br>NTP Amplification (monlist) | `proto=udp sport=123 pkt>=200` | inbound/host | 10kpps · 100Mbps | ×8 (min 2kpps / 20Mbps) | ≥10 kaynak, ort ≥200B | 3s / 60s | FlowSpec discard (RTBH eskalasyon %80) |
| `amp_ssdp`<br>SSDP Amplification | `proto=udp sport=1900` | inbound/host | 10kpps · 100Mbps | — | ≥20 kaynak | 3s / 60s | FlowSpec discard (RTBH eskalasyon %80) |
| `amp_memcached`<br>Memcached Amplification | `proto=udp sport=11211` | inbound/host | 1kpps · 20Mbps | — | ≥3 kaynak | 2s / 120s | FlowSpec discard (RTBH eskalasyon %50) |
| `amp_cldap`<br>CLDAP Amplification | `proto=udp sport=389` | inbound/host | 5kpps · 50Mbps | — | ≥10 kaynak | 3s / 60s | FlowSpec discard (RTBH eskalasyon %80) |
| `amp_snmp`<br>SNMP Amplification | `proto=udp sport=161` | inbound/host | 5kpps · 50Mbps | — | ≥10 kaynak | 3s / 60s | FlowSpec discard (RTBH eskalasyon %80) |
| `amp_chargen_qotd`<br>CharGEN / QOTD Amplification | `proto=udp sport=19,17` | inbound/host | 2kpps · 20Mbps | — | ≥5 kaynak | 3s / 60s | FlowSpec discard (RTBH eskalasyon %80) |
| `amp_netbios_rpc`<br>NetBIOS / Portmap / MSSQL Amplification | `proto=udp sport=137,111,1434` | inbound/host | 5kpps · 50Mbps | — | ≥10 kaynak | 3s / 60s | FlowSpec discard (RTBH eskalasyon %80) |
| `amp_wsd_arms`<br>WS-Discovery / ARMS / CoAP Amplification | `proto=udp sport=3702,3283,5683` | inbound/host | 5kpps · 50Mbps | — | ≥10 kaynak | 3s / 60s | FlowSpec discard (RTBH eskalasyon %80) |
| `amp_discovery_misc`<br>Keşif Protokolü Amplification (SLP/mDNS/Ubiquiti/DHDiscover/TFTP) | `proto=udp sport=427,5353,10001,37810,69,33848` | inbound/host | 5kpps · 50Mbps | — | ≥10 kaynak | 3s / 60s | FlowSpec discard (RTBH eskalasyon %80) |
| `amp_misc_udp`<br>Diğer UDP Yansıtıcılar (BACnet/IPMI/NAT-PMP/Plex/Lantronix/XDMCP/RIPv1) | `proto=udp sport=47808,623,5351,32414,30718,177,520` | inbound/host | 5kpps · 50Mbps | — | ≥10 kaynak | 3s / 60s | FlowSpec discard (RTBH eskalasyon %80) |
| `amp_stun`<br>STUN / TURN Amplification | `proto=udp sport=3478` | inbound/host | 20kpps · 200Mbps | ×6 (min 5kpps / 50Mbps) | ≥50 kaynak | 5s / 60s | FlowSpec rate-limit 20Mbps (RTBH eskalasyon %80) |
| `amp_generic_lowport`<br>Bilinmeyen UDP Yansıtma (düşük kaynak port) | `proto=udp sport=1-1023` | inbound/host | 50kpps · 500Mbps | ×6 (min 10kpps / 100Mbps) | ≥100 kaynak, ort ≥400B | 5s / 60s | Scrubbing (RTBH eskalasyon %80) |

### TCP (10)

| Kural | Eşleşme | Kapsam | Eşik (temel) | Baseline | Koşullar | Sustain / hold | Aksiyon |
|---|---|---|---|---|---|---|---|
| `tcp_syn_flood`<br>TCP SYN Flood | `proto=tcp tcp=+syn !ack!rst!fin pkt<=120` | inbound/host | 50kpps · 300Mbps | ×6 (min 10kpps) | — | 3s / 60s | Scrubbing (RTBH eskalasyon %80) |
| `tcp_synack_reflection`<br>TCP SYN-ACK Reflection Flood | `proto=tcp tcp=+syn+ack !rst!fin!psh pkt<=120` | inbound/host | 30kpps · 200Mbps | — | ≥50 kaynak | 3s / 60s | FlowSpec rate-limit 10Mbps (RTBH eskalasyon %80) |
| `tcp_ack_flood`<br>TCP ACK Flood | `proto=tcp tcp=+ack !syn!fin!rst!psh pkt<=100` | inbound/host | 300kpps · 1Gbps | ×6 (min 50kpps) | ≥100 kaynak | 5s / 60s | Scrubbing (RTBH eskalasyon %80) |
| `tcp_rst_flood`<br>TCP RST Flood | `proto=tcp tcp=+rst !syn!psh` | inbound/host | 20kpps · 100Mbps | ×8 (min 5kpps) | ≥20 kaynak | 3s / 60s | FlowSpec rate-limit 5Mbps (RTBH eskalasyon %80) |
| `tcp_fin_flood`<br>TCP FIN Flood (ACK'siz) | `proto=tcp tcp=+fin !ack` | inbound/host | 10kpps · 50Mbps | — | — | 3s / 60s | FlowSpec discard (RTBH eskalasyon %80) |
| `tcp_invalid_flags`<br>TCP NULL Paketleri (flag yok) | `proto=tcp tcp=none` | inbound/host | 5kpps · 20Mbps | — | — | 3s / 60s | FlowSpec discard |
| `tcp_xmas_synfin`<br>TCP XMAS / SYN+FIN | `proto=tcp tcp=+fin !ack any(syn,urg)` | inbound/host | 2kpps · 10Mbps | — | — | 3s / 60s | FlowSpec discard |
| `tcp_psh_ack_flood`<br>TCP PSH-ACK Flood | `proto=tcp tcp=+psh+ack !syn` | inbound/host | 500kpps · 4Gbps | ×6 (min 100kpps / 1Gbps) | ≥200 kaynak | 10s / 60s | Scrubbing (RTBH eskalasyon %80) |
| `tcp_conn_flood`<br>TCP Bağlantı Seli (yeni flow oranı) | `proto=tcp tcp=+syn+ack any(psh,fin)` | inbound/host | 30kfps | — | — | 10s / 60s | Scrubbing |
| `tcp_flood_generic`<br>TCP Hacimsel Flood (genel) | `proto=tcp` | inbound/host | 1Mpps · 5Gbps | ×5 (min 100kpps / 1Gbps) | ≥50 kaynak | 10s / 90s | Scrubbing (RTBH eskalasyon %80) |

### Altyapı / Kontrol düzlemi (1)

| Kural | Eşleşme | Kapsam | Eşik (temel) | Baseline | Koşullar | Sustain / hold | Aksiyon |
|---|---|---|---|---|---|---|---|
| `infra_bgp_flood`<br>BGP / Kontrol Düzlemi Flood | `proto=tcp dport=179,22,830` | inbound/host | 5kpps · 20Mbps | — | ≥5 kaynak | 3s / 60s | Alarm |

### UDP (4)

| Kural | Eşleşme | Kapsam | Eşik (temel) | Baseline | Koşullar | Sustain / hold | Aksiyon |
|---|---|---|---|---|---|---|---|
| `udp_flood_host`<br>UDP Flood (genel) | `proto=udp` | inbound/host | 200kpps · 1Gbps | ×5 (min 30kpps / 200Mbps) | ≥20 kaynak | 5s / 60s | Scrubbing (RTBH eskalasyon %80) |
| `udp_small_packet_flood`<br>UDP Küçük Paket Flood (pps odaklı) | `proto=udp pkt<=128` | inbound/host | 150kpps | ×6 (min 30kpps) | ≥20 kaynak | 5s / 60s | Scrubbing (RTBH eskalasyon %80) |
| `udp_quic_flood`<br>UDP/443 (QUIC) Flood | `proto=udp dport=443` | inbound/host | 300kpps · 2Gbps | ×5 (min 50kpps / 500Mbps) | ≥50 kaynak | 5s / 60s | Scrubbing |
| `udp_dns_query_flood`<br>DNS Sorgu Seli (hedef port 53) | `proto=udp dport=53` | inbound/host | 100kpps · 300Mbps | ×5 (min 20kpps) | ≥50 kaynak | 5s / 60s | Scrubbing |

### ICMP (5)

| Kural | Eşleşme | Kapsam | Eşik (temel) | Baseline | Koşullar | Sustain / hold | Aksiyon |
|---|---|---|---|---|---|---|---|
| `icmp_echo_flood`<br>ICMP Echo Request Flood (Ping Flood) | `proto=icmp,icmpv6 icmp_type=[8 128]` | inbound/host | 20kpps · 100Mbps | ×10 (min 5kpps) | — | 5s / 60s | FlowSpec rate-limit 5Mbps (RTBH eskalasyon %80) |
| `icmp_echo_reply_flood`<br>ICMP Echo Reply Flood (Smurf / Yansıtma) | `proto=icmp,icmpv6 icmp_type=[0 129]` | inbound/host | 10kpps · 50Mbps | — | ≥20 kaynak | 5s / 60s | FlowSpec rate-limit 2Mbps (RTBH eskalasyon %80) |
| `icmp_unreachable_blacknurse`<br>ICMP Destination Unreachable Flood (BlackNurse) | `proto=icmp icmp_type=[3]` | inbound/host | 5kpps · 20Mbps | — | — | 3s / 60s | FlowSpec rate-limit 1Mbps |
| `icmp_large_packets`<br>Büyük ICMP Paketleri | `proto=icmp,icmpv6 pkt>=1000` | inbound/host | 5kpps · 50Mbps | — | — | 5s / 60s | FlowSpec rate-limit 2Mbps |
| `icmp_flood_generic`<br>ICMP Flood (genel) | `proto=icmp,icmpv6` | inbound/host | 50kpps · 200Mbps | ×10 (min 10kpps) | — | 5s / 60s | FlowSpec rate-limit 10Mbps (RTBH eskalasyon %80) |

### Fragment (3)

| Kural | Eşleşme | Kapsam | Eşik (temel) | Baseline | Koşullar | Sustain / hold | Aksiyon |
|---|---|---|---|---|---|---|---|
| `udp_fragment_flood`<br>UDP Fragment Flood | `proto=udp fragment=true` | inbound/host | 20kpps · 200Mbps | ×8 (min 5kpps / 50Mbps) | — | 3s / 60s | FlowSpec rate-limit 50Mbps (RTBH eskalasyon %80) |
| `tcp_fragment`<br>TCP Fragment'ları | `proto=tcp fragment=true` | inbound/host | 2kpps · 20Mbps | — | — | 3s / 60s | FlowSpec discard |
| `fragment_flood_any`<br>IP Fragment Flood (tüm protokoller) | `fragment=true` | inbound/host | 40kpps · 400Mbps | — | — | 5s / 60s | FlowSpec rate-limit 50Mbps (RTBH eskalasyon %80) |

### IP protokolü (3)

| Kural | Eşleşme | Kapsam | Eşik (temel) | Baseline | Koşullar | Sustain / hold | Aksiyon |
|---|---|---|---|---|---|---|---|
| `gre_flood`<br>GRE Flood | `proto=gre` | inbound/host | 20kpps · 200Mbps | — | — | 3s / 60s | FlowSpec discard (RTBH eskalasyon %80) |
| `esp_flood`<br>ESP / AH Flood | `proto=esp,ah` | inbound/host | 20kpps · 200Mbps | ×8 (min 5kpps) | — | 5s / 60s | FlowSpec rate-limit 20Mbps |
| `ipproto_unusual`<br>Alışılmadık IP Protokolü Flood | `proto!=tcp,udp,icmp,icmpv6,gre,esp,ah` | inbound/host | 5kpps · 50Mbps | — | — | 3s / 60s | FlowSpec discard |

### Carpet bombing (5)

| Kural | Eşleşme | Kapsam | Eşik (temel) | Baseline | Koşullar | Sustain / hold | Aksiyon |
|---|---|---|---|---|---|---|---|
| `carpet_amplification`<br>Carpet Bombing — UDP Amplifikasyon | `proto=udp sport=53,123,1900,11211,389,161,19,17,137,111,1434,3702,3283,5683,427,10001,37810,69,47808,623,5351,520` | inbound/prefix | 40kpps · 400Mbps | ×6 (min 10kpps / 100Mbps) | ≥30 kaynak, ≥16 hedef | 5s / 120s | FlowSpec discard |
| `carpet_udp`<br>Carpet Bombing — UDP Flood | `proto=udp` | inbound/prefix | 500kpps · 3Gbps | ×5 (min 100kpps / 1Gbps) | ≥50 kaynak, ≥16 hedef | 5s / 120s | Scrubbing |
| `carpet_syn`<br>Carpet Bombing — TCP SYN | `proto=tcp tcp=+syn !ack!rst!fin pkt<=120` | inbound/prefix | 150kpps | ×6 (min 30kpps) | ≥16 hedef | 5s / 120s | Scrubbing |
| `carpet_icmp`<br>Carpet Bombing — ICMP | `proto=icmp,icmpv6` | inbound/prefix | 100kpps · 400Mbps | — | ≥16 hedef | 5s / 120s | FlowSpec rate-limit 20Mbps |
| `carpet_fragments`<br>Carpet Bombing — Fragment | `fragment=true` | inbound/prefix | 60kpps · 600Mbps | — | ≥16 hedef | 5s / 120s | FlowSpec rate-limit 100Mbps |

### Hacimsel (vektörden bağımsız) (3)

| Kural | Eşleşme | Kapsam | Eşik (temel) | Baseline | Koşullar | Sustain / hold | Aksiyon |
|---|---|---|---|---|---|---|---|
| `total_host`<br>Hosta Toplam Trafik Aşımı | `all traffic` | inbound/host | 1.5Mpps · 8Gbps | ×6 (min 200kpps / 2Gbps) | — | 5s / 90s | Scrubbing (RTBH eskalasyon %90) |
| `total_object`<br>Nesneye Toplam Trafik Aşımı | `all traffic` | inbound/object | 40Gbps | ×4 (min 500kpps / 4Gbps) | — | 10s / 120s | Scrubbing |
| `total_object_udp`<br>Nesneye UDP Toplamı Aşımı | `proto=udp` | inbound/object | 20Gbps | ×5 (min 200kpps / 2Gbps) | — | 10s / 120s | Alarm |

### Outbound (giden) (5)

| Kural | Eşleşme | Kapsam | Eşik (temel) | Baseline | Koşullar | Sustain / hold | Aksiyon |
|---|---|---|---|---|---|---|---|
| `out_reflector_dns`<br>Açık DNS Yansıtıcı (outbound) | `proto=udp sport=53 pkt>=512` | outbound/host | 10kpps · 100Mbps | ×8 (min 2kpps) | ≥5 kaynak | 5s / 120s | FlowSpec rate-limit 10Mbps |
| `out_reflector_misc`<br>Açık UDP Yansıtıcı (NTP/SSDP/memcached/CLDAP/SNMP/CharGEN) | `proto=udp sport=123,1900,11211,389,161,19,17,3702,5683,427,37810,10001` | outbound/host | 5kpps · 50Mbps | — | ≥3 kaynak | 5s / 120s | FlowSpec discard |
| `out_udp_flood`<br>Outbound UDP Flood (botnet şüphesi) | `proto=udp` | outbound/host | 100kpps · 800Mbps | ×10 (min 20kpps) | — | 5s / 120s | FlowSpec rate-limit 10Mbps |
| `out_syn_flood`<br>Outbound SYN Flood | `proto=tcp tcp=+syn !ack` | outbound/host | 20kpps | ×10 (min 5kpps) | — | 5s / 120s | FlowSpec rate-limit 5Mbps |
| `out_icmp_flood`<br>Outbound ICMP Flood | `proto=icmp,icmpv6` | outbound/host | 20kpps · 100Mbps | — | — | 5s / 120s | FlowSpec rate-limit 2Mbps |

## Profiller

| Profil | Ölçek | Kapatılan | Kural bazlı ayar | Açıklama |
|---|---|---|---|---|
| `datacenter` | ×2 | — | — | Veri merkezi / hosting sunucuları. Yüksek meşru trafik. |
| `default` | ×1 | — | — | Genel amaçlı varsayılan profil (karışık sunucu/istemci trafiği). |
| `dns_server` | ×1.5 | — | `amp_dns` ×20, `out_reflector_dns` ×50, `udp_flood_host` ×3 | Yetkili veya özyinelemeli DNS sunucuları. |
| `gaming` | ×1.5 | — | `amp_stun` ×5, `udp_flood_host` ×4, `udp_small_packet_flood` ×4 | Oyun/VoIP sunucuları; yoğun UDP meşrudur. |
| `infrastructure` | ×0.2 | — | `infra_bgp_flood` ×5 | Router loopback/yönetim adresleri; kontrol düzlemi çok hassastır. |
| `residential` | ×0.5 | — | `tcp_ack_flood` ×2, `tcp_synack_reflection` ×3 | Ev/abone blokları. Sunucu servisi beklenmez; eşikler daha düşük. |
| `vpn_gateway` | ×1 | `gre_flood` | `esp_flood` ×20, `udp_fragment_flood` ×5 | IPsec/GRE tünel uç noktaları. |
| `web` | ×2 | — | `tcp_ack_flood` ×2, `tcp_conn_flood` ×3, `udp_quic_flood` ×3 | Web/CDN önü sunucular (TCP/80-443, QUIC/UDP-443). |
