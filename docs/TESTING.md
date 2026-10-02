# Kendi ağınızda test etme

Önerilen sıra: **demo → simülatörle uzak test → gerçek exporter (gölge mod) → BGP lab → canlı.** Hiçbir adım ağınızda gerçek saldırı trafiği üretmez. Simülatör, yalnızca saldırıyı *anlatan* flow kayıtları gönderir.

## 1. Demo (5 dakika, tek makine)

```bash
go run ./cmd/ddosd -config config.demo.yaml
# veya: make run-demo
```

1. `http://localhost:8090` adresini açın. Baseline trafik otomatik başlar.
2. **Simülatör** sayfasından senaryo başlatın. Beklenen sonuçlar:

| Senaryo | Beklenen | Süre |
|---|---|---|
| DNS Amplification | `amp_dns` + `udp_fragment_flood` (+ `udp_flood_host`) olayı, FlowSpec `sport 53, boy ≥512 → discard` önerisi | ~5–8 sn |
| Carpet Bombing — NTP | `carpet_amplification` (prefix /24), host kuralları **tetiklenmez** | ~8–12 sn |
| TCP SYN Flood | `tcp_syn_flood`, aksiyon **scrubbing** (discard değil) | ~5 sn |
| Outbound: Açık NTP Yansıtıcı | outbound `out_reflector_misc`, FlowSpec kaynak /32 | ~8 sn |
| Eşik Altı DNS Amp | olay **yok**, `near_threshold` aday sinyali → AI Analist | ~5 sn |
| Az Kaynaklı Yüksek Hacim | olay **yok**, `conditions_unmet` sinyali ("benzersiz kaynak 6 < 20") | ~5 sn |
| Yavaş Yükselen UDP | baseline öğrenildikten sonra (demo: 3 dk) `baseline_deviation` | 3–5 dk |

3. **AI Analist → "Bekleyen sinyalleri analiz et"** ile bulgu üretin. Bulgu sayfasında önerileri ("Onay kuyruğuna gönder" veya "Eşiği uygula") deneyin.
4. **Mitigasyon** sayfasında talepleri onaylayın veya reddedin. Sürücü `dryrun` olduğu için yalnızca loglanır.

Farklı telemetri formatlarını denemek için `config.demo.yaml` → `demo.encoder: sflow` ve `sampling_rate: 1000` yapın.

## 2. Simülatörle uzak test

ddosd'yi gerçek sunucunuza kurun (Docker veya binary), ardından başka bir makineden simülatörü çalıştırın:

```bash
go run ./cmd/ddos-sim -list
go run ./cmd/ddos-sim -collector 10.0.0.50:2055 -prefixes 203.0.113.0/24 \
  -scenario dns_amp,syn_flood -target 203.0.113.10 -duration 2m
go run ./cmd/ddos-sim -collector 10.0.0.50:6343 -encoder sflow -sampling 1000 \
  -prefixes 203.0.113.0/24 -scenario carpet_ntp -target 203.0.113.0/24
```

Simülatör makinesi **Telemetri Kaynakları** sayfasında ayrı bir exporter olarak görünür. Bu adım; UDP yolunu, firewall'ı, örnekleme ölçeklemesini ve kural eşiklerini kendi prefixlerinizle doğrular.

## 3. Gerçek exporter: gölge mod (1–2 hafta)

1. `config.example.yaml` dosyasını `config.yaml` olarak kopyalayın. Prefixlerinizi ve profilleri girin, `mitigation.mode: manual` ve `driver: dryrun` olarak bırakın. `never_mitigate` listesine resolver'larınızı, router loopback'lerinizi ve upstream peering IP'lerinizi ekleyin.
2. Tek bir edge router'ı yönlendirin (bkz. [ROUTER-CONFIG.md](ROUTER-CONFIG.md)).
3. **Telemetri Kaynakları** sayfasını kontrol edin:
   - Örnekleme oranı doğru mu? Router'ın gerçek oranıyla aynı olmalı.
   - "Şablonsuz set" sadece açılışta mı artıyor?
   - "Kayıp" sıfır mı?
   - **Genel Bakış**'taki inbound trafik, router arayüz sayaçlarıyla (SNMP) ±%10 içinde mi?
4. Gölge modda olayları ve aday sinyalleri izleyin. Yanlış alarm gördüğünüzde önce **profil** atayın (`dns_server`, `web`, `gaming`, `vpn_gateway`), sonra kural bazlı eşik ayarlayın. Bu sırada **Korunan Nesneler → Hedef analizi** ekranından yararlanın.
5. Kabul kriterleri:
   - 1 hafta boyunca operatörün "gerçek değil" dediği yüksek önemli olay sayısı 0 olmalı.
   - Simülatör senaryolarının hepsi beklenen sürede yakalanmalı.

## 4. BGP lab

1. Lab router veya route reflector'a ExaBGP oturumu kurun (`deploy/exabgp/exabgp.conf`). Compose ile `--profile bgp` kullanabilirsiniz.
2. `mitigation.driver: exabgp` yapın. Simülatörle bir olay üretip mitigasyonu onaylayın.
3. Router'da kuralın kurulduğunu doğrulayın: `show route table inetflow.0` veya `show flowspec ipv4 detail`.
4. Ardından geri çekme yolunu test edin: "Geri çek" düğmesi, TTL dolması ve olay bitiminden `withdraw_after` sonra otomatik geri çekme.
5. FlowSpec'in gerçek trafikteki etkisini yalnızca **izole bir lab ortamında**, kontrollü trafik üreteçleriyle (ör. TRex, iperf3) doğrulayın.

## 5. Canlıya geçiş

- `mode: manual` ile başlayın. NOC her talebi onaylar.
- Güvendiğiniz vektörler için (memcached, CharGEN, GRE gibi hiç meşru olmayanlar) `auto` moda geçmeyi değerlendirin. RTBH ve AI önerileri `auto` modda bile onay ister.
- `max_active`, `default_ttl` ve `withdraw_after` değerlerini ağınıza göre ayarlayın.

## 6. AI analist

| Adım | Ayar | Not |
|---|---|---|
| Başlangıç | `provider: heuristic` | LLM gerektirmez; şablon tabanlı bulgu üretir |
| Claude API (demo/değerlendirme) | `provider: anthropic` + `ANTHROPIC_API_KEY` | Sentetik veya anonimleştirilmiş veriyle kullanın |
| Yerel LLM | `provider: openai_compat`, `base_url: http://localhost:11434/v1` (Ollama) veya vLLM | Veri ağ dışına çıkmaz |

Ayrıntılar için: [AI-ANALYST.md](AI-ANALYST.md).

## Otomatik testler

```bash
go test ./...          # decoder round-trip, kural eşleşmeleri, motor senaryoları, FlowSpec render, analist doğrulama
cd web && npm run build
```
