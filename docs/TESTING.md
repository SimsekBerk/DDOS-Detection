# Kendi ağınızda test etme

Önerilen sıra: **demo → simülatörle uzak test → gerçek exporter (gölge mod) → BGP lab → canlı.** Hiçbir adım ağınızda gerçek saldırı trafiği üretmez. Simülatör, yalnızca saldırıyı *anlatan* flow kayıtları gönderir.

## 1. Demo (5 dakika, tek makine)

```bash
go run ./cmd/ddosd -config config.demo.yaml
# veya: make run-demo
```

1. `http://localhost:8090` adresini açın ve `admin` kullanıcısıyla giriş yapın. Parola ilk açılışta `data-demo/initial-admin-password.txt` dosyasına yazılır (`cat data-demo/initial-admin-password.txt`). Baseline trafik otomatik başlar.
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

3. **AI analist → "Sinyalleri analiz et"** ile bulgu üretin. Bulgu sayfasında önerileri ("Onay kuyruğuna gönder" veya "Eşiği uygula") deneyin.
4. **Mitigasyon** sayfasında talepleri onaylayın veya reddedin. Sürücü `dryrun` olduğu için yalnızca loglanır.
5. **Ayarlar → Bildirimler** ekranından bir kanal ekleyip "Test gönder" ile deneyin; **Ayarlar → Kullanıcılar** ekranından NOC (operator) ve müşteri (kapsamlı viewer) hesapları açın.

Farklı telemetri formatlarını denemek için `config.demo.yaml` → `demo.encoder: sflow` ve `sampling_rate: 1000` yapın.

## 1b. Gerçek trafikle preprod (bu makine)

Demo sentetik trafikle çalışır. Gerçek trafiği görmek için ürünün pasif paket sensörü `ddos-probe`, bu makinenin ağ arayüzünü dinler. Paketleri bir router'ın flow önbelleği gibi flow'lara toplar ve IPFIX olarak ddosd'ye gönderir. Böylece decoder, motor ve arayüz gerçek veriyle çalışır.

```bash
cp config.preprod.example.yaml config.preprod.yaml   # alt ağı ve ağ geçidini girin (route -n get default; ifconfig en0)
make build
./bin/ddosd -config config.preprod.yaml              # http://127.0.0.1:8092, parola: data-preprod/initial-admin-password.txt
./bin/ddos-probe -i en0 -collector 127.0.0.1:9995    # ayrı bir terminalde
```

- **İzin:** Probe macOS'ta `/dev/bpf*` okuma yetkisi ister. Wireshark kuruluysa kullanıcı `access_bpf` grubundadır ve sudo gerekmez; değilse `sudo` ile çalıştırın. Linux'ta softflowd/pmacct veya router export kullanın.
- **Ne görür:** Switch'li ve Wi-Fi ağlarda bir makine yalnızca kendi trafiğini ve broadcast/multicast'i görür; diğer cihazların trafiğini görmez. Probe varsayılan olarak promiscuous modda çalışmaz. `-promisc` seçeneğini yalnızca izlemeye yetkili olduğunuz bir mirror (SPAN) portunda kullanın.
- **Tüm ağı görmek için:** Ağ geçidinin, firewall'un veya core switch'in NetFlow/IPFIX/sFlow export'unu bu makineye, UDP 9995'e yönlendirin (ağ yöneticisi yetkisi gerekir). Ağ geçidinin adresini `collector.allow` listesine ekleyin.
- **Doğruluk kontrolü:** Ağ geçidine sayısı bilinen ping gönderin, ör. `ping -c 200 -i 0.1 -s 1000 <ağ-geçidi>`. Trafik gezgininde hedef = ağ geçidi, protokol = icmp filtresiyle tam 200 paket ve 205.600 bayt görünmelidir. Arayüz sayaçlarıyla (`netstat -ibn -I en0`) toplam karşılaştırmada fark, Ethernet başlıkları ve flow export zamanlaması kadardır (%3–10).
- Preprod yapılandırması mitigasyonu `manual` + `dryrun` tutar: öneriler oluşur, hiçbir kural router'a gönderilmez.

## 2. Simülatörle uzak test

ddosd'yi gerçek sunucunuza kurun (Docker veya binary), ardından başka bir makineden simülatörü çalıştırın:

```bash
go run ./cmd/ddos-sim -list
go run ./cmd/ddos-sim -collector 10.0.0.50:2055 -prefixes 203.0.113.0/24 \
  -scenario dns_amp,syn_flood -target 203.0.113.10 -duration 2m
go run ./cmd/ddos-sim -collector 10.0.0.50:6343 -encoder sflow -sampling 1000 \
  -prefixes 203.0.113.0/24 -scenario carpet_ntp -target 203.0.113.0/24
```

Simülatör makinesi **Ayarlar → Telemetri** ekranında ayrı bir exporter olarak görünür. Bu adım; UDP yolunu, firewall'ı, örnekleme ölçeklemesini ve kural eşiklerini kendi prefixlerinizle doğrular.

## 3. Gerçek exporter: gölge mod (1–2 hafta)

1. `config.example.yaml` dosyasını `config.yaml` olarak kopyalayın. Prefixlerinizi ve profilleri girin, `mitigation.mode: manual` ve `driver: dryrun` olarak bırakın. `never_mitigate` listesine resolver'larınızı, router loopback'lerinizi ve upstream peering IP'lerinizi ekleyin.
2. Tek bir edge router'ı yönlendirin (bkz. [ROUTER-CONFIG.md](ROUTER-CONFIG.md)).
3. **Ayarlar → Telemetri** ekranını kontrol edin:
   - Örnekleme oranı doğru mu? Router'ın gerçek oranıyla aynı olmalı.
   - "Şablonsuz set" sadece açılışta mı artıyor?
   - "Kayıp" sıfır mı?
   - **Genel Bakış**'taki inbound trafik, router arayüz sayaçlarıyla (SNMP) ±%10 içinde mi?
4. Gölge modda olayları ve aday sinyalleri izleyin. Yanlış alarm gördüğünüzde önce **profil** atayın (`dns_server`, `web`, `gaming`, `vpn_gateway`), sonra kural bazlı eşik ayarlayın. Bu sırada **Trafik gezgini → Hedef analizi** ekranından yararlanın. Profil ve eşik değişikliklerini **Ayarlar** üzerinden yapın; her değişiklik sürümlenir ve geri alınabilir.
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
make test          # go test ./...
make test-race     # go test -race -short ./...
make fuzz          # decoder'ı 60 sn rastgele/bozuk paketlerle zorlar
cd web && npm run build   # TypeScript tip kontrolü + üretim derlemesi
```

Kapsam:

| Paket | Ne test ediliyor |
|---|---|
| `decoder` | NetFlow v5/v9, IPFIX, sFlow round-trip; IPFIX options template ile örnekleme; bozuk paketler; fuzz |
| `rules` | gönderilen kural setinin yüklenmesi, eşleşmeler, profil ölçekleme, kurallar arası alt küme/ayrıklık ilişkileri |
| `engine` | DNS amp algılama ve bitiş, sustain, koşul sağlanmadı sinyali, carpet bombing, eşzamanlı farklı carpet saldırıları, baseline sapması, öğrenme dönemi sinyalleri |
| `collector` | UDP alım + decode, flow yönlendirme (replikasyon), izin listesi ve canlı güncellenmesi |
| `mitigation` | kanıttan FlowSpec üretimi, vendor çıktıları, FlowSpec doğrulaması |
| `analyst` | bulgu (submit_finding) doğrulaması, araç şemaları |
| `auth`, `audit` | bootstrap, giriş, kaba kuvvet engeli, roller, kapsam, token'lar, son yönetici koruması, parola sıfırlama; denetim kaydı |
| `notify` | kanallara teslim, önem/olay filtreleme, HMAC imzası |
| `config`, `app` | örnek yapılandırmalar, doğrulama mesajları, YAML gidiş-dönüş, gizli alan maskeleme, salt okunur dizinde yazma |
| `api` | RBAC + CSRF, kiracı kapsamı ve token'lar, yapılandırmanın canlı uygulanması ve geri yüklenmesi, yeniden başlatma uyarısının geri alınması, metrikler ve dışa aktarma, bildirim testi |
| `bench` | seçili senaryoların regresyon testi (algılama + bitiş) ve normal trafikte yanlış alarm testi |

## Doğruluk ve kapasite ölçümü (`ddos-bench`)

```bash
go run ./cmd/ddos-bench detect                     # 27 senaryo × 4 telemetri: algılama, algılama süresi, bitiş
go run ./cmd/ddos-bench baseline -baseline-minutes 120 -phases 6   # yalnızca normal trafik: yanlış alarm
go run ./cmd/ddos-bench throughput                 # decode, motor ve UDP uçtan uca kapasite
go run ./cmd/ddos-bench sizing -network-pps 330e6 -sampling 1000 -prefixes 2000 -hosts 100000 -rate 330000
                                                   # operatör ölçeği: doluluk, değerlendirme süresi, bellek (+ -attack-pps 300e6)
go run ./cmd/ddos-bench all -json sonuc.json       # hepsi + JSON çıktı
```

Senaryolar simüle saatle, gerçek decoder ve motor üzerinden çalışır; router flow önbelleğinin active/inactive timeout davranışı taklit edilir. Bu yüzden 2 saatlik bir yanlış alarm testi birkaç saniye sürer. Son sonuçlar ve GenieATM karşılaştırması: [BENCHMARK.md](BENCHMARK.md).
