# Üretimde işletim

Bu doküman ddosd'yi kendi ağınızda üretim ortamında çalıştırmak için gerekenleri anlatır: kurulum, erişim ve yetki, yapılandırma yönetimi, izleme, yedekleme ve sertleştirme. Adım adım devreye alma planı için [TESTING.md](TESTING.md), mimari için [ARCHITECTURE.md](ARCHITECTURE.md) dosyasına bakın.

## 1. Boyutlandırma

Ölçülen değerler (Apple M3 Pro, 11 çekirdek; ayrıntılar [BENCHMARK.md](BENCHMARK.md)):

| Bileşen | Ölçülen kapasite |
|---|---|
| Decode (tek çekirdek) | NetFlow v9 ~7,4M · IPFIX ~7,1M · sFlow ~10,8M kayıt/sn |
| Motor (tek çekirdek, 52 kural) | ~2,2M kayıt/sn |
| Uçtan uca UDP (tek exporter, loopback) | 2M kayıt/sn kayıpsız; ~2,6M kayıt/sn'de doyma |

Pratik öneriler:

| Ağ | Tahmini flow hızı | Sunucu |
|---|---|---|
| Kurumsal / küçük DC (≤ 40 Gbps, sFlow 1:2000) | < 50k kayıt/sn | 2 vCPU, 4 GB RAM |
| Bölgesel ISS (≤ 400 Gbps, 1:1000–1:4000) | 100–500k kayıt/sn | 4–8 vCPU, 8–16 GB RAM |
| Büyük operatör (çoklu PoP) | > 1M kayıt/sn | PoP başına bir ddosd veya [ARCHITECTURE.md](ARCHITECTURE.md) §2 shard'lı mimari |

Bellek büyük ölçüde flow halka tamponundan (`engine.recent_flows`, kayıt başına ~180 bayt; varsayılan 500k kayıt ≈ 90 MB) ve izlenen seri sayısından (`engine.max_series`) gelir.

Linux'ta UDP alım tamponunu büyütün:

```bash
sysctl -w net.core.rmem_max=33554432
sysctl -w net.core.rmem_default=8388608
```

`collector.read_buffer_bytes` değeri `rmem_max` değerinden büyük olamaz.

## 2. Kurulum

### Binary + systemd

```bash
make ui build                       # bin/ddosd, bin/ddos-sim, bin/ddos-bench
sudo install -m 755 bin/ddosd /usr/local/bin/
sudo useradd --system --home /var/lib/ddosd ddosd
sudo mkdir -p /etc/ddosd /var/lib/ddosd && sudo cp -r rules /etc/ddosd/
sudo cp config.example.yaml /etc/ddosd/config.yaml   # rules_dir: /etc/ddosd/rules, data_dir: /var/lib/ddosd
sudo chown -R ddosd /etc/ddosd /var/lib/ddosd
```

`/etc/systemd/system/ddosd.service`:

```ini
[Unit]
Description=ddosd DDoS detection
After=network-online.target

[Service]
User=ddosd
ExecStart=/usr/local/bin/ddosd -config /etc/ddosd/config.yaml -log-json
Restart=always
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/etc/ddosd /var/lib/ddosd /var/run/ddosd

[Install]
WantedBy=multi-user.target
```

Yapılandırma dizini ddosd kullanıcısı tarafından yazılabilir olmalıdır; arayüzden yapılan değişiklikler buraya kaydedilir.

### Docker

```bash
mkdir -p config && cp config.example.yaml config/config.yaml   # prefixleri düzenleyin
sudo chown -R 10001 config                                     # konteyner kullanıcısı
docker compose -f deploy/docker-compose.yml up -d
```

- `config/` dizini konteynerde `/etc/ddosd` olarak yazılabilir bağlanır. Tek dosya ve salt okunur bağlarsanız arayüz "yapılandırma dosyası yazılamıyor" uyarısı gösterir ve kaydetmeye izin vermez.
- Olaylar, kullanıcılar, denetim kaydı ve yapılandırma geçmişi `ddosd-data` volume'unda (`/data`) tutulur.
- Sağlık kontrolü `/readyz` adresini kullanır. API portu 8080 değilse `DDOSD_HTTP_PORT` ortam değişkenini ayarlayın.

## 3. İlk giriş ve parola kurtarma

- Kullanıcı deposu boşken (ilk açılış) `api.username` ile bir yönetici hesabı oluşturulur. `api.password` boşsa rastgele bir parola üretilir ve `<data_dir>/initial-admin-password.txt` dosyasına (0600) yazılır.
- İlk girişten sonra parolayı sağ üstteki kullanıcı menüsünden değiştirin ve dosyayı silin.
- Parola kaybolursa servisi durdurup şunu çalıştırın; yeni parola ekrana ve aynı dosyaya yazılır, o kullanıcının açık oturumları kapanır:

```bash
ddosd -config /etc/ddosd/config.yaml -reset-admin admin
```

## 4. Kullanıcılar, roller ve kiracılar

| Rol | Yetki |
|---|---|
| `viewer` | Tüm izleme ekranları, raporlar, CSV dışa aktarma |
| `operator` | + mitigasyon onay/ret/geri çekme, manuel FlowSpec, AI analizi çalıştırma, simülatör |
| `admin` | + ayarlar, kurallar, kullanıcılar, token'lar, denetim kaydı |

- **Nesne kapsamı (kiracı):** Kullanıcıya bir veya daha fazla korunan nesne atanırsa yalnızca o nesnelerin olaylarını, sinyallerini, flow'larını ve mitigasyonlarını görür. Exporter, simülatör ve sistem gibi altyapı ekranları kapsamlı kullanıcılara kapalıdır. MSSP müşterilerine salt okunur portal vermek için `viewer` + nesne kapsamı kullanın.
- **API token'ları:** Ayarlar → Kullanıcılar → kullanıcı → "Token oluştur". Token yalnızca bir kez gösterilir, sunucuda SHA-256 özeti saklanır. Kullanım: `Authorization: Bearer <token>`. Token, sahibinin rolü ve kapsamıyla çalışır; Prometheus için `viewer` rolünde ayrı bir kullanıcı açın.
- Son yönetici silinemez, pasifleştirilemez veya yetkisi düşürülemez.
- Aynı istemciden art arda hatalı girişler 10 dakika engellenir.

## 5. Yapılandırma yönetimi

Arayüzde **Ayarlar** bölümleri: Korunan nesneler, Algılama kuralları, Telemetri, Algılama motoru, Mitigasyon, Bildirimler, AI analist, Web ve API, Kullanıcılar, Denetim kaydı, Değişiklik geçmişi, Sistem.

- Değişiklikler tek bir taslakta toplanır; alttaki kaydetme çubuğu hangi bölümlerin değiştiğini gösterir. **Doğrula** sunucuda tam doğrulama yapar, **Kaydet ve uygula** yeni sürümü yazar ve canlı uygular.
- Her kayıt `data/config-history/` altında bir sürüm oluşturur (son 100). **Değişiklik geçmişi** ekranından herhangi bir sürüm görüntülenebilir veya geri yüklenebilir. Geri yükleme de yeni bir sürüm olarak kaydedilir.
- Gizli alanlar (parolalar, token'lar, HMAC anahtarları) arayüzde ve API'de `********` olarak döner; değiştirilmezse kayıtlı değer korunur.
- Yeniden başlatma gerektiren alanlar: `collector.listen`, `collector.workers`, `collector.read_buffer_bytes`, `collector.queue_size`, `collector.forward`, `api.listen`/TLS, `data_dir`, `rules_dir`, `engine.recent_flows`, `demo`. Bunlar kaydedilir ancak servis yeniden başlatılana kadar eski değerle çalışır; üst çubukta "Yeniden başlatma gerekli" uyarısı görünür.
- Kural eşik ve aç/kapa değişiklikleri **Algılama kuralları** ekranından anında uygulanır ve `data/rule_overrides.json` dosyasında tutulur. Kural dosyalarını (`rules/*.yaml`) düzenlediyseniz "Dosyalardan yeniden yükle" ile servis durmadan yükleyin.
- Dosyayı elle düzenlemek de desteklenir; değişiklik bir sonraki başlatmada etkinleşir. Arayüzden kaydedilen dosya YAML olarak yeniden yazılır (yorumlar korunmaz); önceki hâli her zaman `*-onceki.yaml` sürümü olarak saklanır.

## 6. Bildirimler

**Ayarlar → Bildirimler** ekranından kanal ekleyin ve kaydetmeden önce **Test gönder** ile deneyin.

| Tür | Gerekli alanlar | Not |
|---|---|---|
| Slack / Teams | incoming webhook URL | Teams için adaptive card |
| Telegram | bot token, chat ID | |
| E-posta | SMTP sunucu, port (587 STARTTLS), gönderen, alıcılar | kullanıcı/parola opsiyonel |
| Syslog | `host:port`, udp/tcp | RFC 5424, facility local0; önem seviyesi saldırı önemine eşlenir |
| Webhook | URL, HMAC anahtarı | `X-DDoS-Signature: sha256=HMAC(gövde)`; SOAR/ITSM entegrasyonu için |

Olaylar: `incident.started`, `incident.ended`, `vector.added`, `mitigation.pending`, `mitigation.active`, `mitigation.withdrawn`, `mitigation.failed`, `finding.created`. Olay seçilmezse saldırı başlangıç/bitiş, onay bekleyen ve hatalı mitigasyon olayları gönderilir. "En düşük önem" filtresi saldırı önemine göre uygulanır. Bildirim bağlantılarının doğru adrese gitmesi için `api.base_url` değerini ayarlayın.

## 7. İzleme

`GET /metrics` (Prometheus metin formatı; nesne kapsamı olmayan bir `viewer` kullanıcısının token'ı ile):

| Metrik | Anlamı |
|---|---|
| `ddosd_up`, `ddosd_uptime_seconds` | süreç durumu |
| `ddosd_flow_records_total`, `ddosd_flow_records_per_second` | işlenen flow kayıtları |
| `ddosd_engine_dropped_records_total` | motor kuyruğu taşması (sıfır olmalı) |
| `ddosd_collector_dropped_datagrams_total` | worker kuyruğu taşması (sıfır olmalı) |
| `ddosd_collector_rejected_datagrams_total` | izin listesi dışından gelen datagram'lar |
| `ddosd_engine_eval_milliseconds` | saniyelik değerlendirme süresi (< 200 ms olmalı) |
| `ddosd_engine_series`, `ddosd_engine_series_overflow_total` | izlenen seri sayısı, `max_series` aşımı |
| `ddosd_exporter_records_total{exporter,name}`, `ddosd_exporter_errors_total`, `ddosd_exporter_lost_total`, `ddosd_exporter_last_seen_seconds` (son datagram'dan beri geçen sn) | exporter sağlığı |
| `ddosd_object_bits_per_second{object,direction="in\|out"}`, `ddosd_object_packets_per_second` | nesne trafiği |
| `ddosd_incidents_active`, `ddosd_signals_pending`, `ddosd_mitigations{status}` | operasyonel durum |
| `ddosd_notifications_sent_total{channel,type}`, `ddosd_notifications_failed_total` | bildirim teslimi |
| `ddosd_flowstore_records` | adli inceleme tamponu doluluğu |

Önerilen alarmlar:

```yaml
- alert: DdosdExporterSilent
  expr: ddosd_exporter_last_seen_seconds > 120   # son datagram'dan bu yana geçen süre
- alert: DdosdDropping
  expr: rate(ddosd_collector_dropped_datagrams_total[5m]) > 0 or rate(ddosd_engine_dropped_records_total[5m]) > 0
- alert: DdosdSlowEvaluation
  expr: ddosd_engine_eval_milliseconds > 300
- alert: DdosdNotificationFailures
  expr: increase(ddosd_notifications_failed_total[15m]) > 0
```

Sağlık kontrolleri: `/healthz` süreç ayakta mı (her zaman 200), `/readyz` motor son 5 sn içinde değerlendirme yaptı ve collector dinliyor mu (değilse 503).

## 8. Yedekleme

`data_dir` içeriği:

| Dosya | İçerik |
|---|---|
| `users.json` | kullanıcılar, parola özetleri (bcrypt), token özetleri |
| `audit.jsonl` | denetim kaydı (append-only) |
| `incidents.json`, `mitigations.json`, `findings.json` | olay, mitigasyon ve analist bulgusu geçmişi |
| `rule_overrides.json` | arayüzden yapılan kural eşiği değişiklikleri |
| `config-history/` | yapılandırma sürümleri |

Yedekleme için `data_dir`, yapılandırma dosyası ve `rules/` dizinini günlük olarak kopyalamak yeterlidir. Dosyalar atomik (geçici dosya + rename) yazılır; çalışırken kopyalamak güvenlidir.

## 9. Sertleştirme kontrol listesi

- [ ] `collector.allow` yalnızca kendi exporter'larınızı içeriyor (sahte kaynaklı flow enjeksiyonuna karşı). Collector portlarını ACL ile de sınırlayın.
- [ ] Web/API TLS ile sunuluyor (`api.tls_cert`/`tls_key` veya TLS sonlandıran reverse proxy) ve yönetim ağına kısıtlı.
- [ ] İlk yönetici parolası değiştirildi, `initial-admin-password.txt` silindi; bootstrap `api.password` boş.
- [ ] NOC için `operator`, müşteriler için kapsamlı `viewer` hesapları; ortak hesap yok.
- [ ] `mitigation.mode: manual` ile başlandı; `never_mitigate` listesinde resolver'lar, router loopback'leri ve peering IP'leri var; `min_prefix_v4/v6` ağınıza uygun.
- [ ] `demo.enabled: false`.
- [ ] Prometheus alarmları ve en az bir bildirim kanalı (tercihen syslog/SIEM + chat) aktif.
- [ ] `data_dir` yedekleniyor.
- [ ] AI analist `anthropic` sağlayıcısı ile kullanılacaksa veri işleme politikanız gözden geçirildi; hassas ortamlarda `openai_compat` ile yerel model kullanın.

## 10. Sorun giderme

| Belirti | Kontrol |
|---|---|
| Genel bakışta trafik yok | Ayarlar → Telemetri: exporter görünüyor mu? `ddosd_collector_rejected_datagrams_total` artıyorsa izin listesi; hiç görünmüyorsa firewall/port |
| Trafik router sayaçlarından çok farklı | Exporter'ın örnekleme oranı (Telemetri ekranında "exporter"/"elle"/"varsayılan" kaynağıyla gösterilir); bildirmeyen cihazlar için exporter tanımında örnekleme girin |
| "Şablonsuz" kayıt sayısı sürekli artıyor | Router'ın template yenileme süresini 60 sn veya altına indirin |
| Saldırı algılanmadı | Trafik gezgini → Hedef analizi: hız, efektif eşik, baseline ve koşul durumu "neden tetiklenmedi"yi gösterir |
| Çok fazla yanlış alarm | Nesneye doğru profili atayın (`dns_server`, `web`, `gaming`, `vpn_gateway`), sonra kural bazlı eşik ayarlayın |
| Ayarlar kaydedilmiyor | Yapılandırma dosyası/dizini servis kullanıcısı için yazılabilir mi? (Ayarlar ekranındaki uyarı) |
