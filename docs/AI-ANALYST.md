# AI analist

AI analist, algılama motorunun **"ikinci görüş"** katmanıdır. Kıdemli bir NOC analisti gibi çalışır:
- Her flow'a değil, özet tabloya bakar.
- Dedektörün alarm vermediği ama dikkat gerektiren durumları inceler.
- "Dedektör neden kaçırdı?" sorusunu cevaplar.
- Raporlar ve öneri üretir.

Analist **hızlı yolda değildir**: algılama ve mitigasyon kararları deterministik motorda verilir. Analistin hiçbir yazma yetkisi yoktur; tek yan etkisi bulgu kaydetmektir. Öneriler UI'da insan onayıyla uygulanır.

## Akış

```
[her interval] aday sinyal var mı?  ── hayır ──► model çağrılmaz (maliyet 0)
        │ evet
        ▼
LLM ajan döngüsü (en fazla max_turns)
  get_overview → list_candidate_signals → get_target_state / traffic_breakdown / top_n / sample_flows / get_rule …
        │
        ▼
submit_finding (yapılandırılmış JSON, şema ile doğrulanır)
        │
        ▼
UI: bulgu + kanıtlar + "dedektör neden kaçırdı" + öneriler [Onay kuyruğuna gönder] [Eşiği uygula]
```

Analiz şu yollarla tetiklenir:
- **Zamanlanmış** (`auto_run`): yalnızca bekleyen sinyal varsa.
- **"Bekleyen sinyalleri analiz et"** veya seçili sinyaller.
- **Olay raporu** (olay detay sayfası).
- **Serbest soru** (yalnızca LLM sağlayıcılarıyla).

## Aday sinyaller ("kıl payı")

Motor, olay açmadığı her kural serisi için saniyede bir şu kontrolleri yapar:

| Tür | Koşul | Örnek |
|---|---|---|
| `near_threshold` | eşiğe oran ≥ `near_miss_ratio` (0.5) veya sustain dolmadan kısa aşım | DNS amplifikasyonu eşiğin %65'inde sürüyor |
| `conditions_unmet` | eşik aşıldı ama doğrulama koşulu sağlanmadı | 40k pps DNS cevabı ama yalnızca 6 kaynak |
| `baseline_deviation` | z ≥ `signal_min_z` ve ≥2× baseline ve mutlak taban | UDP trafiği 5 dakikada 5 katına çıktı |

Bir sinyal aynı hedefte aktif bir olayla ilişkiliyse `related_incident` alanı doldurulur. Analist bu tür sinyalleri en sona bırakır.

## Araçlar (salt okunur)

| Araç | Döndürdüğü |
|---|---|
| `get_overview` | global/nesne oranları, aktif olay, bekleyen sinyal, exporter sağlığı |
| `list_candidate_signals` | aday sinyaller |
| `get_target_state` | bir IP için tüm kuralların oranı, efektif eşiği, baseline'ı, koşulu, son 60 sn |
| `get_timeseries` | global/nesne trafik geçmişi (≤60 nokta) |
| `top_n` | son flow'larda top-N (kaynak, port, ASN, paket boyu …) |
| `traffic_breakdown` | çok boyutlu özet (protokol, boy histogramı, TCP flag, benzersiz kaynak, fragment payı …) |
| `sample_flows` | ≤30 ham flow örneği |
| `get_incidents` | olay listesi/detayı |
| `get_rule` | kural tanımı ve nesne bazında efektif eşikler |
| `get_object_context` | nesne prefixleri, profil, notlar |
| `submit_finding` | yapılandırılmış bulgu (bitirir) |

Araç çıktıları en fazla 14 KB ile sınırlanır. Model hiçbir zaman ham flow tablosunu toplu halde görmez.

## Sağlayıcılar

### heuristic (varsayılan)
LLM gerektirmez. Aynı araç protokolünü kullanır, bu yüzden UI'daki iz görünümü LLM ile aynıdır. Şablon tabanlı bulgu üretir: kural ve kategoriye göre hipotez, koşul tipine göre açıklama, eşik ve FlowSpec önerileri. Demo bu sayede API anahtarı olmadan da tam çalışır.

### anthropic (Claude API)
```yaml
analyst:
  provider: anthropic
  model: claude-opus-5-5
  effort: high
```
```bash
export ANTHROPIC_API_KEY=...
```
- Resmi Go SDK (`anthropic-sdk-go`) ve manuel ajan döngüsü kullanılır, böylece bütçe ve izleme kontrol altında kalır.
- Adaptive thinking açıktır; düşünme derinliği `effort` ile kontrol edilir.
- Sistem prompt'u ve araç tanımları prompt cache ile önbelleğe alınır.
- Sunucu taraflı refusal fallback açıktır (`server-side-fallback-2026-07-01`, `fallbacks: "default"`). Bir istek güvenlik sınıflandırıcısına takılırsa API onu uygun bir modelle yeniden sunar.

**Gizlilik:** Bu modda araç çıktıları, yani özetler ve en fazla 30 örnek flow, Anthropic'e gönderilir. Abone IP'leri kişisel veri sayılabilir (KVKK). Bu modu sentetik veya anonimleştirilmiş veriyle kullanın ya da kurumunuzun veri işleme onayını alın.

### openai_compat (yerel LLM)
```yaml
analyst:
  provider: openai_compat
  openai_compat:
    base_url: http://localhost:11434/v1   # Ollama; vLLM: http://host:8000/v1
    model: <tool-calling destekli model>
    api_key_env: ""                        # gerekiyorsa API anahtarını okuyacağı ortam değişkeni
```
- `/v1/chat/completions` ve tool calling kullanılır.
- Veri ağ dışına çıkmaz.
- Model seçerken boyuttan çok **araç çağırma güvenilirliğine** ve **Türkçe kalitesine** bakın. Kendi değerlendirme setinizle seçin (aşağıya bakın).

## Güvenlik tasarımı

- **Sayıları model üretmez.** Her iddia `evidence` listesinde araç ve parametresiyle yer alır. UI'da her bulgunun araç çağrıları (girdi ve çıktı önizlemesi) görülebilir.
- **Prompt injection'a karşı:**
  - Saldırgan; DNS adları, exporter adları, nesne notları gibi alanlara metin yerleştirebilir. Sistem prompt'u araç çıktılarındaki serbest metni *güvenilmeyen veri* olarak tanımlar; nesne notları `notes_untrusted` alanında döner.
  - Model hiçbir aksiyon uygulayamaz.
  - `submit_finding` girdisi şema ve enum'larla doğrulanır. Geçersiz öneri tipi veya hedefsiz FlowSpec reddedilir.
- **Bütçe:**
  - `max_turns` (varsayılan 12) ve çalışma başına 6 dakika zaman aşımı var.
  - Son turda model bulguyu göndermeye yönlendirilir.
  - Aynı anda yalnızca bir analiz çalışır.
- **Öneri uygulama:**
  - `flowspec`, `rtbh` ve `scrub` önerileri mitigasyon kuyruğuna `source: analyst` olarak düşer ve **her zaman** onay ister. Güvenlik bariyerlerinden de geçer.
  - `threshold_change` önerisi kural override'ı olarak uygulanır ve geri alınabilir.

## Değerlendirme (önerilen)

1. Simülatördeki `near_miss` senaryolarını ve geçmiş olaylarınızı içeren bir senaryo seti oluşturun.
2. Her sağlayıcı/model için şunları ölçün:
   - Doğru sınıflandırma oranı.
   - Doğru "neden kaçırdı" açıklaması.
   - Kanıtsız sayısal iddia (uydurma) oranı.
   - Gereksiz/yanlış FlowSpec önerisi oranı.
   - Süre ve token.
3. Demo'da Claude API ile kalite tavanını görün; aynı seti yerel modelde koşarak üretim seçimini yapın.
