# Air-gap: sıfır dış bağlantı (egress) doğrulaması

Bu klasör, AutoSecOps'un **air-gap profiliyle** (`infra/airgap/airgap.env`)
çalıştırıldığında dağıtımın dışına hiçbir ağ bağlantısı açmadığını kanıtlar.
İzin verilen tek istisna, operatörün `AIRGAP_EGRESS_ALLOWLIST` içinde açıkça
listelediği hedeflerdir (varsayılan: boş, yani yalnızca bu makine / dağıtımın
kendi servisleri).

İki katman vardır:

| Katman | Dosya | Ne kanıtlar |
|---|---|---|
| Statik envanter | `egress_scan.py`, `egress_inventory.json`, `test_egress_inventory.py` | Koddaki her dış bağlantı noktası (çağrı yeri) listelenmiş, sınıflandırılmış ve air-gap profilinde kapatılmış. Listede olmayan yeni bir çağrı yeri testi düşürür (ratchet). |
| Çalışma zamanı | `guard/sitecustomize.py`, `stub_llm.py`, `test_runtime_egress.py` | API, daemon ve LLM worker gerçek akışlarda çalışırken yerel olmayan **tek bir** bağlantı denemesi bile yapmıyor. |

CI işi: `.github/workflows/airgap.yml` (yalnızca `SingularityRD/autosecops2`,
gizli anahtar kullanmaz).

## Çalıştırma

```bash
# Statik envanter (servis gerektirmez, ~30 sn)
pytest tests/airgap/test_egress_inventory.py --no-cov

# Çalışma zamanı (yerel PostgreSQL gerekir; redis-server kuruluysa kendi
# Redis'ini açar, yoksa REDIS_URL'deki Redis'in 14 numaralı veritabanını kullanır)
pytest tests/airgap/test_runtime_egress.py --no-cov

# Tarayıcının bulduklarını görmek
python -m tests.airgap.egress_scan
```

Çalışma zamanı testi kendi geçici veritabanını (`airgap_<pid>_<hex>`) oluşturur
ve sonunda siler; başlattığı süreçleri PID ile (kendi süreç grubuyla) durdurur.
PostgreSQL ya da Redis yoksa test atlanır (skip); `CI` veya `AIRGAP_REQUIRED`
ortam değişkeni tanımlıysa atlanmak yerine başarısız olur.

Ayarlanabilir değişkenler: `AIRGAP_STARTUP_TIMEOUT` (varsayılan 240 sn),
`AIRGAP_SOAK_SECONDS` (akışlardan sonra süreçlerin periyodik işlerini
çalıştırması için beklenen süre, varsayılan 30 sn).

## Statik envanter

`egress_scan.py` şu kaynakları tarar:

- `core/`, `services/`, `tools/` altındaki Python kodu (AST ile; `import httpx as hx`
  gibi takma adlar ve `asyncio.to_thread(httpx.get, ...)` gibi ertelenmiş
  çağrılar dahil): httpx, requests, aiohttp (istemci), urllib, urllib3,
  http.client, socket, DNS çözümleme, SMTP, websocket, Kafka, AWS/Azure SDK,
  Anthropic/OpenAI SDK, Sentry, OpenTelemetry exporter, MCP istemcisi, LDAP,
  SSH, TAXII, LiteParse (OCR verisi indirme), tiktoken; ayrıca kendi başına ağa
  çıkan komut satırı araçlarını başlatan `subprocess` çağrıları (git, npx, npm,
  pip, uv, uvx, curl, wget, docker, ...).
- `services/agent/` TypeScript katmanı (fetch, http(s).request, SDK, socket).
- Web konsolunun statik dosyaları (dış `src`/`href`/`url()` her tarayıcıyı
  internete çıkarırdı; şu an bulunan yok).
- Hedef adı taşıyan yapılandırma: `mcp-config.json` sunucuları ve Bifrost
  sağlayıcı tohumu (`infra/docker/bifrost/config.json`).

PostgreSQL ve Redis istemcileri listelenmez: dağıtımın kendi durum depolarıdır
ve profil onları yerel adreslere yönlendirir.

### Envanter girdisi

```json
{
  "site": "services/daemon/responder.py",
  "category": "gated",
  "kinds": {"httpx": 2, "host:slack.com": 1, "host:events.pagerduty.com": 1},
  "switches": {"DAEMON_ESCALATION_ENABLED": "off", "DAEMON_SLACK_ENABLED": "off"},
  "note": "Escalation to Slack/PagerDuty."
}
```

- `kinds`: tarayıcının bulduğu istemci türleri ve sayıları (`host:` = kodda
  geçen dış sunucu adı). Ratchet bunlara göre çalışır: yeni site, yeni tür ya da
  artan sayı testi düşürür; azalma serbesttir. Artık bulunmayan bir site de
  testi düşürür (envanter güncel kalsın diye).
- `switches`: `infra/airgap/airgap.env` içinde bulunması zorunlu anahtarlar ve
  beklenen değer: `off` (boş/false/0), `on` (true/1), `set` (boş değil),
  `internal` (yerel / özel ağ / nokta içermeyen servis adı ya da allowlist'te),
  `=değer` (birebir). Anahtarın kodda gerçekten okunduğu da doğrulanır
  (araçların kendi değişkenleri hariç: `NPM_CONFIG_OFFLINE`, `UV_OFFLINE`,
  `PIP_NO_INDEX`, `TESSDATA_PREFIX`).
- `gates`: ortam değişkeni olmayan kapılar:
  - `integration:<id>` — yalnızca operatör o entegrasyonu kimlik bilgileriyle
    etkinleştirdiğinde çalışır; air-gap profili hiçbirini etkinleştirmez.
  - `mcp-server:<ad>` — MCP sunucusu operatör etkinleştirene kadar kapalıdır.
    Test, adın `mcp-config.json` içinde olduğunu ve
    `MCPService._DEFAULT_ENABLED` içinde **olmadığını** doğrular.
  - `operator-action:<açıklama>` — yalnızca operatörün açık bir isteğiyle
    (ör. kural deposu senkronu, Jira'ya aktarma) çalışır; hedef operatörün
    girdiği adrestir ve allowlist'te olmalıdır.

Kategoriler:

| Kategori | Anlamı | Test kuralı |
|---|---|---|
| `internal` | Hedef dağıtımın kendi servisi (Bifrost, agent, backend) | En az bir `internal` anahtarı; dış sunucu adı içeremez |
| `gated` | Bir anahtar ya da kapı kapalıyken hiç çalışmaz | En az bir anahtar veya kapı; hepsi profilde kapalı |
| `operator-action` | Yalnızca operatörün açık eylemiyle | `operator-action:` kapısı |
| `local-only` | Makineden çıkmaz (ör. SSRF koruması için yerel DNS çözümleme) | Dış sunucu adı içeremez |
| `known-gap` | Bilinen, henüz anahtarla kapatılamayan açık | Bu README'de açıklanmış olmalı |
| `UNREVIEWED` | `--write` ile yeni eklenmiş, sınıflandırılmamış | Her zaman başarısız |

### Yeni bir dış bağlantı eklediğinizde

1. Bağlantıyı bir ayarın (ör. `*_ENABLED`, boş URL/anahtar) arkasına koyun.
2. `python -m tests.airgap.egress_scan --write` — yeni site `UNREVIEWED` olarak
   eklenir, mevcut girdilerin sayıları güncellenir.
3. Girdiyi sınıflandırın (`category`, `switches`/`gates`, `note`); gerekiyorsa
   anahtarı `infra/airgap/airgap.env` içine kapalı değeriyle ekleyin.
4. `pytest tests/airgap/test_egress_inventory.py --no-cov`.

## Çalışma zamanı koruması (socket guard)

`guard/sitecustomize.py`, `PYTHONPATH` başına konup `AIRGAP_GUARD_LOG` bir
dosyaya ayarlandığında, Python başlarken uygulama kodundan önce yüklenir ve:

- `socket.connect`/`connect_ex`/`sendto`, `getaddrinfo`, `gethostbyname(_ex)`
  çağrılarını sarar; hedef loopback, Unix soketi ya da allowlist'te değilse
  denemeyi JSON satırı olarak kaydeder ve güvenlik duvarının yapacağı gibi
  reddeder (ad için çözümleme hatası, adres için `ECONNREFUSED`). Uygulama
  böylece üretimdeki normal hata yolundan geçer.
- Ağa kendi çıkan komut satırı araçlarının (git, npx, pip, curl, ...)
  başlatılmasını kaydeder (engellemez; araç Python olmadığından izlenemez).
- Her süreçte bir `armed` kaydı yazar; test, başlattığı her sürecin korunduğunu
  bununla doğrular.

Test akışı:

1. Geçici veritabanı + (varsa) özel `redis-server`, localhost'ta Bifrost yerine
   geçen bir stub model sunucusu (`stub_llm.py`).
2. Profil uygulanmış ortamda `scripts/init_schema.py` ve
   `scripts/seed_reference_data.py` (start.sh'in yaptığı gibi), sonra API
   (uvicorn, `--loop asyncio`), daemon ve LLM worker.
3. Akışlar: health, ilk yönetici (bootstrap) + giriş, yerel model sağlayıcısı
   ekleme (Ollama tipi, stub adresi), eval korpusundan bulgu alma
   (`/api/ingest/ingest-string`), AI triage (`/api/findings/{id}/enrich`, stub
   modele gider), daemon webhook'una bulgu gönderme ve daemon'un otomatik
   triage'ı (worker üzerinden stub'a), bulgudan vaka oluşturma.
4. Bekleme süresince daemon'un periyodik işleri (sondalar, avlar, poller'lar).
5. Doğrulama: guard kaydında `armed` dışında hiçbir olay yok; her iki triage
   yolu da stub modele ulaşmış.

Proxy değişkenleri (`HTTP(S)_PROXY`, `ALL_PROXY`, `NO_PROXY`) alt süreçlerden
kaldırılır: yerel bir proxy, dış istekleri guard'a "yerel bağlantı" gibi
gösterirdi. `DATABASE_URL`/`POSTGRESQL_CONNECTION_STRING` da kaldırılır.

## Bulgular (dışarıya bağlanabilen bileşenler)

Çalışma zamanı testi, profil uygulanmışken yukarıdaki akışlarda **sıfır** dış
bağlantı denemesi gördü. Statik envanter, profil ya da operatör eylemi
olmadan dışarı çıkabilecek şu noktaları ortaya çıkardı:

- `mcp-config.json#security-detections` — **varsayılan olarak açık** MCP
  sunucusu `npx -y security-detections-mcp@3.3.0` ile başlatılır; ilk araç
  çağrısında paket önbellekte yoksa `registry.npmjs.org`'a gider. Profil
  `NPM_CONFIG_OFFLINE=true` ayarlar (MCP alt süreci backend ortamını devralır);
  paket kurulum imajında önbelleğe alınmalıdır. Diğer `npx`/`uvx` sunucuları
  için de `NPM_CONFIG_OFFLINE`/`UV_OFFLINE` geçerlidir; hepsi varsayılan
  olarak kapalıdır.
- `core/documents/extract.py` — LiteParse OCR, dil verisi yoksa ilk OCR'da
  Tesseract verisini internetten indirmeye çalışır. `TESSDATA_PREFIX` ile
  `eng.traineddata` sağlanmalıdır.
- `core/llm/cost/estimator.py` (**known-gap**) — `tiktoken` kurulursa (gereksinim
  listesinde yok) ilk kullanımda BPE dosyalarını
  `openaipublic.blob.core.windows.net`'ten indirir; kurulu değilse karakter
  sezgiseli kullanılır. Kurulacaksa `TIKTOKEN_CACHE_DIR` önceden doldurulmalı.
- `infra/docker/bifrost/config.json` — tohumlanan anthropic/openai/gemini/vertex
  sağlayıcıları, anahtar varsa genel API'lere gider; profil anahtarları boş
  bırakır. Air-gap'te yerel (OpenAI uyumlu / Ollama) bir sağlayıcı kullanılır.
- `core/detections/detection_rules_service.py` — varsayılan kural kaynakları
  GitHub depolarıdır (SigmaHQ, Splunk, Elastic); `git clone` yalnızca operatör
  kaynak ekler/senkronlarsa çalışır. Air-gap'te yerel yol kaynakları kullanılır.
- `core/llm/providers/discovery.py` — sağlayıcı anahtarı doğrulama/model
  listeleme `api.anthropic.com`/`api.openai.com`'a gider; yalnızca operatör
  anahtar eklediğinde.
- `core/integrations/ip_geolocation/tool.py` — `ip-api.com`'a **şifresiz HTTP**
  ile sorgu atar; MCP sunucusu varsayılan olarak kapalıdır.
- Daemon zenginleştirme (VirusTotal, Shodan), sandbox'lar, Slack/PagerDuty,
  Sentry, OTLP, SMTP, Kafka, Medic: hepsi profilde kapalı anahtarların ya da
  etkinleştirilmemiş entegrasyonların arkasında.

## Sınırlar

- Guard yalnızca **Python** soketlerini görür. Yerel kod (libpq/psycopg2,
  LiteParse'ın yerel kısmı, gRPC C çekirdeği) ve Python olmayan bileşenler
  (Bifrost Go ikilisi, Node agent servisi, tarayıcıdaki web konsolu,
  PostgreSQL/Redis) kapsam dışıdır; agent katmanı yalnızca statik olarak
  taranır. Ağ düzeyinde kanıt (ör. `internal: true` compose ağı) air-gap
  paketleme işinin (W3.3) konusudur.
- uvloop, kendi C düzeyi DNS/bağlantısını kullandığından guard'ı atlar; bu
  yüzden test uvicorn'u `--loop asyncio` ile başlatır.
- Statik tarama kaba ve sözdizimseldir: bağlantıyı dolaylı kuran (ör. bir
  kütüphanenin içinden) kodu görmez; bu boşluğu çalışma zamanı testi kapatır.
- Entegrasyon/MCP kapıları operatör yapılandırmasına bağlıdır; bir entegrasyon
  etkinleştirildiğinde hedefi dağıtım içinde ya da allowlist'te olmalıdır.
