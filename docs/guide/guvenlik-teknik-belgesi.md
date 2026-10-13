# Güvenlik teknik belgesi

> **English summary.** Security architecture of AutoSecOps at `main` @
> `167f7b77`: components and data flows, eight trust boundaries, the
> provenance/verdict contract (enforced on the live daemon triage path, with
> known limits), the human-approval rule and response policy for actions
> (protected assets, hourly limits, TTL expiry and revert, two approvers for
> identity actions), the open gap that approved agent MCP tools bypass that
> policy, the audit records and hash chains (agent ledger, regulatory clock
> chain with a head anchor; no signed checkpoints yet), three layers of egress
> control, secret storage, and a cryptography inventory. FIPS mode is planned,
> not in this release. Everything that is planned is marked **Planlı** with its
> branch.

Bu belge, AutoSecOps'un güvenlik mimarisini denetçi ve güvenlik mimarı için
anlatır. Bileşen başına tehditler [tehdit modelinde](tehdit-modeli.md), işletim
ayarları [yönetici kılavuzunda](yonetici-kilavuzu.md), kapsam
[sürüm kapsamında](kapsam.md).

## 1. Mimari

| Bileşen | Teknoloji | Görev | Kurulumda |
|---|---|---|---|
| Web konsolu | React SPA (`clients/web`) | Analist ve yönetici arayüzü | backend tarafından sunulur |
| API | Python / FastAPI (`services/api`) | Bulgular, vakalar, onaylar, ayarlar, kimlik doğrulama | `backend` Deployment |
| SOC daemon | Python (`services/daemon`) | Alarm çekme (federation) ve webhook alımı, triage, yanıtlayıcı (onaylı eylemleri politika ve yürütücü kayıt defteri üzerinden uygular), zamanlanmış işler, saklama/imha işi, vaka otomasyonu, kanarya | `daemon` StatefulSet; Helm'de iki kopya, Postgres danışma kilidiyle tek lider |
| LLM worker | Python ARQ (`services/worker`) | Kuyruktaki model çağrıları | `llm-worker` Deployment |
| Ajan katmanı | TypeScript (`services/agent`) | İş akışı çalışma zamanları (compose, investigate, root cause, hunt); ajan defteri | `agent-worker`, `agent-serve` |
| LLM ağ geçidi | Bifrost | Model sağlayıcılarına tek çıkış; air-gap'te yalnız Ollama | `k8s/llm-stack.yaml` |
| Yerel model | Ollama | Air-gap'te model çıkarımı | `k8s/llm-stack.yaml` |
| Veritabanı | PostgreSQL 16 | Tüm kalıcı durum; uygulama `vigil_app` rolüyle bağlanır | `postgres` StatefulSet |
| Önbellek / kuyruk | Redis 7 | Kuyruklar, tekilleştirme, oturum iptal listesi | `redis` StatefulSet |
| MCP sunucuları | alt süreçler | Entegrasyon araçları; varsayılan kapalı (iki yerel sunucu hariç) | backend içinde |
| Medic | ayrı servis | Kurulum sağlığı izleyicisi; varsayılan kapalı | isteğe bağlı |

Alarm akışı (bu sürüm): kaynak (federation poller, daemon webhook'u, dosya alımı) →
`FindingProcessor` → (bayrak açıksa alarm şeridi seçimi) → tek çağrılık AI triage
(Bifrost üzerinden model; cevap karar şemasına uyan tek JSON nesnesi) → bulgu/vaka →
yanıtlayıcı eylem önerir → müdahale politikası → `approval_actions` → insan onayı →
politika + yürütücü → doğrulama → süre dolunca geri alma → vaka zaman çizelgesi.

## 2. Güven sınırları

| # | Sınır | Karşı taraf | Uygulanan denetim |
|---|---|---|---|
| G1 | Tarayıcı ↔ API | kimliği doğrulanmış kullanıcı | TLS ingress'te sonlanır; HS256 JWT (çerez, `Secure`, `SameSite=strict`); CSRF çift gönderim çerezi; rol izinleri her yazma rotasında sunucu tarafında; hız sınırları; Redis tabanlı oturum iptali (kapalı başarısız) |
| G2 | Alarm kaynakları → daemon/API | saldırganın etkileyebildiği veri | Daemon webhook'u (NetworkPolicy açıkken) `networkPolicies.daemon.webhookAllowFrom` CIDR'lerine sınırlı; alarm içeriği **güvenilmez** sayılır (bkz. §3); kanarya ve QA ile ölçüm |
| G3 | API ↔ ajan katmanı | iç servis | `/internal` uçları yalnızca `AGENT_INTERNAL_TOKEN` paylaşılan sırrıyla (sabit zamanlı karşılaştırma); NetworkPolicy ile hangi pod'ların bağlanabileceği sınırlı; onay gerektiren araçlar onaylanmış bir onay noktası olmadan reddedilir. Onaydan sonra araç müdahale politikasından geçmez (açık risk R2) |
| G4 | Uygulama ↔ model | yerel ya da müşterinin seçtiği sağlayıcı | Tek çıkış Bifrost; air-gap'te bulut anahtarları boş ve egress kapalı; modelin çıktısı doğrudan hiçbir API çağrısına dönüşmez (araç etki sınıfları, onay kuyruğu) |
| G5 | Uygulama → dış entegrasyonlar | SIEM, EDR, IdP, güvenlik duvarı | Kimlik bilgileri şifreli sır deposunda; TLS doğrulaması açık (kapatma CI ratchet'iyle yasak); kullanıcı girdisi URL'ler için SSRF koruması; egress NetworkPolicy |
| G6 | Uygulama ↔ veri depoları | Postgres, Redis | Uygulama sahip olmayan `vigil_app` rolüyle bağlanır; `agent_events` üzerinde bu rolün UPDATE/DELETE/TRUNCATE yetkisi yoktur |
| G7 | Operatör ↔ küme/sunucu | yönetici | Sırlar Secret/ExternalSecrets'te; hizmet hesabı parolası argv/env değil stdin'den; pod'lar root olmayan kullanıcıyla, ayrıcalık yükseltmesi kapalı |
| G8 | Tedarik zinciri → kurulum | sürüm mühendisi | İmzalı paket, bant dışı açık anahtar, hazırlık kopyasında doğrulama (TOCTOU kapalı), arşiv üyesi denetimi |

## 3. Alan kökeni ve karar (verdict) sözleşmesi

Alarm alanlarının bir kısmını saldırgan yazar (e-posta konusu, dosya adı, user agent,
komut satırı). Model bu metni okuyup "zararsız" demeye yönlendirilebilir (prompt
injection). Ürünün yapısal savunması iki kuraldır:

1. **Köken kodla atanır, modelden alınmaz.** Karar şemasında
   (`core/contracts/verdict.schema.json`; Python ve TypeScript eşleri ortak test
   vakalarıyla kilitli) alıntılanan her alan `authored` taşır: `sensor`,
   `adversary` ya da `third_party`. Model yalnızca alan adını alıntılar;
   `authored`'ı kod, kaynağın köken haritasından doldurur. Haritada olmayan alan
   en az güvenilen değeri (`adversary`) alır.
2. **Sensöre dayanmayan "zararsız" kararı belirsizdir.** `benign` bir karar en az bir
   `sensor` alanına dayanmıyorsa kod onu `inconclusive` yapar (`enforce_provenance`).

**Bu sürümdeki durum:** daemon triage'ı modelden karar şemasına uyan tek bir JSON
nesnesi ister ve onu katı ayrıştırır. Geçersiz JSON, şema dışı cevap, fazladan ya da
tekrar eden anahtar çökmeye yol açmaz; karar `inconclusive` olur. Köken haritaları
(`core/federation/provenance.py`) her kaynak için hangi alanın sensöre ait olduğunu
söyler. İstem alanları kodun belirlediği köken gruplarına ayrılmış ve kaçışlanmış
olarak verilir. Kural 2 canlı yolda uygulanır. Kararda `model` ve `prompt_version`
saklanır (`ai_enrichment.ai_triage`).

Bilinen sınırlar:

- Kural 2 yalnızca `benign` kararı içindir. Yalnızca saldırganın yazdığı alanlara
  (başlık, açıklama, host adı) dayanan bir `malicious` kararı geçerli kalır. Bu karar
  bir bulguyu yükseltebilir; eylem yine de onay kapısından ve müdahale politikasından
  geçer.
- `data_source` alanını gönderen seçer (webhook gövdesi, Kafka mesajı, içe aktarma).
  Gönderen bir adaptör adı yazarak o adaptörün daha geniş sensör haritasını
  alabilir. Güven sınırı gönderenin kimlik doğrulamasıdır.
- Ajan katmanındaki (TypeScript) iş akışları bu triage yolunu kullanmaz.
- Injection test seti (`eval/suites/injection/v1.jsonl`) `evalkit` ile çevrimdışı
  ölçülebilir; sürüm kapısı değildir.
  ≤ %5 saldırı başarısının kapı olması (Planlı — `wp/w1.4-injection-set`, bu sürümde yok).

Bu sürümde injection'a karşı **etkin** olan savunmalar:

- **Araç etki sınıfları** (`core/llm/tool_effects.py`): yazan/yıkıcı hiçbir araç,
  bir insanın yanıtladığı onay noktası olmadan çalışamaz. Sohbet bu araçları hiç
  sunmaz. Tabloda olmayan araç en kısıtlayıcı sınıfa düşer. Model ne yazarsa
  yazsın, sonuç en fazla bir kişinin onayını bekleyen bir öneridir.
- **İnsan onayı olmadan eylem yok** (§4).
- **Kanaryalar ve QA örneklemesi**: kaçırılan kötücül alarmların oranı ölçülür
  (yönetici açarsa); Karne yanlış negatif üst sınırını gösterir.
- **Kanarya bulguları** dış zenginleştirmeye, otomatik müdahaleye ve otonom
  soruşturmaya hiç gönderilmez.

## 4. Onaylar, müdahale politikası ve dört göz

Kural: **bir kişinin onaylamadığı müdahale eylemi uygulanmaz.** Onay kapısı
(`core/response/config.py`, `approval_requirement`) bir eylemin insan bekleyip
beklemeyeceğine karar verir ve kararı veren kuralı satıra yazar. Geri alınamaz
eylemler her zaman bekler. Ek olarak yanıtlayıcı, `approved_by` alanı boş olan
"onaylı" bir satırı uygulamaz (güven eşiğiyle serbest kalan eylem loglanır,
çalıştırılmaz). Onay `ai_decisions.approve` izni ister ve onaylayanın kimliği
oturumdan alınır.

**Müdahale politikası** (`core/response/policy.py`) iki yerde çalışır: öneri satır
olmadan önce ve yanıtlayıcı satırı uygulamadan hemen önce. İkincisi atlanamaz.
Politika şunları uygular:

- Korunan varlıklar (yapılandırılmış hedefler ve `domain_controller`, `tier0` gibi
  etiketler) her zaman reddedilir. Host adı, IP, aralık ve kimlik parametrelerinin
  tamamı normalize edilerek karşılaştırılır. Çok geniş IP aralıkları reddedilir.
- Tür başına saatlik etki sınırı.
- Süre (`ttl_seconds`) 30 günle sınırlıdır; geçersiz değer eylemi reddeder.
- Cloudflare eylemlerinde hedef her zaman otoritedir: parametrelerde farklı bir
  adres verilirse eylem reddedilir ve tür başına parametre izin listesi uygulanır.
- Yapılandırma okunamazsa her eylem reddedilir.

**Yürütücüler** `Executor` protokolünü (`validate`, `execute`, `verify`, `reverse`)
uygular ve süreç başına bir kez kurulan kayıt defteri üzerinden çalışır
(`core/response/executors/wiring.py`). Cloudflare her zaman kayıtlıdır. Defender,
Entra ID ve PAN-OS, entegrasyonları etkinse kayda alınır. Her yürütücünün kendi
kuralları da vardır (tek makineye çözümleme, korunan roller, yönetim IP'si).
Süresi dolan geri alınabilir eylemi daemon geri alır ve doğrular. Bir kişi de
gerekçeyle geri alabilir. Her geri alma `approval_actions`'a ayrı bir satır olarak
yazılır. Host izolasyonu için yürütücü yoksa eylem `failed` yazılır (sahte başarı
yoktur).

**Dört göz.** Kimlik eylemleri (`disable_user`, `revoke_sessions`) iki farklı
onaylayıcı ister; liste `response.policy` ile genişletilebilir. Diğer eylemler tek
onaylayıcılıdır. İkinci onaylayanın farklı rolde olması ve görevler ayrılığı raporu
(Planlı — `wp/w3.2-sod`, bu sürümde yok).

**Açık risk: onaylanmış MCP araçları politikayı atlar.** Ajan iş akışlarında onay
gerektiren bir MCP aracı (`mde_isolate`, `aad_disable_user`, `pan_block_ip`,
`cb_quarantine`, Cloudflare `cf_*` araçları) bir kişi onay noktasını onayladıktan
sonra `/internal/tools/invoke` üzerinden satıcı API'sini doğrudan çağırır. Bu yolda
müdahale politikası, korunan varlık listesi, saatlik sınır, yürütücü kuralları,
süre dolumu ve dört göz uygulanmaz. Onay, araç adına bağlıdır ama araç argümanlarına
bağlı değildir. Ayrıntı ve telafi edici önlem: [tehdit modeli R2](tehdit-modeli.md#açık-riskler).

## 5. Denetim kayıtları ve zincir

| Kayıt | Bütünlük |
|---|---|
| `agent_events` (ajan defteri) | Koşu başına hash zinciri: `event_hash = sha256(prev_hash ‖ payload)`, `BEFORE INSERT` tetikleyicisi atar (yazan kod değil). Uygulama rolü `vigil_app` bu tabloda UPDATE/DELETE/TRUNCATE yapamaz. Doğrulama: `npm run ledger:verify` (ajan katmanı) ya da koşu başına `GET /api/workflows/runs/{run_id}/verify` |
| `regulatory_clock_events` | Vaka başına hash zinciri; UPDATE tetikleyiciyle reddedilir; zincirin son satırı tetikleyicinin tuttuğu `regulatory_clock_heads` çapasıyla karşılaştırılır (son olayların silinmesi ve sıra dışı ekleme görünür); her olay `case_audit_logs`'a da yazılır; zincir kontrolü API yanıtında |
| `config_audit_log` | Ayar değişikliği, değiştiren kullanıcı ve gerekçe; saklama/imha çalıştırmaları ve yasal saklama kararları (`config_type='retention'`); geri yükleme; zincirsiz |
| `case_audit_logs` | Vaka alanı değişiklikleri; zincirsiz |
| `approval_actions` | Eylem, karar kuralı, onaylayan, uygulama sonucu; zincirsiz |

Sınırlar (bu sürüm):

- Ajan defterinin başı imzalı bir kontrol noktasına bağlı değildir. Bir koşunun
  **son** olaylarının silinmesi ve veritabanı sahibi rolüyle tüm zincirin tutarlı
  biçimde yeniden yazılması zincir doğrulamasıyla tespit edilemez.
- Düzenleyici an zincirinin çapası aynı veritabanındadır. Tablo sahibi ya da süper
  kullanıcı iki tabloyu birlikte yeniden yazabilir. `TRUNCATE` bu sürümde
  tetikleyiciyle reddedilmez (R27).
- Onay, vaka ve ayar denetim kayıtları zincirde değildir.
- Genişleme ve Ed25519 imzalı kontrol noktası
  (Planlı — `wp/w1.10-audit-chain`, bu sürümde yok).
- Denetim olaylarının SIEM'e akışı (Planlı — `wp/w3.6-audit-export`, bu sürümde yok).

## 6. Egress (dış bağlantı) denetimi

Üç katman:

1. **Yapılandırma profili.** `infra/airgap/airgap.env` (host/Compose) ve
   `infra/airgap/values-airgap.yaml` (Helm) her dış satıcı alt sistemini, telemetriyi,
   uzak MCP bağlantısını ve bulut model anahtarlarını kapatır. Ayrı bir "güncelleme
   kontrolü" yoktur.
2. **Ağ politikası.** `networkPolicies.enabled` + `networkPolicies.egress.inClusterOnly`
   pod çıkışını küme içine (ve `extraCIDRs`) sınırlar; `k8s/llm-stack.yaml` Bifrost ve
   Ollama'ya aynı kuralı uygular. Bu katman, uygulama bir hata yapsa bile geçerlidir
   (CNI'nin NetworkPolicy uygulaması şarttır).
3. **Kanıt.** `tests/airgap/test_egress_inventory.py` koddaki her dış bağlantı
   noktasını sınıflandırılmış bir envanterle karşılaştırır (yeni, listelenmemiş bir
   çağrı yeri testi düşürür); `tests/airgap/test_runtime_egress.py` API, daemon ve LLM
   worker'ı soket koruması altında gerçek akışlarla çalıştırır ve tek bir dış
   bağlantı denemesinde başarısız olur. İkisi de her PR'da CI'da koşar.

Kullanıcının girdiği URL'ler (giden webhook hedefi, sağlayıcı adresi) için
`core/platform/url_safety.py`: çözümlenen her adres loopback, özel, link-local,
multicast, ayrılmış ya da bulut metadata adresiyse reddedilir. Giden webhook
teslimatında ayrıca doğrulanan adres bağlantıya sabitlenir (DNS rebinding'e karşı),
yönlendirme izlenmez ve ortam vekili kullanılmaz. Bilinen açık: 100.64.0.0/10 (CGNAT) aralığı reddedilmez (bkz.
[tehdit modeli](tehdit-modeli.md#açık-riskler)).

## 7. Sırlar

| Sır | Nerede |
|---|---|
| Entegrasyon ve sağlayıcı kimlik bilgileri | Şifreli sır deposu `secrets.enc` (Fernet); anahtar aynı durum dizininde `master.key` (dizin 0700, dosya 0600). Veritabanına ve yapılandırma JSON'una yazılmaz; API yanıtlarında maskelenir |
| `JWT_SECRET_KEY` | Ortam / Kubernetes Secret; `DEV_MODE=false` iken zorunlu, yoksa backend açılmaz |
| `AGENT_INTERNAL_TOKEN` | Ortam / Secret; API ile ajan katmanı arasındaki tek kimlik doğrulama |
| Postgres / Redis parolaları | Secret (`existingSecret` desteklenir) |
| TOTP sırları | Veritabanında, `JWT_SECRET_KEY`'den türetilen anahtarla Fernet şifreli |
| Giden webhook imza anahtarları | Sır deposu; tabloda yalnız `secret_ref` |
| Air-gap paket imza anahtarı | Yalnızca imzalama makinesi; pakette hiçbir anahtar yok |

Okuma önceliği: şifreli dosya → ortam değişkeni → depo kökündeki `.env` (salt okuma)
→ durum dizinindeki `.env` → (açıkça etkinleştirilirse) işletim sistemi anahtarlığı.
Kubernetes'te durum dizini varsayılan olarak geçicidir; üretimde kimlik bilgilerini
Secret ya da ExternalSecrets Operator (`secrets.externalSecret.enabled`; Vault, AWS
Secrets Manager vb.) ile verin.

Döndürme: veritabanı yedeğinden geri yükleme bekleyen onayları reddeder.
`JWT_SECRET_KEY` `secrets.enc`'te, `.env`'de ya da `jwt_secret` dosyasındaysa onu
döndürür ve TOTP sırlarını yeniden şifreler. Anahtar yalnızca ortam değişkeninden
geliyorsa yeni anahtar `secrets.enc`'e yazılır. Ortam değeri önce okunduğu için
operatör ortamdaki değeri silip değiştirmedikçe eski oturumlar geçerli kalır.
Anahtar kurulum dışında tanımlıysa (ör. Kubernetes Secret) geri yükleme onu
döndüremez ve hata ile biter. Bu durumda anahtarı tanımlandığı yerde döndürün
(bkz. [yönetici kılavuzu](yonetici-kilavuzu.md#docker-compose--tek-sunucu)).
`master.key` için yerleşik bir döndürme komutu bu sürümde yoktur. Loglarda URL kullanıcı bilgisi
(`core/platform/log_redaction.py`) ve telemetri öznitelikleri
(`core/telemetry_sanitizer.py`) maskelenir.

## 8. Kriptografi envanteri

| Kullanım | Algoritma / yapı | Kütüphane |
|---|---|---|
| Parola ve kurtarma kodu özeti | bcrypt (tuzlu; 72 bayt üst sınır) | `bcrypt` |
| Oturum belirteci | JWT, HMAC-SHA256 (HS256); erişim 30 dk, yenileme 7 gün | PyJWT |
| Sır deposu, TOTP sırrı şifrelemesi | Fernet (AES-128-CBC + HMAC-SHA256) | `cryptography` |
| MFA | TOTP (RFC 6238) | `pyotp` |
| Giden webhook imzası | HMAC-SHA256, zaman damgalı (`t=…,v1=…`) | standart kütüphane |
| Ajan iç belirteci | sabit zamanlı karşılaştırma (`hmac.compare_digest`) | standart kütüphane |
| Defter ve düzenleyici an zinciri | SHA-256 | PostgreSQL `sha256()` |
| Air-gap paket imzası | Ed25519 (OpenSSL) ya da cosign / minisign; SHA-256 özetler | OpenSSL ve araçlar |
| Yedekler (Compose/host) | restic deposu şifrelemesi (AES-256 + Poly1305-AES) | restic |
| Yedekler (Helm CronJob) | şifreleme yok; özet SHA-256; PVC / nesne deposu şifrelemesi kurumun | `pg_dump` |
| Taşıma | TLS (ingress'te ve entegrasyon istemcilerinde; sertifika doğrulaması açık) | platform |

**FIPS:** bu sürümde FIPS modu yoktur. bcrypt FIPS onaylı bir algoritma değildir ve
kullanılan kütüphaneler doğrulanmış bir FIPS modülü olarak yapılandırılmamıştır.
OpenSSL 3 FIPS sağlayıcısı ve FIPS uyumlu karşılıklar
(Planlı — `wp/w3.10-fips`, bu sürümde yok).

## 9. Güvenli geliştirme süreci

- Her iş paketi yazılı bir şartnameye (spec) karşı geliştirilir. Onu yazmamış
  **bağımsız bir doğrulayıcı** yalnızca şartnameyi ve değişikliği görerek doğrular.
  Yüksek riskli paketler insan onayı ister (`docs/wp/VERIFIER.md`).
- CI'daki eşik testleri (ratchet, `tests/unit/_ratchets/`) şunları sabitler: onaysız
  yazma aracı yok, TLS doğrulaması kapatılamaz, tek egress noktası, Helm'in okuduğu
  her ortam değişkeni kodda okunur, kod yasakları.
- CI'da Trivy imaj taraması, Bandit statik analizi, Dependabot bağımlılık güncellemeleri.
- Güvenlik testleri (`tests/security/`): rota × izin matrisi, kimlik doğrulamanın
  varsayılan açık olması, SSRF, yol geçişi, kimliksiz uçlar.
- Gecelik staging ortamı (`infra/staging/`): bir VM'de kurulduğunda `main` her gece
  k3s üzerine kurulur ve yerel modelle duman testi yapılır.
- İç kırmızı takım incelemesinin (W4.3) bulguları tehdit modelinde R26 ve R28 olarak
  kayıtlıdır; düzeltmeleri birleşmedi.
- SBOM, imzalı imajlar ve sürüm notları (Planlı — `wp/w4.7-release`, bu sürümde yok).
- Dış pentest (Planlı — dal yok, W4.4, bu sürümde yok).
