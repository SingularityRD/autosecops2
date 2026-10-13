# Güvenlik teknik belgesi

> **English summary.** Security architecture of AutoSecOps at `main` @
> `b38f6fdb`: components and data flows, eight trust boundaries, the
> provenance/verdict contract (frozen and tested, but not yet enforced on the
> live triage path), the human-approval rule for response actions (only
> human-approved actions execute; four-eyes is planned), the audit records and
> the SHA-256 hash chain on the agent ledger (append-only for the application's
> database role; no signed checkpoints yet), three layers of egress control,
> secret storage, and a cryptography inventory. FIPS mode is planned, not in
> this release. Everything that is planned is marked **Planlı** with its branch.

Bu belge, AutoSecOps'un güvenlik mimarisini denetçi ve güvenlik mimarı için
anlatır. Bileşen başına tehditler [tehdit modelinde](tehdit-modeli.md), işletim
ayarları [yönetici kılavuzunda](yonetici-kilavuzu.md), kapsam
[sürüm kapsamında](kapsam.md).

## 1. Mimari

| Bileşen | Teknoloji | Görev | Kurulumda |
|---|---|---|---|
| Web konsolu | React SPA (`clients/web`) | Analist ve yönetici arayüzü | backend tarafından sunulur |
| API | Python / FastAPI (`services/api`) | Bulgular, vakalar, onaylar, ayarlar, kimlik doğrulama | `backend` Deployment |
| SOC daemon | Python (`services/daemon`) | Alarm çekme (federation) ve webhook alımı, triage, yanıtlayıcı (onaylı eylemleri uygular), zamanlanmış işler, vaka otomasyonu, kanarya | `daemon` StatefulSet |
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
(Bifrost üzerinden model) → bulgu/vaka → yanıtlayıcı eylem önerir →
`approval_actions` → insan onayı → yanıtlayıcı uygular → vaka zaman çizelgesi.

## 2. Güven sınırları

| # | Sınır | Karşı taraf | Uygulanan denetim |
|---|---|---|---|
| G1 | Tarayıcı ↔ API | kimliği doğrulanmış kullanıcı | TLS ingress'te sonlanır; HS256 JWT (çerez, `Secure`, `SameSite=strict`); CSRF çift gönderim çerezi; rol izinleri her yazma rotasında sunucu tarafında; hız sınırları; Redis tabanlı oturum iptali (kapalı başarısız) |
| G2 | Alarm kaynakları → daemon/API | saldırganın etkileyebildiği veri | Daemon webhook'u (NetworkPolicy açıkken) `networkPolicies.daemon.webhookAllowFrom` CIDR'lerine sınırlı; alarm içeriği **güvenilmez** sayılır (bkz. §3); kanarya ve QA ile ölçüm |
| G3 | API ↔ ajan katmanı | iç servis | `/internal` uçları yalnızca `AGENT_INTERNAL_TOKEN` paylaşılan sırrıyla (sabit zamanlı karşılaştırma), NetworkPolicy ile hangi pod'ların bağlanabileceği sınırlı; gated araçlar onaylı checkpoint olmadan reddedilir |
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

**Bu sürümdeki durum:** sözleşme, şema ve doğrulayıcı kod `main`'dedir ve testlidir;
ancak canlı triage yolu hâlâ satır satır ayrıştırılan metin triage'ıdır ve köken
haritaları ile kural canlı yolda uygulanmaz (Planlı — `wp/w1.2-triage-provenance`, bu sürümde yok). Injection test seti (`eval/suites/injection/v1.jsonl`) `evalkit` ile çevrimdışı ölçülebilir; ≤ %5 saldırı başarısının sürüm kapısı olması (Planlı — `wp/w1.4-injection-set`, bu sürümde yok).

Bu sürümde injection'a karşı **etkin** olan savunmalar:

- **Araç etki sınıfları** (`core/llm/tool_effects.py`): yazan/yıkıcı hiçbir araç,
  bir insanın yanıtladığı onay checkpoint'i olmadan çalışamaz; sohbet bu araçları
  hiç sunmaz; tabloda olmayan araç en kısıtlayıcı sınıfa düşer. Model ne yazarsa
  yazsın, sonuç en fazla onay kuyruğunda bir öneridir.
- **İnsan onayı olmadan eylem yok** (§4).
- **Kanaryalar ve QA örneklemesi**: kaçırılan kötücül alarmların oranı ölçülür
  (yönetici açarsa); Karne yanlış negatif üst sınırını gösterir.
- **Kanarya bulguları** dış zenginleştirmeye, otomatik müdahaleye ve otonom
  soruşturmaya hiç gönderilmez.

## 4. Onaylar ve dört göz

Kural: **bir kişinin onaylamadığı müdahale eylemi uygulanmaz.** Onay kapısı
(`core/response/config.py`, `approval_requirement`) bir eylemin insan bekleyip
beklemeyeceğine karar verir ve kararı veren kuralı satıra yazar; geri alınamaz
eylemler her zaman bekler. Ek olarak yanıtlayıcı, `approved_by` alanı boş olan
"onaylı" bir satırı uygulamaz (güven eşiğiyle serbest kalan eylem loglanır,
çalıştırılmaz). Onay `ai_decisions.approve` izni ister ve onaylayanın kimliği
oturumdan alınır.

Bu sürümde uygulanan eylemler yalnızca Cloudflare eylemleridir; host izolasyonu
onaylansa bile yürütücü olmadığı için `failed` yazılır (sahte başarı yoktur).
Defender, Entra ID ve PAN-OS yürütücüleri `Executor` protokolünü (`validate`,
`execute`, `verify`, `reverse`) uygular; hedef çözümleme, (Entra ID ve PAN-OS'ta)
korunan hesap/adres ve geri alma kurallarıyla testlidir ama onay hattına bağlı değildir (Planlı — `wp/w2.4-executors-policy`, bu sürümde yok).

Dört göz: tek onaylayıcı vardır. Aynı kişinin iki kez onaylayamaması ve kritik
sınıflarda ikinci onay (Planlı — `wp/w2.4-executors-policy`, bu sürümde yok); ikinci onaylayanın farklı rolde olması ve görevler ayrılığı raporu (Planlı — `wp/w3.2-sod`, bu sürümde yok).

## 5. Denetim kayıtları ve zincir

| Kayıt | Bütünlük |
|---|---|
| `agent_events` (ajan defteri) | Koşu başına hash zinciri: `event_hash = sha256(prev_hash ‖ payload)`, `BEFORE INSERT` tetikleyicisi atar (yazan kod değil). Uygulama rolü `vigil_app` bu tabloda UPDATE/DELETE/TRUNCATE yapamaz. Doğrulama: `npm run ledger:verify` (ajan katmanı) ya da koşu başına `GET /api/workflows/runs/{run_id}/verify` |
| `regulatory_clock_events` | Vaka başına hash zinciri; UPDATE tetikleyiciyle reddedilir; her olay `case_audit_logs`'a da yazılır; zincir kontrolü API yanıtında |
| `config_audit_log` | Ayar değişikliği, değiştiren kullanıcı ve gerekçe; zincirsiz |
| `case_audit_logs` | Vaka alanı değişiklikleri; zincirsiz |
| `approval_actions` | Eylem, karar kuralı, onaylayan, uygulama sonucu; zincirsiz |

Sınırlar (bu sürüm): zincirin başı imzalı bir kontrol noktasına bağlanmadığından,
bir koşunun **son** olaylarının silinmesi ve veritabanı sahibi rolüyle tüm zincirin
tutarlı biçimde yeniden yazılması zincir doğrulamasıyla tespit edilemez; onay ve vaka
denetim kayıtları zincirde değildir. Bunları kapatan genişleme ve Ed25519 imzalı
kontrol noktası (Planlı — `wp/w1.10-audit-chain`, bu sürümde yok). Denetim olaylarının SIEM'e akışı (Planlı — `wp/w3.6-audit-export`, bu sürümde yok).

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

Döndürme: veritabanı yedeğinden geri yükleme `JWT_SECRET_KEY`'i otomatik döndürür,
TOTP sırlarını yeniden şifreler ve bekleyen onayları reddeder. `master.key` için
yerleşik bir döndürme komutu bu sürümde yoktur. Loglarda URL kullanıcı bilgisi
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
| Yedekler | restic deposu şifrelemesi (AES-256 + Poly1305-AES) | restic |
| Taşıma | TLS (ingress'te ve entegrasyon istemcilerinde; sertifika doğrulaması açık) | platform |

**FIPS:** bu sürümde FIPS modu yoktur; bcrypt FIPS onaylı bir algoritma değildir ve
kullanılan kütüphaneler doğrulanmış bir FIPS modülü olarak yapılandırılmamıştır. OpenSSL 3 FIPS sağlayıcısı ve FIPS uyumlu karşılıklar (Planlı — `wp/w3.10-fips`, bu sürümde yok).

## 9. Güvenli geliştirme süreci

- Her iş paketi bir spec'e karşı yazılır ve onu yazmamış **bağımsız bir doğrulayıcı**
  tarafından yalnızca spec + diff görülerek doğrulanır; Yüksek riskli paketler insan
  onayı ister (`docs/wp/VERIFIER.md`).
- CI ratchet'leri (`tests/unit/_ratchets/`): kapısız yazma aracı yok, TLS doğrulaması
  kapatılamaz, tek egress noktası, Helm'in okuduğu her ortam değişkeni kodda okunur,
  kod yasakları.
- CI'da Trivy imaj taraması, Bandit statik analizi, Dependabot bağımlılık güncellemeleri.
- Güvenlik testleri (`tests/security/`): rota × izin matrisi, kimlik doğrulamanın
  varsayılan açık olması, SSRF, yol geçişi, kimliksiz uçlar.
- SBOM, imzalı imajlar ve sürüm notları (Planlı — dal yok, W4.7, bu sürümde yok); iç kırmızı takım ve dış pentest (Planlı — dal yok, W4.3/W4.4, bu sürümde yok).
