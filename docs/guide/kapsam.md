# Sürüm kapsamı: bu sürümde ne var, ne yok

> **English summary.** What `main` @ `b38f6fdb` contains and what it does not.
> The merged work packages cover the measurement core, tool-effect gating,
> outbound webhooks, canaries and QA scorecard, alert lanes behind a flag,
> Defender / Entra ID / PAN-OS executors as *unwired* modules, action timeline,
> DORA/NIS2 clocks, air-gap bundle and zero-egress proof. Not merged:
> OIDC SSO, extended audit chain, verdict runs, executor registry and response
> policy (incl. four-eyes), autonomy controller, separation of duties,
> retention/erasure, SIEM audit export, evidence packs, daemon hot standby,
> FIPS mode, lessons, injection-set gate, structured triage with provenance.
> Those are marked **Planlı** everywhere in this guide.

Bu sayfa, belge setinin geri kalanının dayandığı tek kapsam listesidir. Bir özellik
burada "var" değilse, belgelerin hiçbirinde "var" diye anlatılmaz.

## Bu sürümde olanlar (main @ b38f6fdb)

| İş paketi | Özellik | Varsayılan | Nerede |
|---|---|---|---|
| W0.2 | Kullanıcıya görünen her yerde AutoSecOps markası | — | konsol, e-posta, OpenAPI |
| W0.3 | Tam CI; her PR'da backend, web, agent, Helm, güvenlik işleri | — | `.github/workflows/ci-cd.yml` |
| W0.5 | Donmuş sözleşmeler: karar (verdict) şeması, `Executor` protokolü, 46+ tabloların iskeleti | — | `core/contracts/verdict.schema.json`, `core/response/executors/base.py` |
| W0.7, W1.1 | Etiketli eval korpusu ve çevrimdışı değerlendirme düzeneği | — | `eval/corpus/v1`, `evalkit` |
| W1.5 | Gizli kanarya alarmları (yakalama oranı ölçümü) | **kapalı**; yalnızca Admin açar | `core/quality/canary.py` |
| W1.6 | QA örnekleme, inceleme kuyruğu, Karne (Scorecard) ekranı | açık (örnekleme elle tetiklenir) | `core/quality/sampling.py` |
| W1.7 | Araç etki sınıfları; yazan/yıkıcı araç yalnızca onay hattından | her zaman açık | `core/llm/tool_effects.py` |
| W1.8 | HMAC imzalı giden webhook'lar, vaka bildirim dağıtıcısı, SLA izleyicisi | uç nokta tanımlanana kadar hiçbir şey gönderilmez | `core/integrations/outbound_webhooks.py` |
| W2.2 | Üç şeritli alarm yönlendirici (kural / küçük model / verdict) | **kapalı** (`ALERT_LANES_ENABLED=false`) | `core/lanes/alert_lanes.py` |
| W2.5 | Microsoft Defender for Endpoint izolasyon yürütücüsü | **bağlı değil** (aşağıya bakın) | `core/integrations/microsoft_defender/executor.py` |
| W2.6 | Entra ID kullanıcı devre dışı bırakma / oturum iptali yürütücüsü | **bağlı değil** | `core/integrations/azure_ad/executor.py` |
| W2.7 | Palo Alto PAN-OS süreli IP engeli yürütücüsü | **bağlı değil** | `core/integrations/palo_alto/executor.py` |
| W2.8 | Vaka sayfasında eylem zaman çizelgesi (Actions sekmesi) | açık | `core/response/action_timeline.py` |
| W3.3 | İmzalı internetsiz kurulum paketi | — | `infra/airgap/` |
| W3.4 | Sıfır egress profili ve kanıtı (statik envanter + çalışma zamanı testi) | profil uygulanınca | `infra/airgap/airgap.env`, `tests/airgap/` |
| W3.8 | DORA / NIS2 bildirim sayaçları ve rapor taslakları | açık | `core/compliance/` |

Ayrıca 0.7.1'den gelen ve bu belgelerin dayandığı temel özellikler: rol tabanlı
yetki (beş sistem rolü), yerel hesap + TOTP MFA, hesap kilitleme, parola politikası,
Redis tabanlı oturum iptali, onay kuyruğu (`approval_actions`), ajan defterinde
(`agent_events`) koşu başına SHA-256 hash zinciri, ayar değişikliği denetim kaydı
(`config_audit_log`), vaka denetim kaydı (`case_audit_logs`), Fernet ile şifreli sır
deposu, restic ile şifreli ve doğrulanan yedek/geri yükleme (`python -m core.backup`),
Helm grafiği (NetworkPolicy, ExternalSecrets desteği) ve Docker Compose kurulumu.

### Yürütücüler neden "bağlı değil"?

W2.5, W2.6 ve W2.7 yürütücüleri kodda, testleriyle birlikte vardır; ancak onları
onay hattına bağlayacak kayıt defteri (W2.4) birleşmediği için **bu sürümde hiçbir
onaylı eylem onlar üzerinden çalışmaz**. Bugün onaylanmış bir eylemi gerçekten
uygulayan tek yol Cloudflare eylemleridir (`waf_block`, `gateway_block`,
`access_revoke`); `isolate_host` onaylansa bile "yürütücü yok" diye `failed`
kaydedilir (bkz. [yönetici kılavuzu](yonetici-kilavuzu.md#müdahale-politikası-ve-onaylar)).

## Bu sürümde olmayanlar (Planlı)

Aşağıdaki iş paketleri kodlanmıştır ya da kodlanmaktadır, ancak bağımsız
doğrulamadan geçip `main`'e birleşmemiştir. Bu sürüme dahil değildirler.

| İş paketi | Özellik | Durum |
|---|---|---|
| W1.2 / W1.3 | JSON şemalı triage ve alan kökeni (provenance) haritasının canlı triage yoluna bağlanması | Planlı — `wp/w1.2-triage-provenance`, bu sürümde yok |
| W1.4 | Injection test setinin kapı olarak kullanılması (≤ %5) | Planlı — `wp/w1.4-injection-set`, bu sürümde yok |
| W1.9 | OIDC SSO (Entra ID, Okta, Keycloak), grup → rol eşlemesi | Planlı — `wp/w1.9-oidc`, bu sürümde yok |
| W1.10 | Denetim zincirinin onaylara ve vaka denetimine genişlemesi, Ed25519 imzalı kontrol noktası | Planlı — `wp/w1.10-audit-chain`, bu sürümde yok |
| W2.1 | Verdict run (sıfır hipotezli soruşturma) | Planlı — `wp/w2.1-verdict-run`, bu sürümde yok |
| W2.3 | Yerel model şeridi ve model seçimi | Planlı — `wp/w2.3-local-model-lane`, bu sürümde yok |
| W2.4 | Yürütücü kayıt defteri, eylem politikası, korunan varlıklar, süre dolumu ve geri alma döngüsü, aynı kişinin iki kez onaylayamaması | Planlı — `wp/w2.4-executors-policy`, bu sürümde yok |
| W3.1 | Otonomi denetleyicisi (kategori × eylem sınıfı katmanı, devre kesici) | Planlı — `wp/w3.1-autonomy`, bu sürümde yok |
| W3.2 | Dört göz onayının farklı rol koşulu, görevler ayrılığı raporu | Planlı — `wp/w3.2-sod`, bu sürümde yok |
| W3.5 | Veri sınıfı başına saklama, KVKK periyodik imha, yasal saklama | Planlı — `wp/w3.5-retention`, bu sürümde yok |
| W3.6 | Denetim akışının syslog/HTTPS ile SIEM'e aktarımı | Planlı — `wp/w3.6-audit-export`, bu sürümde yok |
| W3.7 | Vaka başına imzalı kanıt paketi ve çevrimdışı doğrulama | Planlı — `wp/w3.7-evidence-pack`, bu sürümde yok |
| W3.9 | Daemon sıcak yedeği, Helm yedek CronJob'u, RPO/RTO belgesi | Planlı — `wp/w3.9-daemon-standby`, bu sürümde yok |
| W3.10 | FIPS modu | Planlı — `wp/w3.10-fips`, bu sürümde yok |
| W3.11 | Dersler (analist düzeltmesinden öğrenme) | Planlı — `wp/w3.11-lessons`, bu sürümde yok |
| W0.6 | Gece kurulumu yapılan staging ortamı | Planlı — `wp/w0.6-staging`, bu sürümde yok |
| W4.1–W4.5, W4.7 | Yük/kaos testleri, kırmızı takım, dış pentest, 0.7.1 → 2.0 yükseltme testi, SBOM ve imzalı imajlar | Planlı — dal yok, bu sürümde yok |

Veritabanında bazı Planlı özelliklerin tabloları şimdiden vardır (`autonomy_tiers`,
`lessons`, `retention_policies`; W0.5 iskeleti). Bu sürümde bu tabloları okuyan ya da
uygulayan kod yoktur; `suppression_rules` yalnızca alarm şeritleri açıkken okunur.

## Bilinen açıklar

Birleşmiş paketlerin doğrulamada "engelleyici değil" diye kaydedilen takip
maddeleri ve birleşmemiş paketlerin yokluğundan doğan riskler
[tehdit modelinin açık riskler bölümünde](tehdit-modeli.md#açık-riskler) tek tek
listelenmiştir.
