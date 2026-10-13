# Yönetici kılavuzu

> **English summary.** Day-to-day administration of AutoSecOps at `main` @
> `167f7b77`: the five built-in roles and their permissions, local accounts with
> TOTP MFA, lockout and session revocation (SSO is planned, not in this
> release), integrations and where their credentials are stored, the response
> approval flow (human approval, response policy with protected assets and
> hourly limits, executor registry for Cloudflare / Defender / Entra ID /
> PAN-OS, TTL expiry and revert, two approvers for identity actions; approved
> agent MCP tools bypass that policy, an open risk), the Assist/Act autonomy
> switch and the recommended regulated-sector setting
> `DAEMON_FORCE_APPROVAL=true`, retention policies, KVKK purge and legal hold,
> which audit records exist and how to read and verify them, encrypted restic
> backups with tested restore, and the Helm backup CronJob and daemon hot
> standby.

Bu kılavuz, kurulumdan sonra AutoSecOps'u işleten yöneticiye yöneliktir. Kurulum
için [internetsiz kurulum kılavuzu](kurulum-internetsiz.md), neyin bu sürümde
olduğu için [sürüm kapsamı](kapsam.md).

Konsolda ayarların yeri: **Ayarlar** (Settings) → AI models, Integrations, Alert
collection, SLA policies, Limits & autonomy, Data & uploads, System (Users dahil).

## Kullanıcılar, roller ve izinler

### Sistem rolleri

Beş sistem rolü veritabanı kurulumunda tohumlanır
(`infra/database/init/06_auth_tables.sql`, ek izinler `43_medic_permissions.sql`).
Bir rolün yapabildiği, `roles.permissions` alanındaki izinlerdir; her yazma rotası
kendi iznini sunucu tarafında denetler ve eksikse `403 Permission denied: <izin>`
döner.

| İzin | Viewer | Analyst | Senior Analyst | Manager | Admin |
|---|:-:|:-:|:-:|:-:|:-:|
| `findings.read` / `cases.read` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `findings.write` / `cases.write` | | ✓ | ✓ | ✓ | ✓ |
| `findings.delete` | | | ✓ | ✓ | ✓ |
| `cases.delete` | | | | ✓ | ✓ |
| `cases.assign` | | | ✓ | ✓ | ✓ |
| `integrations.read` | | ✓ | ✓ | ✓ | ✓ |
| `integrations.write` | | | ✓ | ✓ | ✓ |
| `users.read` | | | ✓ | ✓ | ✓ |
| `users.write` | | | | ✓ | ✓ |
| `users.delete` | | | | | ✓ |
| `settings.read` | | ✓ | ✓ | ✓ | ✓ |
| `settings.write` | | | | ✓ | ✓ |
| `ai_chat.use` | | ✓ | ✓ | ✓ | ✓ |
| `ai_decisions.approve` | | | ✓ | ✓ | ✓ |
| `medic.read` | | | | ✓ | ✓ |
| `medic.admin` | | | | | ✓ |

Rol tanımları bu sürümde konsoldan düzenlenmez ve yeni rol oluşturma arayüzü yoktur;
roller listelenir (`GET /api/users/roles/list`). Rol izinlerini değiştirmek
veritabanında `roles.permissions` üzerinde yapılır ve `config_audit_log`'a yazılmaz;
bunu değişiklik yönetimi sürecinize alın.

### Hangi işlem hangi izni ister

| İşlem | İzin |
|---|---|
| Kullanıcı oluşturma / güncelleme (`POST /api/users/`, `PUT /api/users/{user_id}`) | `users.write` |
| Kullanıcı silme (`DELETE /api/users/{user_id}`; kendini silemez) | `users.delete` |
| Yapılandırma, AI sağlayıcıları, bütçe, orkestratör aç/kapa/öldür, otonomi anahtarı | `settings.write` |
| Entegrasyon kaydetme (`POST /api/config/integrations`) | `integrations.write` |
| Müdahale eylemini onaylama/reddetme (`POST /api/v1/approvals/{action_id}/approve`, `.../reject`), duraklatılmış iş akışını sürdürme/iptal | `ai_decisions.approve` |
| QA örneklemi çekme (`POST /api/qa/samples/draw`) | `ai_decisions.approve` |
| QA örneğini inceleme (`POST /api/qa/samples/{sample_id}/review`) | `findings.write` |
| Ajan koşusu başlatma, sohbet, iş akışı çalıştırma | `ai_chat.use` |
| Tüm bulguları silme (`DELETE /api/findings/all`) | `findings.delete` |
| Kanarya ayarları ve sonuçları (`/api/quality/canaries`) | `settings.write` **ve** Admin rolü (Manager göremez) |
| Giden webhook uç noktaları (`/api/webhook-endpoints`) | `settings.write` |
| Düzenleyici sayaç ayarları (`/api/compliance/regulatory-clocks/config`) | okuma `settings.read`, yazma `settings.write` |
| Vakada düzenleyici an kaydı (`POST /api/cases/{case_id}/regulatory/events`) | `cases.write` |
| Uygulanmış eylemi geri alma (`POST /api/response/actions/{action_id}/revert`, gerekçe zorunlu) | `ai_decisions.approve` |
| Saklama politikası, yasal saklama, imha çalıştırma (`/api/compliance/retention/...`) | okuma `settings.read`, yazma ve imha `settings.write` |

CI'daki `tests/security/test_route_permissions.py` iki şeyi sınar. Birincisi,
testin rota listesindeki her rota, izni olmayan bir kullanıcıya 403 döner. Bu
listede yukarıdaki tablonun onay, geri alma, iş akışı sürdürme, QA, kanarya, giden
webhook, saklama, entegrasyon kaydetme ve tüm bulguları silme rotaları vardır.
Kullanıcı yönetimi (`/api/users/`) ve düzenleyici sayaç rotaları bu listede
**yoktur**. Bu rotaların izin denetimi kodda vardır ama bu testle sabitlenmez.
İkincisi, API'deki her yazma rotası ya bir izin bağımlılığı taşır ya da
gözden geçirilmiş `tests/security/auth_only_write_routes.txt` listesindedir. O
listedeki rotalar yalnızca oturum ister; bazıları (ör. kural kaynakları) bugün
Viewer'a açıktır (bkz. [tehdit modeli R26, R28](tehdit-modeli.md#açık-riskler)).

### Rol atama kuralları

- Bir kullanıcı yalnızca **kendi sahip olduğu tüm izinleri** veren bir rolü
  atayabilir. Örneğin Manager `users.write` taşır ama `users.delete` taşımadığı için
  Admin rolünü atayamaz.
- Rolü ya da e-postası değişen kullanıcının tüm oturumları anında geçersiz olur
  (kullanıcı başına iptal zamanı, Redis'te).
- Hizmet hesapları (`users.service_account`) yalnızca Viewer olabilir; başarısız
  girişlerle kilitlenmezler. Bugün tek hizmet hesabı Medic ağ geçididir ve
  `python -m core.auth.service_account` ile yönetilir (bkz. [docs/medic/enable.md](../medic/enable.md)).

### İlk yönetici ve acil erişim

Varsayılan yönetici yoktur. Kullanıcı tablosu boşken giriş ekranı ilk hesabı
oluşturmayı önerir (`POST /api/auth/bootstrap`, dakikada 5 deneme sınırı); ilk
hesap oluşunca bu uç kalıcı olarak kapanır. Öneri: ilk hesabı yalnızca acil erişim
(break-glass) yöneticisi olarak kullanın, MFA'sını açın, parolasını ve kurtarma
kodlarını kasada tutun; günlük yönetim için kişisel hesaplar açın.

## Kimlik doğrulama

| Ayar | Varsayılan | Ortam değişkeni |
|---|---|---|
| Erişim belirteci ömrü | 30 dk | `JWT_ACCESS_EXPIRATION_MINUTES` |
| Yenileme belirteci ömrü | 7 gün | `JWT_REFRESH_EXPIRATION_DAYS` |
| Kilitlenme eşiği / süresi | 5 hatalı giriş / 15 dk | `AUTH_LOCKOUT_THRESHOLD`, `AUTH_LOCKOUT_DURATION_MINUTES` |
| En kısa parola | 12 karakter (en çok 72 bayt) | `AUTH_MIN_PASSWORD_LENGTH`, `AUTH_MAX_PASSWORD_BYTES` |
| Parola gücü (zxcvbn) | ≥ 3 | `AUTH_MIN_ZXCVBN_SCORE` |
| Parola geçmişi (yeniden kullanım yasağı) | son 5 | `AUTH_PASSWORD_HISTORY_LIMIT` |
| Parola sıfırlama bağlantısı ömrü | 3600 sn | `PASSWORD_RESET_TTL_SECONDS` |
| Redis erişilemezken iptal denetimi | kapalı başarısız (istek reddedilir) | `REVOCATION_FAIL_OPEN=false` |
| Çerez | `Secure`, `SameSite=strict` | `VIGIL_COOKIE_SECURE`, `VIGIL_COOKIE_SAMESITE` |
| CSRF (çift gönderim çerezi) | açık, **yalnızca raporlama** | `VIGIL_CSRF_ENABLED`, `VIGIL_CSRF_REPORT_ONLY` |

Önerilen üretim ayarları: `VIGIL_CSRF_REPORT_ONLY=false` (kodun varsayılanı
yalnızca loglar; `env.example` engellemeyi önerir), `DEV_MODE=false`
(Helm ve `env.example` varsayılanı). `DEV_MODE=true` tüm kimlik doğrulamayı kapatır
ve her isteği tam yetkili sahte bir yönetici olarak çalıştırır; açılışta ve
erişilebilir bir adreste bunu yüksek sesle loglar ama **engellemez**. Üretimde asla
açmayın; `JWT_SECRET_KEY` olmadan backend `DEV_MODE=false` iken açılmaz.

**MFA (TOTP).** Her kullanıcı kendi hesabında MFA'yı açar (`/api/auth/mfa/setup`
→ `/api/auth/mfa/verify`); 10 tek kullanımlık kurtarma kodu üretilir. TOTP sırrı
veritabanında şifreli durur. Bu sürümde MFA'yı bir rol için **zorunlu kılan bir
ayar yoktur**; yönetici ve onaylayıcı hesaplarında MFA'yı süreçle zorunlu tutun ve
düzenli olarak kullanıcıların `mfa_enabled` alanını denetleyin.

**Hız sınırları.** Giriş, ilk hesap, parola değiştirme, MFA doğrulama ve kurtarma
kodu uçları dakikada 5; parola sıfırlama isteği saatte 3, sıfırlamanın tamamlanması
saatte 5 ile sınırlıdır.

**SSO.** Bu sürümde OIDC ile tek oturum açma yoktur. Entra ID, Okta ve Keycloak
desteği, grup → rol eşlemesi ve yerel acil erişim hesabı birlikte gelecektir
(Planlı — `wp/w1.9-oidc`, bu sürümde yok).
SAML ihtiyacı o pakette bir OIDC aracı (Keycloak/Dex) üzerinden karşılanacaktır
(Planlı — `wp/w1.9-oidc`, bu sürümde yok).

## Entegrasyonlar

- Konsol: **Ayarlar → Integrations** (kaydetme `integrations.write`; Senior Analyst,
  Manager, Admin). Zamanlanmış alarm çekme kaynakları: **Ayarlar → Alert collection**
  (`/api/federation/sources`).
- Kimlik bilgileri (API anahtarı, parola, belirteç) veritabanına yazılmaz: kaydetme
  işleyicisi gizli alanları şifreli sır deposuna (`secrets.enc`) yönlendirir, geri
  okurken maskeler; yalnızca URL, bölge, `verify_ssl` gibi gizli olmayan alanlar
  veritabanında durur.
- Kubernetes'te `stateDirectory` varsayılan olarak geçicidir; kimlik bilgilerini
  konsol yerine Secret / ExternalSecrets ile verin (bkz.
  [kurulum kılavuzu](kurulum-internetsiz.md#5-kurulum-kubernetes)).
- **Test** düğmesi (`POST /api/config/integrations/{integration_id}/test`): Splunk ve
  Elastic için gerçekten oturum açıp sunucu bilgisini okur; diğerleri için yalnızca
  MCP sunucusunun yanıt verdiğini gösterir.
- Kendi imzalı CA'sı olan bir sunucu için entegrasyonun "CA Certificate Path"
  alanını kullanın; tüm süreçlere bir CA eklemek için Helm `caBundle.existingSecret`.
- MCP sunucuları: `mcp-config.json`'daki sunucular, yerel `security-detections` ve
  müşterinin kendi Splunk'ı dışında, operatör açana kadar kapalıdır. AutoSecOps'un
  kendi MCP yüzeyi `VIGIL_MCP_ENABLED=false` ile kapalı gelir.
- Air-gap'te bir entegrasyonu açtığınızda hedefinin küme içinde ya da
  `networkPolicies.egress.extraCIDRs` listesinde olması gerekir.
- Defender, Entra ID ve Palo Alto entegrasyonları açıkken müdahale yürütücüleri de
  kayda alınır. Kayıt defteri API ve daemon açılışında bir kez kurulur; bu
  entegrasyonları açtıktan ya da kapattıktan sonra iki servisi yeniden başlatın.

**Giden webhook'lar ve bildirimler.** Uç noktalar `/api/webhook-endpoints` ile
yönetilir (`settings.write`); imza anahtarı yalnızca oluştururken bir kez döner ve
sır deposunda saklanır. İstekler `X-AutoSecOps-Signature` başlığıyla HMAC-SHA256
imzalıdır; alıcı doğrulaması [docs/outbound-webhooks.md](../outbound-webhooks.md).
İlgili ayarlar: `WEBHOOK_ALLOWED_CIDRS` (özel ağlara izin; boşsa özel/loopback/
link-local hedefler reddedilir, bulut metadata adresi her durumda reddedilir),
`WEBHOOK_MAX_ATTEMPTS` (8), `CASE_AUTOMATION_ENABLED`, `CASE_NOTIFY_SLACK_ENABLED`,
`CASE_NOTIFY_EMAIL_PRIORITIES`. Kanarya vakaları hiçbir dış kanala gitmez.

## Müdahale politikası ve onaylar

### Bir eylemin yaşam döngüsü (bu sürüm)

1. **Öneri.** Daemon'un yanıtlayıcısı, orkestratör, bir iş akışı ya da MCP aracı
   `create_approval_action` bir eylem önerir. Öneri, satır oluşmadan önce müdahale
   politikasından geçer: korunan bir varlığa yönelen ya da saatlik sınırı aşan öneri
   hiç oluşmaz. Geçen öneri `approval_actions` tablosuna yazılır (eylem tipi, hedef,
   güven, gerekçe, geri alınabilirlik, tekrar önleme anahtarı).
2. **Onay kapısı.** Satırın insan beklemesi gerekip gerekmediğine kod karar verir ve
   kararı veren kuralı satıra yazar (ör. `response.confidence_threshold=0.90 met (0.92)`):
   - `DAEMON_FORCE_APPROVAL=true` ya da konsolda Assist → her eylem insan bekler;
   - geri alınamaz eylem → her zaman insan bekler, hiçbir zaman otomatik onaylanmaz;
   - geri alınabilir eylem → güven `DAEMON_CONFIDENCE_THRESHOLD` (0.90) altındaysa
     insan bekler.
3. **Karar.** `ai_decisions.approve` iznine sahip bir kişi onaylar ya da gerekçeyle
   reddeder (konsolda onay kuyruğu / "Needs you"). Onaylayanın adı ve zamanı satıra
   yazılır. Kimlik eylemleri (`disable_user`, `revoke_sessions`) **iki farklı kişi**
   ister: ilk onay satırı `pending` bırakır, ikinci onay farklı bir kullanıcıdan
   gelmelidir (büyük/küçük harf duyarsız karşılaştırma). Aynı kişinin ikinci onayı
   409 ile reddedilir.
4. **Uygulama.** Daemon'un yanıtlayıcı döngüsü onaylı satırları uygular. Her satır
   önce yeniden politikadan, sonra yürütücü kayıt defterinden geçer. **Bir kişinin
   onaylamadığı satır uygulanmaz**: yalnızca güven eşiğiyle "onaylı" sayılan bir
   eylem loglanır ve atlanır. Politika reddi satırı `failed` yapar
   (`policy_refused: ...`). Kayıtlı yürütücüler: Cloudflare (`waf_block`,
   `gateway_block`, `access_revoke`) her zaman; Defender (`isolate_host`), Entra ID
   (`disable_user`, `revoke_sessions`) ve PAN-OS (`block_ip`) entegrasyon etkinse.
   `isolate_host` için yürütücü yoksa satır "No EDR executor is configured" ile
   `failed` kaydedilir; hiçbir eylem başarılı gibi gösterilmez.
5. **Doğrulama ve süre dolumu.** Yürütücü eylemden sonra sonucu doğrular. Geri
   alınabilir eylemin bir süresi vardır: öneriyle gelen `ttl_seconds` (30 güne
   kadar; geçersiz değer öneriyi reddeder) ya da yürütücünün varsayılanı
   (Cloudflare için 24 saat). Süresi dolan eylemi daemon geri alır, doğrular ve
   geri alma satırını (`reverse_of`) `approval_actions`'a yazar.
6. **Elle geri alma.** Actions sekmesindeki **Revert** düğmesi
   `POST /api/response/actions/{action_id}/revert`'i çağırır (`ai_decisions.approve`,
   gerekçe zorunlu). Geri alınamaz eylem, yürütülmemiş eylem ya da zaten geri
   alınmış eylem 409 alır; geri alma ya da doğrulama başarısızsa 502 döner ve
   ayrıntısı konsolda gösterilir.
7. **İzleme.** Vaka sayfasındaki **Actions** sekmesi önerildi → onaylandı → uygulandı
   → doğrulandı → süresi doldu/geri alındı adımlarını ve kararı veren kuralı gösterir
   (`GET /api/cases/{case_id}/actions/timeline`).
8. **Süre aşımı.** Yanıtlanmayan onay istekleri `DAEMON_APPROVAL_EXPIRY_DAYS` (7) gün
   sonra daemon'un temizlik döngüsünde süresi dolmuş sayılır.

Kuru çalıştırma için `DAEMON_DRY_RUN=true`: eylemler loglanır, uygulanmaz.

### Müdahale politikasının ayarları

Politika `system_config` tablosundaki `response.policy` satırından (JSON) okunur;
konsolda bunun için bir ekran yoktur. Anahtarlar:

| Anahtar | Anlamı | Varsayılan |
|---|---|---|
| `protected_targets` | Hiçbir eylemin hedef alamayacağı host, hesap, IP ya da aralıklar | boş |
| `protected_tags` | Bu etiketi taşıyan varlık korunur (varsayılanlara eklenir) | `domain_controller`, `protected`, `break_glass`, `tier0`, `critical_infrastructure` |
| `asset_tags` | Varlık → etiket listesi eşlemesi | boş |
| `hourly_limits`, `default_hourly_limit` | Tür başına saatlik en çok eylem | `isolate_host`, `disable_user`, `revoke_sessions` için 10; diğerleri 20 |
| `four_eyes_types` | İki onaylayıcı isteyen türler (varsayılanlara eklenir) | `disable_user`, `revoke_sessions` |

Korunan varlık eşleşmesi host adlarında büyük/küçük harfe, sondaki noktaya ve
`DOMAIN\` önekine duyarsızdır; tam ad da kısa ad da eşleşir. IP adresleri ve
aralıklar örtüşmeyle eşleşir; IPv4'te /24'ten, IPv6'da /64'ten geniş bir aralık
hedefi her durumda reddedilir. Satır okunamazsa politika "degraded" olur ve
**her eylem reddedilir**. Yürütücülerin kendi güvenlik kuralları (korunan roller,
yönetim IP'si, TTL üst sınırı, tek makineye çözümleme)
[Defender](../../core/integrations/microsoft_defender/EXECUTOR.md),
[Entra ID](../../core/integrations/azure_ad/EXECUTOR.md) ve
[Palo Alto](../../core/integrations/palo_alto/EXECUTOR.md) belgelerinde yazılıdır.

### Araçların etki sınıfları

Ajanların ve sohbetin kullanabildiği her araç `core/llm/tool_effects.py` tablosundan
bir sınıf alır: `read_only`, `records`, `approval`, `decision`, `write`,
`destructive`. `write` ve `destructive` araçlar ("onay gerektiren araçlar") her
yüzeyde yalnızca bir kişinin yanıtladığı onay noktasından sonra çalışır. Sohbet bu
araçları hiç sunmaz. İş akışları onay noktasında bekler. `/internal/tools/invoke`
onaylanmış bir onay noktası olmadan çağrıyı reddeder. Tabloda olmayan bir araç,
adı açıkça okuma fiiliyle başlamıyorsa en kısıtlayıcı sınıfa (`destructive`) düşer.
Bu kural CI'da `tests/unit/_ratchets/test_no_ungated_write_tools.py` ile sayılır
(onaysız yazma aracı = 0).

**Dikkat — açık risk.** Onay noktası onaylandıktan sonra bir MCP aracı (ör.
`mde_isolate`, `aad_disable_user`, `pan_block_ip`, `cb_quarantine`,
`cf_waf_block_ip`) satıcı API'sini doğrudan çağırır. Bu yol yukarıdaki müdahale
politikasından ve yürütücülerden geçmez. Korunan varlık listesi, saatlik sınır,
süre dolumu, geri alma ve iki onaylayıcı kuralı burada uygulanmaz; onay tek
kişiliktir ve araç argümanlarına bağlı değildir. Telafi: bu entegrasyonları iş
akışlarında kullanmayın ya da bu araçları içeren iş akışı onaylarını yalnızca
kıdemli kişilere verin (bkz. [tehdit modeli R2](tehdit-modeli.md#açık-riskler)).

### Bu sürümde olmayanlar

- İkinci onaylayanın farklı rolde olması ve görevler ayrılığı raporu
  (Planlı — `wp/w3.2-sod`, bu sürümde yok).
  Bugün iki onaylayıcı kuralı yalnızca kişileri ayırır, rolleri değil.
- Kategori × eylem sınıfı başına otonomi katmanları
  (Planlı — `wp/w3.1-autonomy`, bu sürümde yok).

## Otonomi

Bu sürümde otonomi iki anahtarla belirlenir; konsolun üst çubuğundaki çip bunları
**Assist** (değişiklikten önce sorar) ya da **Act** olarak gösterir
(`GET /api/config/autonomy`):

| Anahtar | Varsayılan | Etki |
|---|---|---|
| `DAEMON_AUTO_RESPONSE` | `true` | `false` ise daemon hiçbir müdahale eylemi önermez ve **onaylanmış** eylemleri de uygulamaz |
| `DAEMON_FORCE_APPROVAL` | `false` | `true` ise her eylem insan onayı bekler (Assist) |
| `approval.force_manual_approval` (konsoldan, `POST /api/config/force-manual-approval`, `settings.write`) | kayıt yok = Act | Assist'i kalıcı yapar; ortam değişkeni Assist'i zorluyorsa Act kaydı 409 ile reddedilir |

**Düzenlenmiş sektör için önerilen ayar:** `DAEMON_FORCE_APPROVAL=true` (Helm:
`config.DAEMON_FORCE_APPROVAL`) ve `DAEMON_AUTO_RESPONSE=true` (aksi halde onaylanan
eylemler de uygulanmaz). Böylece "ortam kazanır" ve konsoldan Act'e geçilemez.
Kodun varsayılanı Act görünür. Yine de yukarıda anlatıldığı gibi bir kişinin
onaylamadığı eylem uygulanmaz. Ayar bu davranışı yapılandırma düzeyinde de sabitler
ve denetçiye gösterilebilir kılar.

Diğer otonomi düğmeleri:

- **Otonom soruşturma (orkestratör)**: `ORCHESTRATOR_ENABLED=false` varsayılan; konsoldan
  açıp kapatma ve tüm koşuları durdurma (`POST /api/orchestrator/kill`) `settings.write`
  ister. Bütçeler: `ORCHESTRATOR_MAX_COST`, `ORCHESTRATOR_MAX_HOURLY_COST`,
  `ORCHESTRATOR_MAX_RUNTIME`.
- **Alarm şeritleri**: `ALERT_LANES_ENABLED=false` varsayılan; açıkken eşikler
  `INTENT.md`'nin `alert_lanes:` bölümünden okunur ve uygulanır, kural şeridi
  `suppression_rules` tablosunu okur. Bütçe baskısında hiçbir alarm düşürülmez.
- **Verdict run** (tek alarm için kısa, eleştirmenli soruşturma; sonucu karar
  şemasına uyar): `VERDICT_RUN_ENABLED=false` varsayılan. Bütçe:
  `VERDICT_RUN_MAX_ITERATIONS` (4), `VERDICT_RUN_MAX_COST_USD` (1.0),
  `VERDICT_RUN_MAX_WALL_MS` (300000). Bu sürümde daemon verdict run başlatmaz:
  alarm şeritlerinin verdict şeridine bir kuyruklayıcı bağlı değildir. Bayrak açık
  olsa bile koşu yalnızca `alert-verdict` iş akışı elle çalıştırılınca oluşur.
- **Beyan edilen niyet (`INTENT.md`)**: diğer anahtarlar için yalnızca gözlem
  modundadır; daemon açılışta beyan ile etkin değer arasındaki farkı loglar, hiçbir
  şeyi uygulamaz. Elle kontrol: `python -m services.daemon.intent`.
- Kategori × eylem sınıfı başına otonomi katmanları, devre kesici ve "yalnızca insan
  yükseltir" kuralı (Planlı — `wp/w3.1-autonomy`, bu sürümde yok).

### Kalite ölçümü: kanarya ve QA

- **Kanaryalar** varsayılan **kapalıdır**; yalnızca Admin açar
  (`PUT /api/quality/canaries/settings`; değişiklik `config_audit_log`'a yazılır).
  Açıkken daemon eval korpusunun ayrılmış test bölümünden bilinen kötücül bir alarmı
  normal alım yolundan yeniden oynatır ve 24 saat sonra yakalanıp yakalanmadığını
  puanlar. Kanaryalar müşteri metriklerine, dışa aktarımlara, SIEM'e geri yazmaya,
  bildirimlere, otomatik müdahaleye ve otonom soruşturmaya girmez. Acil kapatma:
  `DAEMON_CANARIES_ENABLED=false`. Adres havuzu: `CANARY_ADDRESS_POOL`.
- **QA örnekleme ve Karne**: insansız kapatılan kararlardan kategori başına basit
  rastgele örnek çekilir, analist inceler; Karne (Scorecard) kategori başına
  yanlış negatif oranının tek taraflı %95 Clopper–Pearson üst sınırını gösterir
  (`GET /api/qa/scorecard`).

## Saklama ve imha

Saklama ve imha veri sınıfı başınadır. Ayrıntılı başvuru:
[core/compliance/RETENTION.md](../../core/compliance/RETENTION.md) (hukuki görüş
değildir).

- **Veri sınıfları:** `findings`, `raw_events`, `cases`, `case_evidence`,
  `chat_conversations`, `llm_logs`, `agent_ledger`, `audit_logs`, `uploads`
  (`GET /api/compliance/retention/classes`).
- **Politika:** sınıf başına saklama süresi ve yöntem (`delete` ya da `anonymise`),
  `PUT /api/compliance/retention/policies/{data_class}` (`settings.write`).
  **Politikası olmayan sınıf hiçbir zaman işlenmez.** Kurulumda politika yoktur.
- **Yasal saklama:** `PUT /api/compliance/retention/legal-holds/cases/{case_id}`
  (gerekçe zorunlu). Vaka ve ona bağlı bulgu, kanıt, sohbet, LLM ve denetim kayıtları
  her sınıfta imhadan dışlanır. Açık (çözülmemiş) bir vaka da bağlı kayıtlarını korur.
- **İmha işi:** `POST /api/compliance/retention/purge`; gövdede `dry_run`
  varsayılanı `true`'dur. Zamanlanmış çalıştırma için `RETENTION_PURGE_ENABLED=true`
  (varsayılan kapalı); açıldığında da `RETENTION_PURGE_DRY_RUN=true` varsayılandır.
  Gerçekten silmek için bunu bilinçli olarak `false` yapın. Diğer ayarlar:
  `RETENTION_PURGE_INTERVAL` (86400 sn), `RETENTION_PURGE_BATCH_SIZE` (500),
  `RETENTION_PURGE_MAX_BATCHES` (20). Sıcak yedekli kurulumda iş yalnızca lider
  daemon'da çalışır.
- **İmha tutanağı:** her gerçek çalıştırma, politika ve yasal saklama değişikliği
  `config_audit_log`'a yazılır. KVKK periyodik imha tutanağı bu kayıtlardan üretilir:
  `GET /api/compliance/retention/reports` (`format=json` ya da `markdown`).
- **Ajan defteri** (`agent_ledger`, hash zincirli) otomatik imha edilmez. Zincir
  doğrulamalı arşiv `GET /api/compliance/retention/agent-ledger/archive` ile alınır;
  arşivden sonra kesme, belgelenmiş elle yapılan bir veritabanı sahibi işlemidir.

Sınırlar: imha geri alınamaz; bu yüzden önce kuru çalıştırma çıktısını inceleyin ve
gerçek çalıştırmadan önce yedek alın. Politikalar yalnızca `default` kiracısı için
geçerlidir ve bu sürümde yalnız API ile yönetilir (konsol ekranı yoktur).
`config_audit_log` hash zincirinde değildir (bkz. [tehdit modeli R6](tehdit-modeli.md#açık-riskler)).

Saklama politikası dışındaki otomatik davranışlar:

| Veri | Ne olur |
|---|---|
| Yanıtlanmayan onay istekleri | `DAEMON_APPROVAL_EXPIRY_DAYS` (7) gün sonra süresi dolar (satır kalır) |
| Epizodik bellek okuma günlüğü | `DAEMON_CLEANUP_RETENTION_DAYS` (90) gün sonra silinir |
| Bifrost istek günlüğü (`logs.db`) | Bifrost veri dizininde durur; yedeklere ve imha işine girmez |

Elle silme yolları da vardır: tek vaka silme (`cases.delete`), tüm bulguları silme
(`DELETE /api/findings/all`, `findings.delete`) ve tüm soruşturmaları temizleme
(`POST /api/orchestrator/investigations/purge`, `settings.write`). Bu silmeler geri
alınamaz, yasal saklamaya bakmaz ve imha tutanağına girmez. Düzenlenmiş kurulumda
imhayı yalnızca imha işiyle yapın.

## Denetim kayıtları ve dışa aktarım

| Kayıt | İçerik | Nasıl okunur |
|---|---|---|
| `config_audit_log` | Her ayar değişikliği: anahtar, eski/yeni değer, değiştiren kullanıcı, gerekçe, zaman | veritabanı; ilgili ekranlar |
| `case_audit_logs` | Vaka alanı değişiklikleri, düzenleyici an kayıtları, taslaklar | Vaka sayfası → Record sekmesi |
| `approval_actions` | Önerilen her eylem, kararı veren kural, onaylayan/reddeden, uygulama sonucu | onay kuyruğu, vaka Actions sekmesi, `GET /api/v1/approvals` |
| `agent_events` (ajan defteri) | Her ajan koşusunun olayları; koşu başına SHA-256 hash zinciri | `GET /api/workflows/runs/{run_id}/verify` ya da toplu doğrulama (aşağıda) |
| `regulatory_clock_events` | DORA/NIS2 başlangıç anları; vaka başına hash zinciri, güncelleme tetikleyiciyle reddedilir | `GET /api/cases/{case_id}/regulatory/events` (zincir kontrolü dahil) |
| Soruşturma gözetim zinciri | Bir soruşturmanın dosyaları ve kayıtları | `GET /api/orchestrator/investigations/{investigation_id}/chain-of-custody` |

Ajan defterinin tamamını doğrulama (Postgres'e erişen bir makineden):

```bash
cd services/agent && npm run ledger:verify
cd services/agent && npm run ledger:verify -- --run-id <uuid>
```

Çıktı ilk kırılan satırı (`run_id`, `seq`, neden: `prev_hash` ya da `payload`) ya da
toplam olay/koşu sayısını verir.

Bu sürümde **olmayanlar**:

- Denetim ve defter olaylarının syslog (RFC 5424/TLS) ya da HTTPS ile SIEM'e akışı
  (Planlı — `wp/w3.6-audit-export`, bu sürümde yok).
- Onay ve vaka denetim kayıtlarının hash zincirine alınması, Ed25519 imzalı kontrol
  noktası (Planlı — `wp/w1.10-audit-chain`, bu sürümde yok).
- Vaka başına imzalı kanıt paketi (Planlı — `wp/w3.7-evidence-pack`, bu sürümde yok).

Geçiş döneminde SIEM'e aktarım için yukarıdaki tabloları salt okuma yetkili bir
veritabanı rolüyle periyodik okumanızı öneririz.

## Yedekleme ve geri yükleme

`python -m core.backup` şunları **şifreli bir restic deposuna** yazar:
PostgreSQL'in tutarlı bir dökümü (`pg_dump -Fc`), durum dizini (`secrets.enc` ve
`master.key` dahil), soruşturma çalışma dizini, `INTENT.md`, depo kökündeki `.env`
(varsa) ve isteğe bağlı olarak Bifrost veri dizini. Komut dönmeden önce anlık
görüntüyü doğrular; doğrulanamayan anlık görüntü silinir. Sır deposu ile anahtarı
aynı yedektedir. Bu yüzden yedeğin gizliliği restic parolasına bağlıdır; parolayı
yedekten ayrı saklayın.

### Docker Compose / tek sunucu

```bash
# Tek seferlik yedek
./start.sh backup --repo /yedek/depo --passphrase-file /guvenli/parola

# Geri yüklemeyi canlı duruma dokunmadan sına (önerilir: düzenli)
./start.sh restore --repo /yedek/depo --passphrase-file /guvenli/parola --test

# Geri yükleme (önce Bifrost konteynerini durdurun)
./start.sh restore --repo /yedek/depo --passphrase-file /guvenli/parola --snapshot latest
```

Zamanlanmış yedek için Compose'daki `backup` servisi durum dizinindeki
`backups.json` dosyasını okur. Her hedef: `name`, `repo` (yerel yol), `passphrase_secret`
(parolanın sır deposundaki anahtarı), isteğe bağlı `interval_hours` (24), `keep_last`
(14), `default`, `must_be_mount`, `env`. Dosya yoksa servis bekler. Sürüm yükseltmeden
önce `backup-pre-upgrade` servisi varsayılan hedefe otomatik anlık görüntü alır.

Geri yükleme (`--test` olmadan) veritabanını değiştirdikten sonra bekleyen onayları
reddeder ve `config_audit_log`'a bir satır yazar. Eski JWT anahtarını bulabildiğinde
MFA sırlarını yeni anahtarla yeniden şifreler. Bu sayede eski bir anlık görüntüden "geri dönen" bir onay istemi
uygulanamaz. JWT anahtarının döndürülmesi anahtarın nerede tutulduğuna bağlıdır:

| `JWT_SECRET_KEY` nerede | Geri yüklemenin yaptığı | Sizin yapmanız gereken |
|---|---|---|
| `secrets.enc`, depo kökündeki `.env` ya da durum dizinindeki `jwt_secret` | Yeni anahtarı oraya yazar; yeniden başlatmadan sonra tüm oturumlar düşer | Servisleri yeniden başlatın |
| Yalnızca ortam değişkeni (ör. Compose'a verilen ortam) | Yeni anahtarı `secrets.enc`'e yazar ve bunu çıktıda söyler. Ortam değeri `secrets.enc`'ten önce okunduğu için eski anahtar geçerli kalır | Compose'un okuduğu ortamdaki `JWT_SECRET_KEY`'i silin ya da değiştirin, sonra `up`; yapmazsanız **eski oturumlar geçerli kalır** |
| Bu kurulumun dışında (ör. Kubernetes Secret) ve sürece verilmemiş | Anahtarı döndürmez; onayları reddeder, denetim satırını yazar ve hata ile çıkar | Anahtarı tanımlandığı yerde (Secret/kasa) döndürün ve pod'ları yeniden başlatın |

Doğrudan kullanım: `python -m core.backup create --repo ... --passphrase-file ...`,
`python -m core.backup restore ... --test`, `python -m core.backup run`.

### Kubernetes

Helm grafiğinde `backup.enabled=true` ile bir yedek CronJob'u açılır (varsayılan
**kapalı**). İş `pg_dump -Fc` ile döküm alır, dökümün tamamını okuyarak doğrular,
PVC'ye yazar, sayı (`backup.keepLast`, 14) ve gün (`backup.retentionDays`, 30) ile
saklama uygular. İsteğe bağlı olarak dökümü S3 uyumlu bir nesne deposuna yükler
(`backup.objectStore`). Varsayılan zamanlama günlüktür (`backup.schedule`); RPO bu
aralıktır. CronJob dökümü kendisi şifrelemez; PVC'nin ve nesne deposunun
şifrelemesini kurum tarafında sağlayın. CronJob yalnızca veritabanını yedekler.
Kimlik bilgilerini Secret/ExternalSecrets ile verdiyseniz durum dizini yeniden
üretilebilir.

**Daemon sıcak yedeği.** Helm'de `daemon.leaderElection.enabled=true`
varsayılandır ve daemon iki kopya çalışır. Postgres danışma kilidini alan kopya
liderdir ve tüm döngüleri çalıştırır; diğeri bekler (`/health` → `"role": "standby"`).
Lider düşerse diğeri birkaç saniyede, düğüm kaybında `leaseSeconds` + `retrySeconds`
(varsayılan 15 + 2 sn) içinde devralır. Eski liderin veritabanı bağlantıları
çitlenir. Compose ve tek sunucuda seçim kapalıdır (`DAEMON_LEADER_ELECTION_ENABLED`).

RPO/RTO hedefleri, ölçüm yöntemi, geri yükleme prosedürü ve kalan riskler
(veritabanı dışı yan etkiler çitlenmez):
[docs/operations/rpo-rto.md](../operations/rpo-rto.md). Bu belgedeki süreler
hedeftir. Devralma ve döküm/geri yükleme testlerle sınanır, ancak bir müşteri
ortamında ölçülmüş RTO değeri yoktur; tatbikatı yapıp süreyi kaydedin.
