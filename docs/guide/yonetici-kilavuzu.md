# Yönetici kılavuzu

> **English summary.** Day-to-day administration of AutoSecOps at `main` @
> `b38f6fdb`: the five built-in roles and their permissions, local accounts with
> TOTP MFA, lockout and session revocation (SSO is planned, not in this
> release), integrations and where their credentials are stored, the response
> approval flow (single human approver; only Cloudflare actions execute in this
> release; four-eyes and the executor registry are planned), the Assist/Act
> autonomy switch and the recommended regulated-sector setting
> `DAEMON_FORCE_APPROVAL=true`, what data is aged out today (retention policies
> are planned), which audit records exist and how to read and verify them, and
> encrypted restic backups with tested restore.

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

Bu matris `tests/security/test_route_permissions.py` ile CI'da sabitlenir: listedeki
her rota, izni olmayan bir kullanıcıya işleyiciye ulaşmadan 403 döner.

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

**SSO.** OIDC ile tek oturum açma (Entra ID, Okta, Keycloak; grup → rol eşlemesi;
yerel acil erişim hesabı) bu sürümde yoktur (Planlı — `wp/w1.9-oidc`, bu sürümde yok). SAML, OIDC aracı (Keycloak/Dex) üzerinden karşılanacaktır.

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

1. **Öneri.** Daemon'un yanıtlayıcısı, orkestratör ya da bir iş akışı bir eylem
   önerir; `approval_actions` tablosuna bir satır yazılır (eylem tipi, hedef, güven,
   gerekçe, geri alınabilirlik, tekrar önleme anahtarı).
2. **Onay kapısı.** Satırın insan beklemesi gerekip gerekmediğine kod karar verir ve
   kararı veren kuralı satıra yazar (ör. `response.confidence_threshold=0.90 met (0.92)`):
   - `DAEMON_FORCE_APPROVAL=true` ya da konsolda Assist → her eylem insan bekler;
   - geri alınamaz eylem → her zaman insan bekler;
   - geri alınabilir eylem → güven `DAEMON_CONFIDENCE_THRESHOLD` (0.90) altındaysa
     insan bekler.
3. **Karar.** `ai_decisions.approve` iznine sahip **tek bir kişi** onaylar ya da
   gerekçeyle reddeder (konsolda onay kuyruğu / "Needs you"). Onaylayanın adı ve
   zamanı satıra yazılır.
4. **Uygulama.** Daemon'un yanıtlayıcı döngüsü onaylı satırları uygular. **Bir
   kişinin onaylamadığı satır uygulanmaz**: yalnızca güven eşiğiyle "onaylı" sayılan
   bir eylem loglanır ve atlanır. Bu sürümde gerçekten uygulanan eylemler Cloudflare
   eylemleridir (`waf_block`, `gateway_block`, `access_revoke`). `isolate_host`
   onaylansa bile "No EDR executor is configured" ile `failed` kaydedilir; hiçbir
   eylem başarılı gibi gösterilmez.
5. **İzleme.** Vaka sayfasındaki **Actions** sekmesi önerildi → onaylandı → uygulandı
   → doğrulandı → süresi doldu/geri alındı adımlarını ve kararı veren kuralı gösterir
   (`GET /api/cases/{case_id}/actions/timeline`).
6. **Süre aşımı.** Yanıtlanmayan onay istekleri `DAEMON_APPROVAL_EXPIRY_DAYS` (7) gün
   sonra daemon'un temizlik döngüsünde süresi dolmuş sayılır.

Kuru çalıştırma için `DAEMON_DRY_RUN=true`: eylemler loglanır, uygulanmaz.

### Araçların etki sınıfları

Ajanların ve sohbetin kullanabildiği her araç `core/llm/tool_effects.py` tablosundan
bir sınıf alır: `read_only`, `records`, `approval`, `decision`, `write`,
`destructive`. `write` ve `destructive` araçlar her yüzeyde yalnızca onay hattından
geçerek çalışır: sohbet bunları hiç sunmaz; iş akışları onay checkpoint'inde park
eder; `/internal/tools/invoke` onaylanmış checkpoint olmadan reddeder. Tabloda
olmayan bir araç en kısıtlayıcı sınıfa (`destructive`) düşer. Bu kural CI'da
`tests/unit/_ratchets/test_no_ungated_write_tools.py` ile sayılır (kapısız yazma
aracı = 0).

### Bu sürümde olmayanlar

- Yürütücü kayıt defteri, tipli eylem politikası, korunan varlık listesi, saatlik etki
  sınırı, süre dolumunda otomatik geri alma ve Defender / Entra ID / Palo Alto
  yürütücülerinin onay hattına bağlanması (Planlı — `wp/w2.4-executors-policy`, bu sürümde yok).
- Dört göz onayı: aynı kişinin iki kez onaylayamaması (Planlı — `wp/w2.4-executors-policy`, bu sürümde yok) ve ikinci onaylayanın farklı rolde olması, görevler ayrılığı raporu (Planlı — `wp/w3.2-sod`, bu sürümde yok). `approval_actions` tablosunda `second_approver` sütunu vardır ama bu sürümde hiçbir kod onu doldurmaz.
- Actions sekmesindeki **Revert** düğmesinin çağırdığı sunucu ucu (Planlı — `wp/w2.4-executors-policy`, bu sürümde yok); bugün düğme "Revert is not available on this AutoSecOps server yet." bilgisini gösterir.

Yürütücülerin kendi güvenlik kuralları (korunan roller, yönetim IP'si, TTL üst
sınırı, tek makineye çözümleme) bağlandıklarında geçerli olacaktır ve
[Defender](../../core/integrations/microsoft_defender/EXECUTOR.md),
[Entra ID](../../core/integrations/azure_ad/EXECUTOR.md),
[Palo Alto](../../core/integrations/palo_alto/EXECUTOR.md) belgelerinde yazılıdır.

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
eylemler de uygulanmaz). Böylece "ortam kazanır" ve konsoldan Act'e
geçilemez. Kodun varsayılanı Act görünse de, yukarıda anlatıldığı gibi bu sürümde
bir kişinin onaylamadığı eylem uygulanmaz; ayar, bu davranışı yapılandırma
düzeyinde de sabitler ve denetçiye gösterilebilir kılar.

Diğer otonomi düğmeleri:

- **Otonom soruşturma (orkestratör)**: `ORCHESTRATOR_ENABLED=false` varsayılan; konsoldan
  açıp kapatma ve tüm koşuları durdurma (`POST /api/orchestrator/kill`) `settings.write`
  ister. Bütçeler: `ORCHESTRATOR_MAX_COST`, `ORCHESTRATOR_MAX_HOURLY_COST`,
  `ORCHESTRATOR_MAX_RUNTIME`.
- **Alarm şeritleri**: `ALERT_LANES_ENABLED=false` varsayılan; açıkken eşikler
  `INTENT.md`'nin `alert_lanes:` bölümünden okunur ve uygulanır, kural şeridi
  `suppression_rules` tablosunu okur. Bütçe baskısında hiçbir alarm düşürülmez.
- **Beyan edilen niyet (`INTENT.md`)**: diğer anahtarlar için yalnızca gözlem
  modundadır; daemon açılışta beyan ile etkin değer arasındaki farkı loglar, hiçbir
  şeyi uygulamaz. Elle kontrol: `python -m services.daemon.intent`.
- Kategori × eylem sınıfı başına otonomi katmanları, devre kesici ve "yalnızca insan
  yükseltir" kuralı bu sürümde yoktur (Planlı — `wp/w3.1-autonomy`, bu sürümde yok).

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

Bu sürümde **otomatik saklama politikası yoktur**. Bugünkü davranış:

| Veri | Ne olur |
|---|---|
| Bulgular, vakalar, soruşturmalar, ajan defteri | Otomatik silinmez |
| Yanıtlanmayan onay istekleri | `DAEMON_APPROVAL_EXPIRY_DAYS` (7) gün sonra süresi dolar (satır kalır) |
| Epizodik bellek okuma günlüğü | `DAEMON_CLEANUP_RETENTION_DAYS` (90) gün sonra silinir |
| Bifrost istek günlüğü (`logs.db`) | Bifrost veri dizininde durur; yedeklere girmez |

Elle silme yolları: tek vaka silme (`cases.delete`), tüm bulguları silme
(`DELETE /api/findings/all`, `findings.delete`), tüm soruşturmaları temizleme
(`POST /api/orchestrator/investigations/purge`, `settings.write`). Bu silmeler
geri alınamaz ve bu sürümde zincirli bir imha kaydı üretmez.

Veri sınıfı başına saklama süresi, KVKK periyodik imhası, vakada yasal saklama
bayrağı ve imha raporu (Planlı — `wp/w3.5-retention`, bu sürümde yok). `retention_policies` tablosu şemada vardır ama bu sürümde okunmaz.

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

Bu sürümde **olmayanlar**: denetim ve defter olaylarının syslog (RFC 5424/TLS) ya da
HTTPS ile müşterinin SIEM'ine akışı (Planlı — `wp/w3.6-audit-export`, bu sürümde yok); onay ve vaka denetim kayıtlarının hash zincirine alınması ve zincir başlarının Ed25519 imzalı kontrol noktası (Planlı — `wp/w1.10-audit-chain`, bu sürümde yok); vaka başına imzalı kanıt paketi (Planlı — `wp/w3.7-evidence-pack`, bu sürümde yok).
Geçiş döneminde SIEM'e aktarım için yukarıdaki tabloları salt okuma yetkili bir
veritabanı rolüyle periyodik okumanızı öneririz.

## Yedekleme ve geri yükleme

`python -m core.backup` PostgreSQL'in tutarlı bir dökümünü (`pg_dump -Fc`), durum
dizinini (`secrets.enc` ve `master.key` dahil), soruşturma çalışma dizinini,
`INTENT.md`'yi, depo kökündeki `.env`'i (varsa) ve isteğe bağlı olarak Bifrost veri
dizinini **şifreli bir restic deposuna** yazar ve dönmeden önce anlık görüntüyü
doğrular; doğrulanamayan anlık görüntü silinir. Sır deposu ile anahtarı aynı
yedektedir: yedeğin gizliliği restic parolasına bağlıdır, parolayı yedekten ayrı
saklayın.

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

Geri yükleme (`--test` olmadan) değiştirme sonrası şunları yapar: JWT anahtarını
döndürür (tüm oturumlar düşer), MFA sırlarını yeni anahtarla yeniden şifreler,
bekleyen onayları reddeder ve bir denetim satırı yazar. Bu sayede eski bir anlık
görüntüden "geri dönen" bir onay istemi uygulanamaz.

Doğrudan kullanım: `python -m core.backup create --repo ... --passphrase-file ...`,
`python -m core.backup restore ... --test`, `python -m core.backup run`.

### Kubernetes

Helm grafiğinde bu sürümde zamanlanmış yedek CronJob'u yoktur (Planlı — `wp/w3.9-daemon-standby`, bu sürümde yok). Postgres PVC'sinin depolama düzeyinde anlık görüntüsünü ya da kurumunuzun PostgreSQL yedek aracını kullanın; kimlik bilgilerini Secret/ExternalSecrets ile verdiyseniz durum dizini yeniden üretilebilir.

RPO/RTO hedefleri (15 dk / 4 saat) ve otomatik geri yükleme testi plan hedefidir; bu
sürümde ölçülmüş bir değer yoktur (Planlı — `wp/w3.9-daemon-standby`, bu sürümde yok).
