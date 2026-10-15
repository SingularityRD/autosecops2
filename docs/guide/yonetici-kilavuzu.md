# Yönetici kılavuzu

> **English summary.** Day-to-day administration of AutoSecOps at `main` @ `b8795def`: the five built-in roles and their permissions, local accounts with
> TOTP MFA, lockout and session revocation, OIDC single sign-on with group →
> role mapping and break-glass local accounts, FIPS 140-3 mode (checkpoint and
> evidence-pack signatures stay Ed25519; `ssh_tunnel` unsupported), integrations and where their credentials are stored, the response
> approval flow (human approval, per-category autonomy tiers with a circuit
> breaker, response policy with protected assets and hourly limits, executor
> registry for Cloudflare / Defender / Entra ID / PAN-OS, TTL expiry and revert,
> four-eyes approval with an optional distinct-role rule, the
> segregation-of-duties report; models cannot approve, approvals are bound to
> the tool call's arguments (refused above 64 KB), people decide on the
> AI Decisions → Pending Approvals screen, approved agent MCP tools still bypass the response
> policy, an open risk), the Assist/Act switch and the recommended
> regulated-sector setting `DAEMON_FORCE_APPROVAL=true`, the local model lane
> and lessons, retention policies, KVKK purge and legal hold, which audit
> records exist and how to verify them (`python -m core.audit.verify`, signed
> checkpoints, per-case evidence packs), SIEM audit export over syslog/HTTPS
> (free-text PII redaction is best effort), encrypted restic backups with tested
> restore, the Helm backup CronJob and daemon hot standby, where the 0.7 →
> 2.0 upgrade procedure lives, and the desktop app (macOS dmg, Linux AppImage,
> Windows installer as a preview): requirements, first run, data and log
> locations, manual update, uninstall, support bundle and signature checks.

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
| Kullanıcı oluşturma / güncelleme (`POST /api/users/`, `PUT /api/users/{user_id}`) | `users.write`; eş ya da üst hesabın e-postası, rolü ve etkinliği yalnızca Admin'ce değişir |
| SSO yapılandırmasını görme (`GET /api/auth/sso/admin/config`) | `settings.write` **ve** `users.write` |
| SSO sağlayıcısı ekleme, değiştirme, silme; giriş politikası (`PUT /api/auth/sso/admin/providers/{provider_id}`, `DELETE ...`, `PUT /api/auth/sso/admin/login-policy`) | yalnızca yönetici: Admin rolü ya da tüm rollerin tüm izinleri |
| SIEM aktarımı yapılandırmasını ve durumunu görme (`GET /api/compliance/audit-export/config`, `.../status`) | `settings.read` |
| SIEM aktarımını yapılandırma, test olayı gönderme (`PUT /api/compliance/audit-export/config`, `POST /api/compliance/audit-export/test`) | `settings.write` |
| Kullanıcı silme (`DELETE /api/users/{user_id}`; kendini silemez) | `users.delete` |
| Yapılandırma, AI sağlayıcıları, bütçe, orkestratör aç/kapa/öldür, otonomi anahtarı | `settings.write` |
| Entegrasyon kaydetme (`POST /api/config/integrations`) | `integrations.write` |
| Müdahale eylemini onaylama/reddetme (`POST /api/v1/approvals/{action_id}/approve`, `.../reject`), duraklatılmış iş akışını sürdürme/iptal | `ai_decisions.approve` |
| Otonomi katmanlarını ve denetim kaydını görme (`GET /api/autonomy/tiers`, `GET /api/autonomy/audit`) | `settings.read` |
| Otonomi katmanı yazma, devre kesiciyi çalıştırma (`PUT /api/autonomy/tiers/{category}/{action_type}`, `POST /api/autonomy/check`) | `settings.write`; hizmet hesabı 403 alır |
| Görevler ayrılığı raporu ve dışa aktarımı (`GET /api/response/segregation`, `.../segregation/export`), dört göz onayı ayarını görme (`GET /api/response/four-eyes`) | `users.read` |
| Sınıf başına farklı rol koşulunu açma/kapama (`PUT /api/response/four-eyes/{action_type}`, gerekçe zorunlu) | `settings.write` |
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
| Vaka kanıt paketini indirme (`GET /api/cases/{case_id}/evidence-pack`) | `cases.read` |
| Dersleri görme (`GET /api/lessons`, `GET /api/lessons/{lesson_id}`, `.../events`) | `findings.read` |
| Ders önerme, replay, geri alma (`POST /api/lessons`, `POST /api/lessons/{lesson_id}/replay`, `.../rollback`) | `findings.write` |
| Dersi etkinleştirme (`POST /api/lessons/{lesson_id}/promote`; öneren kendi dersini etkinleştiremez, 403) | `ai_decisions.approve` |
| Kural kaynağı ekleme, silme, güncelleme, yeniden yükleme (`POST /api/detection-rules/sources`, `DELETE /api/detection-rules/sources/{source_id}`, `.../update`, `POST /api/detection-rules/update-all`, `POST /api/detection-rules/reload`) | `settings.write` |
| AI bileşen yapılandırması, Kafka ayarı, federasyon ayarı, ajan ve iş akışı açma/kapama, iş akışı koşusu silme, maliyet yeniden hesabı (`POST /api/analytics/recalculate-cost`) | `settings.write` |
| Federasyon kaynağını düzenleme ve hemen çekme (`PATCH /api/federation/sources/{source_id}`, `.../poll-now`) | `integrations.write` |
| Dosya/metin/S3 alımı (`POST /api/ingest/upload`, `POST /api/ingest/ingest-string`, `.../sync-s3-folder`, `.../s3-file`), gürültü işaretleme (`/api/findings/{finding_id}/noise`), soruşturma incelemesi, AI kararına geri bildirim (`POST /api/ai/decisions/{decision_id}/feedback`) | `findings.write` |
| Beceriler, özel ajanlar, özel iş akışları, iş akışı üretme, sohbet içe aktarma, bulgu alımı, vaka raporu üretme, soruşturma başlatma/durdurma, AI karar kaydı oluşturma (`POST /api/ai/decisions`) | `ai_chat.use` |
| SLA politikaları (`/api/sla-policies`), vaka şablonları (`/api/cases/templates`) | `cases.write` |

CI'daki `tests/security/test_route_permissions.py` iki şeyi sınar. Birincisi,
testin rota listesindeki her rota, izni olmayan bir kullanıcıya 403 döner. Bu
listede yukarıdaki tablonun onay, geri alma, iş akışı sürdürme, QA, kanarya, giden
webhook, saklama, entegrasyon kaydetme, tüm bulguları silme, kanıt paketi, SIEM
aktarımı ve kural kaynağı rotaları ile W0.11'in kapıladığı rotalar vardır. Ders (`/api/lessons`)
rotaları bu listede yoktur; rol matrisinde vardır.
Kullanıcı yönetimi (`/api/users/`) ve düzenleyici sayaç rotaları bu listede
**yoktur**. Bu rotaların izin denetimi kodda vardır ama bu testle sabitlenmez.
İkincisi, API'deki her yazma rotası ya bir izin bağımlılığı taşır ya da
gözden geçirilmiş `tests/security/auth_only_write_routes.txt` listesindedir. O
listedeki rotalar yalnızca oturum ister. W0.11 bu listeyi küçülttü; kalanlar
bilinçlidir: kimlik ve kendi hesabı (`/api/auth/...`, `PUT /api/auth/me`), kendi
sohbetleri, izni yardımcı işlevde denetlenenler (`PUT /api/users/{user_id}`,
`/api/services/...`, `/api/exclusions`), POST ile yapılan okumalar
(`POST /api/cases/search`, `POST /api/findings/export`,
`POST /api/analytics/estimate-cost`) ve bulgu açılınca üretilen zenginleştirme
(bkz. [tehdit modeli R28](tehdit-modeli.md#açık-riskler)).
Ayrıca `tests/security/test_route_role_matrix.py`, API'nin **her** rotası için
her yerleşik rolün sonucunu (`allow`, `deny`, `conditional`)
`tests/security/route_role_matrix.json` dosyasına karşı sınar. Kullanıcı yönetimi ve
düzenleyici sayaç rotaları da bu matristedir. `allow` ve `deny` hücreleri gerçek
HTTP isteğiyle doğrulanır. Bir rotanın kapısı ya da bir rolün izinleri değişirse
dosya yeniden üretilip gözden geçirilene kadar CI düşer.

### Rol atama kuralları

- Bir kullanıcı yalnızca **kendi sahip olduğu tüm izinleri** veren bir rolü
  atayabilir. Örneğin Manager `users.write` taşır ama `users.delete` taşımadığı için
  Admin rolünü atayamaz.
- Admin rolü olmayan biri bir hesabın e-postasını, rolünü ya da etkinliğini yalnızca
  kendisi için ya da izinleri kendisininkinden kesin olarak az olan bir hesap için
  değiştirebilir veya o hesabı silebilir. Bir Admin'in, eşin ya da üstün hesabı
  değişmez (403). E-posta parola sıfırlamanın gittiği yer olduğu için bu kural hesap
  ele geçirmeyi kapatır (W1.9, W0.13). Son etkin Admin düşürülemez.
- Rolü ya da e-postası değişen kullanıcının tüm oturumları anında geçersiz olur
  (kullanıcı başına iptal zamanı, Redis'te).
- Hizmet hesapları (`users.service_account`) yalnızca Viewer olabilir; başarısız
  girişlerle kilitlenmezler, SSO ile giremezler ve e-postaları `PUT /api/auth/me`
  ile değiştirilemez; parola sıfırlama e-postası almazlar. Bugün tek hizmet hesabı Medic ağ geçididir ve
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
| CSRF (çift gönderim çerezi) | açık; kodun varsayılanı **yalnızca raporlama**, Helm ve `env.example` zorlar | `VIGIL_CSRF_ENABLED`, `VIGIL_CSRF_REPORT_ONLY` |
| FIPS 140-3 modu | kapalı | `FIPS_MODE` (bkz. aşağıda) |

Önerilen üretim ayarları: `VIGIL_CSRF_REPORT_ONLY=false` (kodun varsayılanı
yalnızca loglar; Helm grafiği ve `env.example` engeller), `DEV_MODE=false`
(Helm ve `env.example` varsayılanı). `DEV_MODE=true` tüm kimlik doğrulamayı kapatır
ve her isteği tam yetkili sahte bir yönetici olarak çalıştırır; açılışta ve
erişilebilir bir adreste bunu yüksek sesle loglar ama **engellemez**. Üretimde asla
açmayın; `JWT_SECRET_KEY` olmadan backend `DEV_MODE=false` iken açılmaz.

**MFA (TOTP).** Her kullanıcı kendi hesabında MFA'yı açar (`/api/auth/mfa/setup`
→ `/api/auth/mfa/verify`); 10 tek kullanımlık kurtarma kodu üretilir. TOTP sırrı
veritabanında şifreli durur. Bu sürümde MFA'yı bir rol için **zorunlu kılan bir
ayar yoktur**; yönetici ve onaylayıcı hesaplarında MFA'yı süreçle zorunlu tutun ve
düzenli olarak kullanıcıların `mfa_enabled` alanını denetleyin. MFA açıkken onu
kapatmak (`DELETE /api/auth/mfa`) ve yeni kurtarma kodu üretmek
(`POST /api/auth/mfa/recovery-codes`) geçerli bir TOTP ya da kurtarma kodu ister;
MFA açıkken yeniden kurulum 409 döner. Böylece çalınmış bir oturum MFA'yı sessizce
kapatamaz. MFA'yı kapatmak kurtarma kodlarını da siler.

**Hız sınırları.** Giriş, ilk hesap, parola değiştirme, MFA doğrulama ve kurtarma
kodu uçları dakikada 5; parola sıfırlama isteği saatte 3, sıfırlamanın tamamlanması
saatte 5 ile sınırlıdır.

### Parola sıfırlama

**Kullanıcının akışı.** Giriş ekranındaki **Forgot password?** bağlantısı e-posta
soran bir istek ekranı açar (`POST /api/auth/password-reset/request`). Yanıt hesap
olsun olmasın, etkin ya da SSO'lu olsun aynıdır; hangi e-postanın kayıtlı olduğunu
sızdırmaz. Yanıt yalnızca posta yapılandırmasına göre değişir (`delivery` alanı):

| `VIGIL_EMAIL_BACKEND` | `DEV_MODE` | Kullanıcının gördüğü |
|---|---|---|
| `smtp` | herhangi | "If that email matches an active account, a reset link has been sent." |
| `console` (varsayılan) | `false` | E-posta kurulu olmadığı, bağlantı **gönderilmediği** ve AutoSecOps yöneticisine başvurması gerektiği |
| `console` | `true` | Bağlantının ya da belirtecin sunucu loguna yazıldığı (yalnızca geliştirme) |

Hava boşluklu (air-gap) kurulumlarda SMTP genellikle yoktur: ekran bu durumda
"bağlantı gönderildi" demez, kullanıcıyı yöneticiye yönlendirir. SSO sağlayıcısı
tanımlıysa ekran ayrıca SSO kullanıcılarının parolasını kimlik sağlayıcıda
sıfırlaması gerektiğini yazar.

Bağlantı `/reset-password#token=…` sayfasını açar. Belirteç adresin **parça**
(fragment, `#`) kısmındadır; tarayıcı parçayı sunucuya hiç göndermez, bu yüzden
belirteç erişim loglarına, ters vekil (proxy) loglarına ya da `Referer`'a düşmez.
Bu sürümden önce verilmiş `?token=…` biçimli bağlantılar da açılır. Ek önlem
olarak backend, HTTP erişim logunda (uvicorn) adı `token`, `code`, `state`,
`password`, `secret`, `key` ya da `reset` içeren her sorgu parametresinin
değerini `[REDACTED]` yapar; erişim logu kapatılmaz. Sayfa belirteci okur okumaz
adres çubuğundan ve tarayıcı geçmişinden siler; sunucu bu sayfayı
`Referrer-Policy: no-referrer` ile gönderir. Yeni parola aynı parola
politikasından geçer (uzunluk, zxcvbn, son 5 parola). Başarılı sıfırlama kilidi
kaldırır ve hesabın tüm açık oturumlarını kapatır.

Bağlantı `PASSWORD_RESET_TTL_SECONDS` süresince (varsayılan 1 saat) geçerlidir ve
**bir kez** kullanılır: belirteç, parola denetiminden önce harcanır; politikaya
takılan bir deneme de bağlantıyı tüketir, kullanıcı yeni bağlantı ister. Tek
kullanım Redis'te tutulur; Redis'e ulaşılamazsa sıfırlama **yapılmaz** ve kullanıcı
"Password reset is unavailable right now" (503) görür; Redis dönünce aynı bağlantı
yeniden denenebilir. Bağlantı hesabın o anki e-posta adresine **ve parolasına**
bağlıdır: adres ya da parola değişirse (parola değiştirme, başka bir sıfırlama)
bekleyen tüm bağlantılar geçersiz olur. Bu sürüme yükseltmeden önce verilmiş,
kullanılmamış bağlantılar da bu yüzden geçersizdir; kullanıcı yenisini ister. Akış
zorlanan CSRF altında çalışır (sayfa yüklemesi `csrf_token` çerezini verir).
E-postadaki bağlantının konsol adresi `VIGIL_FRONTEND_URL`'den gelir; boşsa e-posta
yalnızca belirteci içerir.

**Kimler sıfırlayamaz.** SSO ile oluşmuş (parolasız) hesaplar ve hizmet hesapları
(Medic ağ geçidi) ne e-posta alır ne de yönetici bağlantısı. SSO hesabı bir
bağlantıyı yine de açarsa "This account signs in with single sign-on…" iletisiyle
reddedilir; parolası kimlik sağlayıcıda sıfırlanır. Hizmet hesabının parolası
`python -m core.auth.service_account ensure` ile döndürülür. Devre dışı hesaplar
önce yeniden etkinleştirilmelidir.

**Yöneticinin verdiği bağlantı (posta yokken).** Sunucuya erişimi olan bir
operatör tek kullanımlık bir bağlantı üretir ve kullanıcıya güvenilir bir kanaldan
iletir. Araç parolayla hiç uğraşmaz; parolayı kullanıcı aynı `/reset-password`
ekranında kendisi belirler. Bağlantı çalışan backend'in `JWT_SECRET_KEY`'iyle
imzalanır, bu yüzden araç backend ile aynı ortamda çalışmalıdır.

> **Güven sınırı.** Aracı çalıştırabilen kişi backend'in `JWT_SECRET_KEY`'ine
> erişebilir; bu, sunucu ya da konteyner üzerinde root/kök erişimine denktir (aynı
> anahtarla her hesap için oturum belirteci de üretilebilir). Araç kimseyi kimlik
> doğrulamasından geçirmez: denetim kaydındaki `cli:<operatör>` adı **operatörün
> kendi beyanıdır**. Bu aracı yalnızca sunucuda zaten tam yetkili olan kişilere
> açın; kimin çalıştırdığını işletim sistemi, `sudo`, `docker exec` ya da
> Kubernetes denetim loglarıyla ayrıca doğrulayın.



```bash
# Tek sunucu (yerel kurulum): hesapları listele, sonra bağlantı üret
scripts/reset-password.sh --list
scripts/reset-password.sh ana@example.com --operator "Ayşe Yılmaz"

# Docker Compose
docker exec deeptempo-backend python scripts/reset_password.py ana@example.com --operator ayse

# Kubernetes (backend Deployment adını `kubectl get deploy` ile bulun)
kubectl -n <ad-alanı> exec deploy/<backend-deployment> -- python scripts/reset_password.py ana@example.com --operator ayse
```

`--list` her hesabı kullanıcı adı, e-posta, rol, tür (`local` / `sso-only` /
`service`) ve durumuyla gösterir. `--base-url` bağlantının konsol adresini verir
(varsayılan `VIGIL_FRONTEND_URL`). `--operator` verilmezse `SUDO_USER` ya da işletim
sistemi kullanıcısı kaydedilir; kişisel adınızı vermenizi öneririz, çünkü
konteyner içinde bu genellikle bir hizmet kullanıcısıdır.

Her bağlantı **ekrana basılmadan önce** denetim kaydına yazılır; kayıt yazılamazsa
bağlantı gösterilmez. Kayıt `case_audit_logs` tablosundadır (`entity_type='user'`,
`action='reset_link_issued'`, `changed_by='cli:<operatör>'`) ve kimin, kimin için,
ne zaman verdiğini ve bitiş zamanını tutar; belirtecin kendisi bu kayda, araç ve
backend loglarına yazılmaz (araç bağlantıyı yalnızca kendi terminal çıktısına
basar; o çıktıyı saklamayın). Tek istisna geliştirme kipidir: `DEV_MODE=true` ve
posta yokken backend e-postadaki bağlantıyı bilerek sunucu loguna yazar; üretimde
`DEV_MODE` kapalıdır. Satır denetim zincirine girer (`python -m core.audit.verify` ile
doğrulanır) ve SIEM aktarımı açıksa `case_audit` kaynağından
`case.user.reset_link_issued` olayı olarak gider. Kullanıcının bağlantıyı
kullanması ayrıca `password_reset` kimlik doğrulama olayı olarak kaydedilir.

**SSO (OIDC).** Yönetici **Ayarlar → System → Single sign-on** bölümünden bir ya
da daha çok OIDC sağlayıcısı tanımlar (türler: Entra ID, Okta, Keycloak, genel
OIDC). Giriş ekranı her etkin sağlayıcı için bir "Sign in with …" düğmesi gösterir.
Akış Authorization Code + PKCE'dir; geri dönüşte `state` (tek kullanımlık, Redis'te
10 dk), `nonce`, ID token imzası (sağlayıcının JWKS'i, yalnızca RS256/ES256),
`iss`/`aud`/`azp`/`exp`/`iat` ve saat kayması denetlenir. Başarılı SSO girişi yerel
girişle aynı oturum çerezlerini verir; oturum süreleri ve iptal aynıdır.

- **Geri dönüş adresi.** Sağlayıcıda kaydedilecek adres, konsol adresinin
  arkasına eklenen `/api/auth/sso/{provider_id}/callback` yoludur; konsol adresi
  `VIGIL_FRONTEND_URL`'den (boşsa isteğin adresinden) gelir. Yapılandırma ekranı
  etkin adresi gösterir; sağlayıcı başına elle de verilebilir.
- **İstemci sırrı** sır deposunda (`OIDC_CLIENT_SECRET_<ID>`) tutulur; API onu
  asla geri döndürmez.
- **Hesap ve rol.** Kullanıcı ilk girişte oluşturulur. Rolü sağlayıcıdaki grup ya
  da claim eşlemesinden gelir; eşleşme yoksa sağlayıcının varsayılan rolü verilir
  (konsolda "Default role"; varsayılanı Viewer, Admin olamaz, ama Manager gibi
  başka bir role ayarlanabilir; Viewer bırakmanızı öneririz). Admin rolüne eşleme
  yalnızca sağlayıcıda açıkça izin verilmişse yapılır. Var olan bir yerel hesaba
  doğrulanmış e-postayla bağlanma da yalnızca açıkça açılırsa olur. Bu iki ayarı
  açık kaydetmek Admin rolü ister. Eşlemeyi kaydeden kişi, eşlenen her rolün tüm
  izinlerine sahip olmalıdır. Hizmet hesapları SSO ile giremez. SSO ile oluşmuş
  (parolasız) hesaba parola sıfırlama e-postası gitmez.
- **Yerel girişi kapatma.** Giriş politikası
  (`PUT /api/auth/sso/admin/login-policy`) yerel parola girişini break-glass
  hesapları ve hizmet hesapları dışında kapatabilir. Kapatmak için en az bir etkin
  sağlayıcı ve en az bir etkin Admin break-glass hesabı gerekir; parolasız bir hesap
  break-glass olamaz. Yerel giriş kapalıyken son etkin sağlayıcı silinemez ya da
  kapatılamaz (409). Kapalıyken diğer hesapların parolayla girişi 403 alır.
- **Kayıt.** Her SSO girişi ve başarısızlığı `config_audit_log`'a
  (`config_type='auth_event'`, `sso_login` / `sso_failure`) yazılır.
- **Kapsam dışı.** SAML, SCIM, IdP'den başlatılan giriş ve IdP oturumu kapatma
  (front/back-channel logout) yoktur. SAML gerekiyorsa Keycloak ya da Dex gibi bir
  OIDC aracı kullanın. İşten ayrılan kişiyi IdP'de kapatmak yeni girişi engeller;
  açık oturumu düşürmek için hesabı AutoSecOps'ta da devre dışı bırakın.

**FIPS 140-3 modu.** `FIPS_MODE=true` (Helm: `config.FIPS_MODE`) iken API, daemon
ve worker yalnızca OpenSSL 3 FIPS sağlayıcısı hem Python `hashlib` hem
`cryptography` için etkinse başlar; değilse `configuration error: FIPS_MODE=true …`
yazıp 78 ile çıkar. Bunun için FIPS etkin ayrı bir imaj gerekir (varsayılan imaj
FIPS sağlayıcısı içermez). FIPS modunda yeni parola ve kurtarma kodu hash'leri
PBKDF2-HMAC-SHA256 ile üretilir (`PASSWORD_PBKDF2_ITERATIONS`, varsayılan 600 000).
Eski bcrypt parola hash'i doğru parolayla ilk girişte yeniden yazılır. Göç bitince
`FIPS_LEGACY_BCRYPT_VERIFY=false` giriş parolalarında bcrypt doğrulamasını kapatır.
`PASSWORD_HASH_SCHEME=pbkdf2_sha256` FIPS modu olmadan da seçilebilir; FIPS modunda
`bcrypt` seçmek yapılandırma hatasıdır. Bu sürüme yükseltirken, önceden verilmiş ve
kullanılmamış parola sıfırlama bağlantıları geçersiz olur (imza SHA-256'ya geçti).
**Bilinen boşluklar:** denetim kontrol noktası ve kanıt paketi imzaları FIPS modunda
da Ed25519 kalır ve FIPS onaylı sayılmaz. Veritabanı proxy'sinin `ssh_tunnel` türü
FIPS modunda desteklenmez; TLS'li doğrudan bağlantı ya da HTTP proxy kullanın. İmaj
hazırlığı, göç ve ayrıntı: [docs/fips.md](../fips.md).

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

### Bağlayıcı destek durumu

Katalogdaki her MCP sunucusunun tek bir destek durumu vardır
(`clients/web/src/screens/settings/integrationsData.ts`):

| Durum | Bağlayıcılar | Konsolda |
|---|---|---|
| Destekli | Listede adı geçmeyen her bağlayıcı (ör. Splunk (Self-Hosted), Elastic, Okta, VirusTotal) | Etiketsiz |
| Deneysel (**Experimental**) | CrowdStrike Falcon, SentinelOne, Microsoft Sentinel, resmî Splunk MCP sunucusu, Google SecOps, Google Threat Intelligence, Joe Sandbox, vStrike, Atomic Red Team, CAPE Sandbox | Bir bağlayıcıyı açan her ekranda etiket: Add integration kartı, Connected tablosu, Ayarlar kurulum çekmecesi, ilk kurulumdaki veri kaynağı seçimi ve formu (formda gerekçe metniyle) |
| Sunulmuyor (WIP) | Carbon Black, Hybrid Analysis, ANY.RUN, AlienVault OTX, Palo Alto, Slack, MISP, IP Geolocation, URL Analysis, Microsoft Defender, Entra ID (Azure AD), Microsoft Teams | Add integration'da yok; önceden açılmışsa Connected tablosunda WIP etiketiyle |

"Destekli", canlı bir ürün örneğine karşı test edilebilen bağlayıcı demektir:
bunlar AutoSecOps'un temel aldığı açık kaynak projenin haftalık canlı testlerinde
çalışır. Bu canlı test takımı AutoSecOps deposunda henüz yoktur (ertelendi:
satıcı hesapları ve CI'dan dış erişim gerektirir). Deneysel bağlayıcılar ise canlı
bir ürün örneğine karşı hiç çalıştırılmadı; çalışmayabilir. Etiket kapatılamaz ve kurulum tarafından
"destekli" olarak işaretlenemez; bir bağlayıcı yalnızca canlı bir testi
olduğunda bu durumdan çıkar. Birini kullanırsanız sonucu bir destek paketiyle
birlikte AutoSecOps desteğine bildirin (bkz.
[Loglar ve destek paketi](#loglar-ve-destek-paketi)).

**Okta.** Okta MCP sunucusu backend imajına bir commit'e sabitlenmiş uv aracı
olarak gömülüdür; başlatmak için internet gerekmez, air-gap kurulumda da açılır.
Çağrılar müşterinin kendi Okta kuruluşuna gider: air-gap'te o adres
`networkPolicies.egress.extraCIDRs` listesinde olmalıdır. Ayarlarda yalnızca alan
adı (ör. acme.okta.com, `https://` olmadan) ve API belirteci girilir.

## Müdahale politikası ve onaylar

### Bir eylemin yaşam döngüsü (bu sürüm)

1. **Öneri.** Daemon'un yanıtlayıcısı, orkestratör, bir iş akışı ya da MCP aracı
   `create_approval_action` bir eylem önerir. Öneri, satır oluşmadan önce müdahale
   politikasından geçer: korunan bir varlığa yönelen ya da saatlik sınırı aşan öneri
   hiç oluşmaz. Geçen öneri `approval_actions` tablosuna yazılır (eylem tipi, hedef,
   güven, gerekçe, geri alınabilirlik, tekrar önleme anahtarı).
2. **Onay kapısı ve otonomi katmanı.** Satırın insan beklemesi gerekip
   gerekmediğine kod karar verir ve kararı veren kuralı satıra yazar
   (ör. `autonomy.tier=approve`):
   - `DAEMON_FORCE_APPROVAL=true` ya da konsolda Assist → her eylem insan bekler;
   - geri alınamaz eylem → her zaman insan bekler, hiçbir zaman otomatik onaylanmaz;
   - dört göz onayı isteyen eylem → her zaman insan bekler;
   - güven `DAEMON_CONFIDENCE_THRESHOLD` (0.90) altındaysa → insan bekler;
   - ayrıca alarm kategorisi × eylem sınıfı için yapılandırılmış **otonomi
     katmanı** uygulanır. Watch'ta satır hiç oluşmaz. Suggest ve Approve'da satır
     insan bekler. Varsayılan Approve'dur: yüksek güven tek başına bir eylemi
     serbest bırakmaz. Yalnızca Autonomous katmanı, yukarıdaki kuralların hiçbiri
     eylemi tutmuyorsa, onu kişisiz serbest bırakır (koşullar için bkz.
     [Otonomi](#otonomi)); süre katmanın üst sınırına kısılır.
   Uygulanan katman satırda `parameters.autonomy` altında kayıtlıdır. İş akışı
   onay noktaları (`workflow_phase`) katmanlara tabi değildir.
3. **Karar.** `ai_decisions.approve` iznine sahip bir kişi onaylar ya da gerekçeyle
   reddeder (konsolda onay kuyruğu / "Needs you"). Onaylayanın adı ve zamanı satıra
   yazılır; her karar, karar verenin o anki rolüyle `approval_decisions`'a da eklenir.
   Kimlik eylemleri (`disable_user`, `revoke_sessions`) **dört göz onayı** ister:
   ilk onay satırı `pending` bırakır, ikinci onay farklı bir kullanıcıdan gelmelidir
   (büyük/küçük harf duyarsız karşılaştırma). Aynı kişinin ikinci onayı 409 ile
   reddedilir. Bir sınıf için farklı rol koşulu açıksa ikinci onaylayan, birincinin
   onay anındaki rolünden farklı bir rolde olmalıdır; aynı rol ya da bulunamayan
   rol de 409 alır.
4. **Uygulama.** Daemon'un yanıtlayıcı döngüsü onaylı satırları en eskiden
   başlayarak uygular; hiçbir yürütücünün alamayacağı satırlar kuyruğu tıkamaz. Her satır
   önce yeniden politikadan, sonra yürütücü kayıt defterinden geçer. **Bir kişinin
   onaylamadığı satır uygulanmaz; tek istisna Autonomous katmanının serbest
   bıraktığı satırdır.** Bu satır için katman, politikadan sonra ve yürütücüden önce
   yeniden kararlaştırılır. Artık Autonomous değilse (ör. devre kesici katmanı
   düşürdüyse) satır onay kuyruğuna döner. Politika reddi satırı `failed` yapar
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
   ayrıntısı konsolda gösterilir. Süreç geri alma sırasında ölürse yarım kalan
   geri alma talebi 1 saat sonra yeni bir talebe devredilir; yeni talep önce
   eylemin hâlâ yürürlükte olup olmadığını doğrular. Geri alma satırları onaylanamaz
   ve reddedilemez.
7. **İzleme.** Vaka sayfasındaki **Actions** sekmesi önerildi → onaylandı → uygulandı
   → doğrulandı → süresi doldu/geri alındı adımlarını ve kararı veren kuralı gösterir
   (`GET /api/cases/{case_id}/actions/timeline`).
8. **Süre aşımı.** Yanıtlanmayan onay istekleri `DAEMON_APPROVAL_EXPIRY_DAYS` (7) gün
   sonra daemon'un temizlik döngüsünde süresi dolmuş sayılır.

Kuru çalıştırma için `DAEMON_DRY_RUN=true`: eylemler loglanır, uygulanmaz.

### Müdahale politikasının ayarları

Politika `system_config` tablosundaki `response.policy` satırından (JSON) okunur.
Konsolda yalnızca farklı rol koşulu için bir ekran vardır; diğer anahtarlar için
yoktur. Anahtarlar:

| Anahtar | Anlamı | Varsayılan |
|---|---|---|
| `protected_targets` | Hiçbir eylemin hedef alamayacağı host, hesap, IP ya da aralıklar | boş |
| `protected_tags` | Bu etiketi taşıyan varlık korunur (varsayılanlara eklenir) | `domain_controller`, `protected`, `break_glass`, `tier0`, `critical_infrastructure` |
| `asset_tags` | Varlık → etiket listesi eşlemesi | boş |
| `hourly_limits`, `default_hourly_limit` | Tür başına saatlik en çok eylem | `isolate_host`, `disable_user`, `revoke_sessions` için 10; diğerleri 20 |
| `four_eyes_types` | Dört göz onayı isteyen türler (varsayılanlara eklenir) | `disable_user`, `revoke_sessions` |
| `distinct_role_types` | İkinci onaylayanın farklı rolde olmasını isteyen türler; her biri dört göz onayı türü de olur. Ayarlar → System → Segregation of duties ekranından (gerekçe zorunlu) ya da `PUT /api/response/four-eyes/{action_type}` ile değiştirilir; değişiklik `config_audit_log`'a yazılır | boş |

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
araçları sunmaz. İş akışları onay noktasında bekler. `/internal/tools/invoke`
onaylanmış bir onay noktası olmadan çağrıyı reddeder. Onay noktası, kişiye çalışacak
aracın adını ve argümanlarını gösterir (`Tool: …`, `Arguments: …`) ve onay o
argümanlara bağlıdır: farklı argümanla gelen çağrı reddedilir. Tabloda olmayan bir
araç, adı açıkça okuma fiiliyle başlamıyorsa en kısıtlayıcı sınıfa (`destructive`)
düşer. Bu kural CI'da `tests/unit/_ratchets/test_no_ungated_write_tools.py` ile
sayılır (onaysız yazma aracı = 0).

`decision` sınıfı (onaylamak, reddetmek) yalnızca insana aittir: hiçbir model
yüzeyi (sohbet, iş akışları, AutoSecOps'un `/mcp` sunucusu, `/internal/tools/invoke`)
bir onayı veremez ya da reddedemez. Önceki sürümde `/mcp` sunucusu
`approve_action` ve `reject_action` araçlarını sunuyordu; MCP ile bağlanan bir model
kendi önerdiği eylemi onaylayabiliyordu. W1.7b bu araçları kaldırdı: model artık
kendi eylemini onaylayamaz. Onları çağıran bir MCP istemcisi ya da betik hata alır.
Karar yalnızca kişinin konsoldaki **AI Decisions → Pending Approvals** ekranından (iş akışı
onay noktaları için iş akışı koşusunun faz kapısından) ya da kişinin kendi
oturumuyla `POST /api/v1/approvals/{action_id}/approve` / `.../reject` isteğiyle
verilir. Otomasyon onay vermek istiyorsa bir kişi yerine değil, Autonomous
otonomi katmanı üzerinden (bkz. [Otonomi](#otonomi)) çalışmalıdır. CI'da
`tests/unit/_ratchets/test_no_model_approvals.py` sınar.

**Onay ekranında ne görünür.** Araç çağrısına bağlı onay, aracın adını, hedef
alanlarını (`machine_id`, `hosts`, `ips`, `user_ids` gibi; büyük/küçük harf ve
`_`/`-` farkı gözetilmez) ve kanonik argümanların **tamamını** gösterir. Hedef
değeri en çok 200 karakterle gösterilir, kesilirse `… (N chars)` eki taşır. Satır
sonu, kontrol karakterleri ve görünmez ya da yön değiştiren Unicode karakterleri
`\n`, `\uXXXX` olarak kaçışlanır; böylece bir değer sahte bir `Arguments:`
satırı başlatamaz ya da bir host adını görsel olarak ters çeviremez. Onay ham
argümanlara bağlıdır. Kanonik argümanları 64 KB'ı (UTF-8) aşan bir araç çağrısı
onaya **park edilmez**: ajan katmanına 413 döner, onay satırı yazılmaz ve çağrı
çalışmaz (kapalı başarısız). Bu sınırı aşan bir iş akışı adımı onaysız kalır ve
hata ile biter; argümanı küçültün.

**Dikkat — açık risk.** Onay noktası onaylandıktan sonra bir MCP aracı (ör.
`mde_isolate`, `aad_disable_user`, `pan_block_ip`, `cb_quarantine`,
`cf_waf_block_ip`) satıcı API'sini doğrudan çağırır. Bu yol yukarıdaki müdahale
politikasından ve yürütücülerden geçmez. Korunan varlık listesi, saatlik sınır,
süre dolumu, geri alma ve dört göz onayı burada uygulanmaz; onay tek
kişiliktir. Onay sorusundaki argümanlar (hedef) çalışacak olanlardır; onaylamadan
önce okuyun. Telafi: bu entegrasyonları iş akışlarında kullanmayın ya da bu araçları
içeren iş akışı onaylarını yalnızca kıdemli kişilere verin (bkz.
[tehdit modeli R2](tehdit-modeli.md#açık-riskler)).

### Görevler ayrılığı raporu

**Ayarlar → System → Segregation of duties** ekranı ve
`GET /api/response/segregation` (izin `users.read`) her eylem için öneren,
onaylayan, ikinci onaylayan ve yürüteni rolleriyle listeler. Tarih aralığı, eylem
türü ve yalnız ihlaller süzgeci vardır. İhlal türleri: `self_approval` (öneren
kendisi onayladı), `same_person`, `missing_second_approver`, `same_role`,
`unknown_role`, `executed_without_approval`. Rol, `approval_decisions`'taki karar
anı kaydından okunur. Kayıt yoksa (tablo öncesi eylemler) kişinin bugünkü rolü
kullanılır ve satır bunu `role_source` ile söyler. Denetçiye vermek için
`GET /api/response/segregation/export?format=csv` (ya da `json`) kullanın.

## Otonomi

Otonomi iki düzeyde belirlenir. Genel anahtarlar her eylem için geçerlidir ve
otonomi katmanlarının üstündedir. Konsolun üst çubuğundaki çip bunları **Assist**
(değişiklikten önce sorar) ya da **Act** olarak gösterir
(`GET /api/config/autonomy`):

| Anahtar | Varsayılan | Etki |
|---|---|---|
| `DAEMON_AUTO_RESPONSE` | `true` | `false` ise daemon hiçbir müdahale eylemi önermez ve **onaylanmış** eylemleri de uygulamaz |
| `DAEMON_FORCE_APPROVAL` | `false` | `true` ise her eylem insan onayı bekler (Assist) |
| `approval.force_manual_approval` (konsoldan, `POST /api/config/force-manual-approval`, `settings.write`) | kayıt yok = Act | Assist'i kalıcı yapar; ortam değişkeni Assist'i zorluyorsa Act kaydı 409 ile reddedilir |

**Düzenlenmiş sektör için önerilen ayar:** `DAEMON_FORCE_APPROVAL=true` (Helm:
`config.DAEMON_FORCE_APPROVAL`) ve `DAEMON_AUTO_RESPONSE=true` (aksi halde onaylanan
eylemler de uygulanmaz). Böylece "ortam kazanır" ve konsoldan Act'e geçilemez.
Kodun varsayılanı Act görünür. Yine de otonomi katmanlarının varsayılanı Approve
olduğu için, bir yönetici bir katmanı Autonomous yapmadıkça bir kişinin onaylamadığı
eylem uygulanmaz. Assist bunu yapılandırma düzeyinde sabitler: Autonomous katmanlar
da insan bekler. Böylece kural denetçiye gösterilebilir olur.

### Otonomi katmanları

**Ayarlar → Limits & autonomy** altındaki matris her alarm kategorisi (`phishing`,
`malware`, `identity`, `network`, `cloud`, `other` ve adı geçmeyenler için `*`) ×
eylem sınıfı için bir katman tutar (`autonomy_tiers` tablosu):

| Katman | Davranış |
|---|---|
| Watch | Eylem yalnızca gözlenir; onay satırı oluşmaz |
| Suggest | Öneri olarak kaydedilir; yalnızca bir kişi serbest bırakır |
| Approve (varsayılan) | Onay kuyruğuna girer; bir kişi onaylar |
| Autonomous | Geri alınabilir, süreli eylem kişisiz çalışır |

Autonomous yalnızca şu koşulların hepsi doğruysa uygulanır, aksi halde eylem
Approve gibi işlenir:

- Sınıf `isolate_host`, `block_ip`, `block_domain`, `waf_block` ya da
  `gateway_block`'tur. Eylem hem satırda hem yürütücü kaydında geri alınabilirdir.
- Sınıf dört göz onayı istemez. Kategori `*` ya da `other` değildir.
- Katmanda bir süre (`max_ttl_seconds`, en çok 7 gün) ve bir güven tabanı
  (`min_confidence`) vardır. Eylemin güveni bu tabana ve
  `DAEMON_CONFIDENCE_THRESHOLD`'a ulaşır. Assist açık değildir.
- Kategorinin QA sınırı tutar: en az 299 basit rastgele incelemeden tek taraflı %95
  Clopper–Pearson yanlış negatif üst sınırı ≤ %1 (Karne'deki değer).

Katmanı yükseltmek (ve her Autonomous yazımı) bir kişi ve bir `https://` kanıt
bağlantısı ister (`PUT /api/autonomy/tiers/{category}/{action_type}`,
`settings.write`). Hizmet hesabı, ajan ya da MCP aracı katman yükseltemez.
**Devre kesici:** kategorinin sınırı okunabilir ve tutmuyorsa katman kalıcı olarak
Approve'a düşürülür, `config_audit_log`'a `system:autonomy-breaker` adıyla yazılır
ve uyarı loglanır. Bu, karar anında, daemon'un 30 saniyelik döngüsünde ve
`POST /api/autonomy/check` ile olur. Katmanı yalnızca bir kişi yeniden yükseltir.
Değişikliklerin kaydı: `GET /api/autonomy/audit` ve ekrandaki denetim listesi.

Kategori koddan gelir. Önce sensörün yazdığı alanlar (MITRE tekniği,
`data_source`), bunlar bir şey söylemiyorsa triage kararının kategorisi kullanılır.
Gönderenin yükte yazdığı kategori alanı okunmaz; eşlenemeyen her alarm `other`'a
düşer ve `other` hiçbir zaman Autonomous olamaz. Autonomous bir eylem de müdahale
politikasından (korunan varlıklar, saatlik sınır) geçer.

**Düzenlenmiş sektör için öneri:** `DAEMON_FORCE_APPROVAL=true` ile tüm katmanları
insan onayında tutun. Autonomous'u yalnızca değişiklik yönetimi kaydıyla ve Karne
sınırı tuttuğu kategorilerde açın.

Diğer otonomi düğmeleri:

- **Otonom soruşturma (orkestratör)**: `ORCHESTRATOR_ENABLED=false` varsayılan; konsoldan
  açıp kapatma ve tüm koşuları durdurma (`POST /api/orchestrator/kill`) `settings.write`
  ister. Bütçeler: `ORCHESTRATOR_MAX_COST`, `ORCHESTRATOR_MAX_HOURLY_COST`,
  `ORCHESTRATOR_MAX_RUNTIME`.
- **Alarm şeritleri**: `ALERT_LANES_ENABLED=false` varsayılan; açıkken eşikler
  `INTENT.md`'nin `alert_lanes:` bölümünden okunur ve uygulanır, kural şeridi
  `suppression_rules` tablosunu okur. Bütçe baskısında hiçbir alarm düşürülmez.
- **Yerel model şeridi**: varsayılan kapalıdır. Yalnızca alarm şeritleri açıkken
  ve küçük model şeridine düşen alarm için çalışır: triage istemi Bifrost
  üzerinden `ollama/<model>` olarak, JSON şemasıyla kısıtlı çıktı istenerek
  gönderilir. Model `LOCAL_LANE_MODEL` ile verilir; boşsa
  `python -m evalkit.local_lane rank`'ın eval korpusunda yaptığı sıralamanın
  yazdığı seçim dosyası (`LOCAL_LANE_SELECTION_FILE`) okunur; ikisi de yoksa şerit
  kapalıdır. Bifrost adresi yerel ya da özel değilse şerit kurulmaz
  (`LOCAL_LANE_ALLOW_NONLOCAL_GATEWAY=false`). Diğer ayarlar:
  `LOCAL_LANE_TIMEOUT_S` (60), `LOCAL_LANE_MAX_TOKENS` (512). Yerel model hata
  verirse bulut modele geçilmez, bulut sağlayıcı düşerse de yerel modele
  geçilmez; bulgu triage hatasıyla kaydedilir.
- **Verdict run** (tek alarm için kısa, eleştirmenli soruşturma; sonucu karar
  şemasına uyar): `VERDICT_RUN_ENABLED=false` varsayılan. Bütçe:
  `VERDICT_RUN_MAX_ITERATIONS` (4), `VERDICT_RUN_MAX_COST_USD` (1.0),
  `VERDICT_RUN_MAX_WALL_MS` (300000). Bu sürümde daemon verdict run başlatmaz:
  alarm şeritlerinin verdict şeridine bir kuyruklayıcı bağlı değildir. Bayrak
  yalnızca bu kuyruklayıcıyı açar. `alert-verdict` iş akışı ise bayraktan bağımsız
  olarak her iş akışı gibi elle çalıştırılabilir (`ai_chat.use`). Bunu engellemek
  için iş akışını kapatın (`PUT /api/workflows/{workflow_id}/enabled`).
- **Beyan edilen niyet (`INTENT.md`)**: diğer anahtarlar için yalnızca gözlem
  modundadır; daemon açılışta beyan ile etkin değer arasındaki farkı loglar, hiçbir
  şeyi uygulamaz. Elle kontrol: `python -m services.daemon.intent`.

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

### Dersler

Bir analist düzeltmesi (ör. "bu adresten gelen Entra uyarıları bizim
tarayıcımız") bir **ders** olarak kaydedilir: yapısal alan eşleyicileriyle
kapsamlı, en çok 90 gün süreli, en çok `medium` (ya da `high`) şiddete uygulanır;
`critical` alarma hiçbir zaman uygulanmaz ve ders hiçbir bulguyu ya da vakayı
kapatmaz. Ders `proposed` olarak doğar (`POST /api/lessons`, `findings.write`).
Etkinleştirme (`POST /api/lessons/{lesson_id}/promote`, `ai_decisions.approve`,
öneren dışında bir kişi) dersi geçmiş etiketli alarmlarda çevrimdışı yeniden
oynatır (replay); hiçbir kötücül vakanın kararı kötüleşmez, hiçbir zararsız vaka
yeni yanlış pozitif olmaz ve en az bir iyileşme varsa ders `active` olur, yoksa
terfi reddedilir ve ret kaydedilir. Kapsam değeri yalnızca alarmın serbest
metninden geliyorsa ders analist kökenli sayılmaz ve etkinleşemez. Etkin ders tek
istekle geri alınır (`POST /api/lessons/{lesson_id}/rollback`). Her geçiş
`lesson_events` tablosunda yalnızca eklenerek tutulur. Konsol: **Karne → Lessons**
sekmesi.

**Sınır:** bu sürümde daemon'un canlı triage yolu etkin dersleri okumaz ve
uygulamaz; dersler yalnızca saklanır, replay edilir ve yönetilir.

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
- **Ajan defteri** (`agent_ledger`, hash zincirli) otomatik imha edilmez. Bu sınıfın
  tek yöntemi `archive`'dır: politikası varsa imha işi silmez, yalnızca süresi
  geçmiş koşu sayısını (`archive_candidates`) raporlar. Zincir doğrulamalı arşiv
  `GET /api/compliance/retention/agent-ledger/archive` ile alınır; her arşiv alımı
  `config_audit_log`'a `ledger_archive_exp` eylemiyle yazılır. Arşivden sonra
  kesme, belgelenmiş elle yapılan bir veritabanı sahibi işlemidir.

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

| Kayıt | İçerik | Bütünlük | Nasıl okunur / doğrulanır |
|---|---|---|---|
| `config_audit_log` | Her ayar değişikliği: anahtar, eski/yeni değer, değiştiren kullanıcı, gerekçe, zaman; otonomi katmanı değişiklikleri (`config_type='autonomy_tier'`), saklama/imha | zincirsiz | veritabanı; ilgili ekranlar; `GET /api/autonomy/audit` |
| `case_audit_logs` | Vaka alanı değişiklikleri, düzenleyici an kayıtları, taslaklar | `audit_chain`'de zincirli | Vaka sayfası → Record sekmesi; `python -m core.audit.verify` |
| `approval_actions` | Önerilen her eylem, kararı veren kural, uygulanan otonomi katmanı, araç çağrısının argüman özeti, onaylayan/reddeden, uygulama sonucu | `audit_chain`'de zincirli | onay kuyruğu, vaka Actions sekmesi, `GET /api/v1/approvals`; `python -m core.audit.verify` |
| `approval_decisions` | Her onay kararı (onay, ilk onay, ikinci onay, red), karar veren ve o anki rolü | yalnızca eklenir, değiştirilemez; zincirsiz | görevler ayrılığı raporu, `GET /api/response/segregation` |
| `agent_events` (ajan defteri) | Her ajan koşusunun olayları | koşu başına SHA-256 hash zinciri; başı imzalı kontrol noktasında | `GET /api/workflows/runs/{run_id}/verify`, `npm run ledger:verify`, `python -m core.audit.verify --agent-events` |
| `audit_checkpoints` | Ajan defteri ve `audit_chain` başlarının Ed25519 imzalı kontrol noktaları | imzalı, birbirine bağlı | `python -m core.audit.verify` |
| `regulatory_clock_events` | DORA/NIS2 başlangıç anları | vaka başına hash zinciri; güncelleme ve `TRUNCATE` tetikleyiciyle reddedilir | `GET /api/cases/{case_id}/regulatory/events` (zincir kontrolü dahil) |
| `lesson_events` | Derslerin her geçişi (öneri, replay, terfi, ret, geri alma) | yalnızca eklenir; zincirsiz | `GET /api/lessons/{lesson_id}/events` |
| Soruşturma gözetim zinciri | Bir soruşturmanın dosyaları ve kayıtları | — | `GET /api/orchestrator/investigations/{investigation_id}/chain-of-custody` |

### İmzalı kontrol noktalarını açma

Zincir (`audit_chain`) kurulumla birlikte çalışır. Kontrol noktaları ise imza
anahtarı verilene kadar yazılmaz (daemon her aralıkta uyarı loglar):

1. Anahtar çiftini üretin: `python -m core.audit.checkpoint keygen`. İlk satır
   (`AUDIT_CHECKPOINT_SIGNING_KEY=…`) gizlidir: sır deposuna ya da
   Secret/ExternalSecrets'e koyun ve daemon'a verin. İkinci satır
   (`AUDIT_CHECKPOINT_PUBLIC_KEY=…`) açık anahtardır: doğrulamayı yapacak kişiye,
   veritabanının dışında verin.
2. Aralık: `AUDIT_CHECKPOINT_INTERVAL_SECONDS` (varsayılan 3600; `0` işi kapatır).
   Sıcak yedekli kurulumda iş yalnızca lider daemon'da çalışır.
3. Veritabanı dışı kopya için `AUDIT_CHECKPOINT_FILE`'ı başka bir depolamaya
   yazılan bir dosyaya yöneltin. İsteğe bağlı RFC 3161 zaman damgası:
   `AUDIT_TSA_URL` (varsayılan boş; air-gap'te yalnızca ağ içi bir TSA ve izin
   listesiyle).
4. Elle bir kontrol noktası: `python -m core.audit.checkpoint run`.

Doğrulama (Postgres'e erişen bir makineden; çıkış 0 temiz, 1 kırılma, 2 kullanım
ya da bağlantı hatası):

```bash
python -m core.audit.verify --agent-events --require-signature --public-key <acik-anahtar>
python -m core.audit.verify --json --checkpoint-file /baska-depolama/checkpoints.jsonl
cd services/agent && npm run ledger:verify
cd services/agent && npm run ledger:verify -- --run-id <uuid>
```

`core.audit.verify` ilk kırılmayı nedeniyle verir (ör. `hash`, `gap`,
`source_modified`, `history_modified`, `checkpoint_signature`,
`checkpoint_head`, `signature_required`). Zamanlanmış doğrulamada
`--require-signature` kullanın: güvenilir açık anahtar ya da imzalı kontrol noktası
yoksa da başarısız olur. `ledger:verify` ilk kırılan defter satırını (`run_id`,
`seq`, neden) ya da toplam olay/koşu sayısını verir. Denetlenen bir tabloda
bilinçli olarak kolon silinir ya da yeniden adlandırılırsa doğrulayıcı
`schema_column_missing` raporlar; şema sahibi rolüyle
`python -m core.audit.checkpoint rebaseline --table <tablo> --reason "<neden>"`
imzalı bir yeniden temel alma kaydı yazar.

### Vaka kanıt paketi

Vaka sayfasında **Evidence pack** düğmesi (`GET /api/cases/{case_id}/evidence-pack`,
`cases.read`) vakanın imzalı ZIP arşivini indirir (içerik:
[güvenlik teknik belgesi §5](guvenlik-teknik-belgesi.md#5-denetim-kayıtları-ve-zincir)).
Kalıcı imza anahtarı için `scripts/autosecops evidence-keygen` çıktısındaki gizli
anahtarı `EVIDENCE_PACK_SIGNING_KEY` sırrı olarak verin ve açık anahtarı denetçiye
ayrıca iletin. Anahtar yoksa her paket geçici bir anahtarla imzalanır ve bu manifestte
yazılıdır. Denetçi paketi ağsız doğrular:

```bash
scripts/autosecops verify-bundle vaka-paketi.zip --public-key <acik-anahtar>
```

Paket redaksiyon yapmaz: `cases.read` sahibine vakanın ham kayıtlarını verir.

Bu sürümde **olmayanlar**:

- `config_audit_log` ve `approval_decisions` tablolarının hash zinciri: bu iki
  tablo bu sürümde zincirsizdir ve bunun için bir iş paketi henüz yoktur.
- Kontrol noktası ve kanıt paketi imza anahtarları için döndürme arayüzü yoktur;
  anahtarı değiştirmek sırrı değiştirip açık anahtarı doğrulayıcılara yeniden
  vermektir.

### SIEM'e denetim aktarımı

AutoSecOps güvenlikle ilgili olayları kurumun SIEM'ine akıtabilir. Aktarım
**varsayılan olarak kapalıdır**; kapalıyken dosya yazılmaz, bağlantı açılmaz.
Yönetici API'si (konsol ekranı yoktur):

- `GET /api/compliance/audit-export/config` ve `.../status` (`settings.read`):
  yapılandırma (gizli değerler dönmez) ve çalışma durumu: imleçler, son hata,
  güvensiz ayar uyarıları.
- `PUT /api/compliance/audit-export/config` (`settings.write`): açar, kaynakları ve
  hedefleri tanımlar. Değişiklik `config_audit_log`'a yazılır ve kendisi de aktarılır.
- `POST /api/compliance/audit-export/test` (`settings.write`): bir hedefe sentetik
  bir test olayı gönderir.

Kaynaklar: ajan defteri (`agent_events`), onay geçişleri (`approval_actions`),
kimlik doğrulama olayları (giriş, çıkış, MFA, parola, kullanıcı ve rol
değişiklikleri), `config_audit_log`, `case_audit_logs` ve imzalı kontrol noktaları
(`audit_checkpoints`; SIEM böylece veritabanı dışındaki kopya olur). Hedefler: RFC
5424 syslog (TLS; laboratuvar için TCP/UDP) ya da HTTPS (JSON `autosecops.audit.v1`
ya da CEF). Teslim en az bir kezdir: her (hedef, kaynak) için kalıcı bir imleç
tutulur, alıcı kapalıyken olaylar kaybolmaz ve yeniden denenir; SIEM'de olayın
`id`'siyle tekilleştirin. TLS doğrulaması varsayılan açıktır; jetonlar ve istemci
anahtarı sır deposunda (`AUDIT_EXPORT_<HEDEF>_TOKEN`) tutulur. Hedef adresi
`url_safety` ile denetlenir; şirket içi (RFC 1918, CGNAT) SIEM'lere izin verilir,
bulut metadata adresleri reddedilir.

**Maskeleme.** Olaylar gönderilmeden önce sırlar ve (`redact_pii: true`,
varsayılan) kişisel veri maskelenir. Güvenilir yol **yapısal alanlardır**: bir
değeri kesin maskelemek için onu `details` içinde kendi anahtarıyla gönderin
(`{"password": "…"}`, `{"diagnosis": "…"}`); karar anahtarın adına göre verilir.
Serbest metindeki (`message`, `details` içindeki dizeler, `user_agent`) kişisel
veri ve kimlik bilgisi maskelemesi **en iyi çabadır**: tanımadığı bir düzyazı
biçimindeki değeri (ör. ayırıcısız `patient diagnosis HIV positive`, adı
geçmeyen bir kişi adı) olduğu gibi aktarır. Aktör alanı denetim izinin amacı
gereği maskelenmez.

**Çok kopyalı kurulum.** Aktarımı Postgres danışma kilidini alan tek süreç yapar.
Kimlik doğrulama olayları API sürecinde yerel bir biriktiriciye
(`$VIGIL_DIR/audit_export/`) yazılır; birden çok API kopyası varsa bu dizin tüm
kopyaların paylaştığı bir birimde olmalıdır, yoksa lider olmayan kopyaların olayları
aktarılmaz. Mantıksal geri yüklemeden sonra imleç dosyasını (`cursors.json`)
silin.

Alan eşlemesi, biçimler, metrikler (`autosecops_audit_export_*`) ve bilinen sınırlar:
[core/compliance/AUDIT_EXPORT.md](../../core/compliance/AUDIT_EXPORT.md).

## Sürüm yükseltme

0.7.x sürümünden AutoSecOps 2.0'a veritabanı yükseltmesi
`scripts/upgrade_database.py` ile yapılır: salt okunur ön kontroller, `--dry-run`
ile plan, `--backup <dosya>` ile `pg_dump -Fc` yedeği, yeni init SQL dosyaları ve
şema göçü, sonucun taze kurulum şemasıyla karşılaştırılması. Yükseltme yalnızca
ileri yönlüdür; geri dönüş yedeğin geri yüklenmesidir. Adım adım prosedür (Compose,
Helm, kurulum dışı), doğrulama ve geri alma:
[docs/upgrade-0.7-to-2.0.md](../upgrade-0.7-to-2.0.md). 2.0 içindeki sonraki
sürümler için bkz. [kurulum kılavuzu §9](kurulum-internetsiz.md#9-güncelleme-ve-geri-alma).
Her sürümle birlikte SBOM, imzalı imajlar ve sürüm notları verilmesi
(Planlı — `wp/w4.7-release`, bu sürümde yok).

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
| Yalnızca ortam değişkeni (ör. Compose'a ve `./start.sh restore`'a verilen ortam) | Yeni anahtarı durum dizinindeki `secrets.enc`'e yazar. Backend anahtarı `secrets.enc`'ten ortamdan önce okur; aynı durum dizinini (Compose'da `vigil_home` birimi) okuyan servisler yeniden başlayınca yeni anahtarı kullanır ve eski oturumlar düşer | Servisleri yeniden başlatın. Ortamdaki eski değeri de yenisiyle değiştirin: `secrets.enc` sonradan kaybolursa ortamdaki eski anahtar yeniden geçerli olur. Komutun çıktısındaki "an environment value outranks secrets.enc" ifadesi yanlıştır |
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
şifrelemesini kurum tarafında sağlayın. CronJob veritabanını ve vaka kanıt
deposunu yedekler (aşağıya bakın); durum dizinini yedeklemez. Kimlik bilgilerini
Secret/ExternalSecrets ile verdiyseniz durum dizini yeniden üretilebilir.

**Vaka kanıt deposu.** Vakaya eklenen dosyalar (ör. /hunt belgesi)
`<stateDirectory.mountPath>/evidence` altına yazılır.

> **UYARI: Helm'de kanıt dosyaları varsayılan olarak kalıcı değildir.**
> `evidence.persistence.enabled` varsayılan olarak `false`'tur; dosyalar durum
> dizini birimine (varsayılan `emptyDir`) yazılır, pod yeniden başlayınca ya da
> taşınınca kaybolur ve iki backend kopyasında yalnızca dosyayı alan kopyada
> bulunur. Veritabanındaki `case_evidence` satırları kalır ve artık olmayan
> dosyaları gösterir. Kanıt saklayan her kurulumda açın:
>
> ```yaml
> evidence:
>   persistence:
>     enabled: true
>     storageClassName: <RWX sınıfı>   # NFS, CephFS, Longhorn RWX, EFS ...
>     accessModes: [ReadWriteMany]     # zorunlu
>     # ya da existingClaim: <PVC>
> ```
>
> `accessModes` açıkken zorunludur. Birimi backend, daemon ve llm-worker (ve
> yedek işi) birlikte bağladığından ve bunlar farklı düğümlerde çalışabildiğinden,
> birden çok pod bağlıyorsa `ReadWriteOnce` şablon aşamasında reddedilir. RWX
> sınıfı varsayılan sınıfa bırakılırsa kurulum çıktısı (NOTES) uyarır: o sınıf
> RWX sağlamıyorsa PVC `Pending` kalır ve pod'lar başlamaz. İnternetsiz profil
> (`infra/airgap/values-airgap.yaml`) birimi kapalı bırakır. Kanıtın PostgreSQL'e
> ya da nesne deposuna taşınması ertelenmiş bir iştir.

Birim açıksa ve `backup.includeEvidence: true` (varsayılan) iken yedek CronJob'u her dökümün
yanına aynı zaman damgalı `evidence-<damga>.tar.gz` (ve `.sha256`,
`LATEST_EVIDENCE`) yazar (dosyalar 0600), aynı saklama kurallarını uygular ve
nesne deposuna yükler; geri yükleme artıkları (`.vigil-pre-restore-*`) arşive
girmez. Birim kapalıyken yedekte kanıt dosyası yoktur. Geri yüklemede dökümü ve aynı damgalı arşivi birlikte kullanın: arşivi
kanıt biriminin köküne açın (`tar -xzf evidence-<damga>.tar.gz -C <birim>`).
`backup.includeEvidence: false` ise kanıt biriminin yedeği operatörün
sorumluluğundadır. `python -m core.backup restore` durum dizinindeki bağlama
noktalarını (kanıt birimi) yeniden adlandırmaz; içeriklerini yerinde geri yükler,
öncekileri birimin içinde `.vigil-pre-restore-<damga>` altında bırakır.

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

## Masaüstü uygulaması

AutoSecOps masaüstü uygulaması, tek bir makinede Docker üzerinde çalışan yerel
yığının (PostgreSQL, Redis, Bifrost LLM ağ geçidi, backend, ajan katmanı) önüne
yerel bir pencere koyar. Kaynak kod, Python ya da Node gerekmez; yalnızca Docker
gerekir. Değerlendirme, eğitim ve tek analistlik küçük kurulumlar içindir; çok
kullanıcılı üretim kurulumu için Docker Compose ya da Helm kullanın
([internetsiz kurulum kılavuzu](kurulum-internetsiz.md)). Konsol yalnızca bu
makineden erişilen `http://127.0.0.1:6987` adresinde çalışır; diğer servisler
dışarı port açmaz.

### Gereksinimler

| | macOS | Linux | Windows (önizleme) |
|---|---|---|---|
| İşletim sistemi | macOS 12 ve üstü, Apple silikon (arm64) ya da Intel (x64) | x86_64, glibc tabanlı güncel bir dağıtım; AppImage için FUSE 2 kitaplığı | Windows 10/11 x64 |
| Docker | Docker Desktop | Docker Engine ve Compose v2 eklentisi; kullanıcı `docker` komutunu `sudo` olmadan çalıştırabilmeli | Docker Desktop (WSL 2 arka ucu) |
| Kaynak | En az 8 GB bellek (16 GB önerilir), imajlar ve veri için ~15 GB disk | aynı | aynı |
| İsteğe bağlı | Yerel modeller için Ollama | aynı | aynı |

Windows kurulum dosyası sürüm hattında üretilir, ancak gerçek bir Windows
makinesinde uçtan uca sınanmamıştır; bu yüzden **önizleme** olarak verilir.

### Kurulum

Kurulum dosyaları GitHub Release'te `autosecops-<V>-desktop-<işletim sistemi>-<mimari>`
adıyla durur. Önce dosyayı doğrulayın (aşağıda, "Doğrulama"). Adında `-unsigned`
geçen dosya, işletim sisteminin kod imzasını (Apple Developer ID / Authenticode)
taşımaz; cosign imzası ve `SHA256SUMS` yine de vardır.

- **macOS:** `autosecops-<V>-desktop-mac-arm64.dmg` (Apple silikon) ya da
  `-mac-x64.dmg` (Intel) dosyasını açın, AutoSecOps'u Applications klasörüne
  sürükleyin. İmzasız (`-unsigned`) bir dmg'den kurulan uygulamayı macOS
  "hasarlı" (damaged) diye açmaz. Dosyayı doğruladıktan sonra karantina işaretini
  kaldırın: `xattr -dr com.apple.quarantine /Applications/AutoSecOps.app`, ya da
  **Sistem Ayarları → Gizlilik ve Güvenlik → Yine de Aç** yolunu kullanın.
- **Linux:** `chmod +x autosecops-<V>-desktop-linux-x86_64.AppImage` ve dosyayı
  çalıştırın. Kurulum gerekmez.
- **Windows:** `autosecops-<V>-desktop-win-x64.exe` kurulum sihirbazını
  çalıştırın (kullanıcı başına kurulur, yönetici yetkisi istemez). İmzasız bir
  dosyada SmartScreen "Windows bilgisayarınızı korudu" der: **Ek bilgi → Yine de
  çalıştır**.

### İlk çalıştırma

1. Uygulama Docker'ı arar. Yoksa indirme sayfasını öneren bir uyarıyla kapanır;
   Docker kurulu ama çalışmıyorsa başlatmayı dener ve en çok üç dakika bekler.
2. Compose dosyasını ve şema SQL'ini uygulama veri dizinine kopyalar (her yeni
   sürümde bir kez).
3. Yığının beş imajını kullanır; yerelde olmayanı ilk açılışta indirir (birkaç
   dakika sürer):
   - `ghcr.io/singularityrd/autosecops-backend:<V>`
   - `ghcr.io/singularityrd/autosecops-agent:<V>`
   - `postgres:16-alpine`
   - `redis:7-alpine`
   - `maximhq/bifrost:v2.2.1`

   Kayıt defterlerine erişimi olmayan bir makinede beşini de önceden
   `docker load` ile yükleyin (imaj arşivleri için bkz.
   [internetsiz kurulum kılavuzu](kurulum-internetsiz.md)). Beşi de yerelde
   varsa uygulama ağa çıkmaz; biri eksikse Docker onu indirmeyi dener ve
   internetsiz makinede açılış başarısız olur.
4. PostgreSQL'i başlatır, şemayı uygular, servisleri ayağa kaldırır ve konsolu
   açar. Kurulumda hazır bir hesap yoktur: ilk açılışta yönetici hesabını siz
   oluşturursunuz (kullanıcı adı ve parola sizin seçiminizdir).

Uygulama ilk açılışta bu kuruluma özel bir JWT imza anahtarı ve ajan iç belirteci
üretir ve veri dizinindeki `config.json` dosyasına (yalnızca sahibi okuyabilir,
`0600`) yazar. Uygulamayı kapatmak tüm konteynerleri durdurur ve kaldırır; vakaları
ve ayarları tutan Docker birimleri kalır.

### Veri ve log konumları

| | macOS | Linux | Windows |
|---|---|---|---|
| Uygulama verisi (`config.json`, Compose kopyası) | `~/Library/Application Support/AutoSecOps` | `~/.config/AutoSecOps` | `%APPDATA%\AutoSecOps` |
| Uygulama logu (`autosecops-desktop.log`, son 5 açılış) ve kapanışta alınan konteyner logları (`containers/autosecops-<UTC>.log`, son 5) | `~/Library/Logs/AutoSecOps` | `~/.config/AutoSecOps/logs` | `%APPDATA%\AutoSecOps\logs` |
| Veritabanı, Redis, durum dizini, Bifrost verisi | Compose projesi `vigil` altındaki Docker birimleri: `postgres_data`, `redis_data`, `vigil_home`, `bifrost_data` (Docker'da proje adı önekiyle görünür) | aynı | aynı |

Docker birimlerindeki ve konteyner adlarındaki `vigil` öneki, Compose proje
adından gelen iç bir addır. Yükseltmede verinin yerinde kalması için bilerek
korunur. 2.0'dan önceki sürümlerin yazdığı `vigil-desktop.log` ve
`containers/vigil-*.log` dosyaları da destek paketine girer.

### Güncelleme

Uygulamanın kendi kendini güncelleme özelliği yoktur ve hiçbir güncelleme
sunucusuna bağlanmaz (internetsiz kurulumlar için bilinçli bir karar). Yeni
sürümü yükseltmek için:

1. Uygulamayı kapatın. Veri önemliyse veritabanı birimini (`postgres_data`) yedekleyin.
2. Yeni kurulum dosyasını indirin, doğrulayın ve eskisinin üzerine kurun (macOS:
   Applications'taki uygulamayı değiştirin; Linux: yeni AppImage'ı kullanın;
   Windows: yeni kurulum sihirbazını çalıştırın).
3. İlk açılışta uygulama yeni Compose dosyasını kopyalar ve yeni sürümün
   imajlarını indirir (ya da yerelde bulur); veritabanı birimi korunur.

2.0 sürümünde uygulama kimliği `com.singularityrd.autosecops` olarak değişti
(önceki: `ai.deeptempo.vigil`). macOS, Tam Disk Erişimi izinlerini uygulama
kimliğine bağladığı için bu izni bir kez yeniden vermeniz gerekebilir; veri
dizini değişmez.

### Kaldırma

- **macOS:** Applications'taki AutoSecOps'u çöpe atın.
- **Linux:** AppImage dosyasını silin.
- **Windows:** **Ayarlar → Uygulamalar → AutoSecOps → Kaldır**.

Kaldırma; veri dizinini, logları ve Docker birimlerini **silmez**. Tamamen
temizlemek için uygulama veri ve log dizinlerini silin, ardından birimleri
kaldırın (geri alınamaz; tüm vakalar ve ayarlar gider):

```bash
docker volume ls --filter label=com.docker.compose.project=vigil
docker volume rm $(docker volume ls -q --filter label=com.docker.compose.project=vigil)
```

### Loglar ve destek paketi

**Help → Open Logs** (ya da sistem tepsisi menüsü) konteynerlerin son 500
satırını geçici dizinde `autosecops-logs.txt` dosyasına yazar ve açar.
**Help → Support Bundle Command…** bu kuruluma uygun destek paketi komutunu
gösterir ve kopyalar, örneğin macOS'ta:

```bash
sh "/Applications/AutoSecOps.app/Contents/Resources/vigil-support/vigil-support.sh"
```

Komut bir terminalde çalıştırılır, maskelenmiş tek bir `.tar.gz` yazar ve hiçbir
şey yüklemez ([destek aracının belgesi](../../scripts/vigil-support/README.md)).
Betik POSIX `sh` ister; Windows'ta WSL ya da Git Bash içinden çalıştırın.

### Doğrulama

Her kurulum dosyası `SHA256SUMS` içinde listelenir ve yanında bir
`<dosya>.sigstore.json` cosign imzası bulunur. Sürüm dizininin tamamı
`verify-release.sh` ile doğrulanır; betik masaüstü kurulum dosyalarının
imzalarını da denetler ([docs/release/dogrulama.md](../release/dogrulama.md)).
Tek dosya için:

```bash
cosign verify-blob \
  --bundle autosecops-<V>-desktop-mac-arm64.dmg.sigstore.json \
  --certificate-identity "https://github.com/SingularityRD/autosecops2/.github/workflows/release.yml@refs/tags/v<V>" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  autosecops-<V>-desktop-mac-arm64.dmg
```

İşletim sisteminin kod imzası ayrıca denetlenir:

- **macOS, imzalı:** `spctl --assess --type execute -vv /Applications/AutoSecOps.app`
  çıktısında `accepted` ve `source=Notarized Developer ID` görünür;
  `codesign -dv --verbose=4 /Applications/AutoSecOps.app` çıktısında
  `Authority=Developer ID Application: …` satırı vardır.
- **macOS, imzasız (`-unsigned`):** `codesign -dv` çıktısında `Signature=adhoc`
  görünür ve `spctl` uygulamayı reddeder; bu beklenen durumdur, dosyanın
  bütünlüğünü cosign imzası ve `SHA256SUMS` kanıtlar.
- **Windows, imzalı:** PowerShell'de `Get-AuthenticodeSignature .\autosecops-<V>-desktop-win-x64.exe`
  komutu `Status: Valid` ve yayıncı sertifikasını gösterir. İmzasız dosyada
  durum NotSigned olur.
- **Linux:** AppImage'ın işletim sistemi imzası yoktur; cosign imzası ve
  `SHA256SUMS` yeterlidir.

### Güvenlik özellikleri ve sınırlar

- Her pencere yalıtılmış (context isolation) ve kum havuzunda (sandbox) çalışır;
  web içeriği Node.js'e erişemez. Ana pencere yalnızca yerel backend'i
  (`127.0.0.1:6987`) gösterir. Başka bir adrese giden bağlantı, yönlendirme ya da
  yeni pencere uygulamada açılmaz; yalnızca `https:` ve `mailto:` bağlantıları
  sistem tarayıcısına verilir, diğer şemalar (`file:`, `smb:` ve benzeri)
  engellenir. Kamera, mikrofon, konum gibi izinler reddedilir.
- Kurulu uygulamada geliştirici araçları kapalıdır. Electron sigortaları
  (fuses) ile uygulamanın düz Node olarak çalıştırılması, `NODE_OPTIONS` ve
  `--inspect` bayrakları kapatılmıştır; kod yalnızca `app.asar`'dan yüklenir ve
  macOS ile Windows'ta `app.asar` paketleme sırasında gömülen bütünlük özetiyle
  karşılaştırılır (değiştirilmiş bir `app.asar` ile uygulama açılmaz). Konsol
  oturum çerezleri diskte işletim sisteminin anahtar deposuyla şifrelenir.
- OIDC tek oturum açma, masaüstü penceresinde desteklenmez: kimlik sağlayıcının
  sayfası sistem tarayıcısında açılır ve oturum orada kalır. Masaüstü
  uygulamasında yerel hesap kullanın.
