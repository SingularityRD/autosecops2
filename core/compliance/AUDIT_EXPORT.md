# Denetim akışının SIEM'e aktarımı (audit export)

AutoSecOps, güvenlikle ilgili olayları müşterinin SIEM'ine (Splunk, QRadar,
Sentinel, Elastic, Wazuh, syslog-ng/rsyslog aktarıcısı vb.) sürekli akıtabilir.
Kod: `core/compliance/audit_export.py`; yönetici API'si:
`core/compliance/audit_export_router.py`. Spec: `docs/wp/w3.6.md`.

Aktarım **varsayılan olarak kapalıdır.** Yapılandırma yokken ya da
`enabled: false` iken hiçbir dosya yazılmaz, kilit alınmaz, bağlantı açılmaz.

## Ne aktarılır

| Kaynak (`source`) | Okunduğu yer | Olaylar |
|---|---|---|
| `agent_events` | ajan defteri tablosu `agent_events` (yalnız-ekleme, hash zincirli) | her defter olayı: `agent.<kind>` (ör. `agent.tool_call`, `agent.terminal`) |
| `approvals` | `approval_actions` satırındaki zaman damgası geçişleri | `approval.requested`, `approval.approved`, `approval.rejected`, `response.executed`, `response.verified`, `response.reversed` |
| `auth` | API sürecinin yazdığı yerel biriktirici (`$VIGIL_DIR/audit_export/auth_spool/`) | `auth.login` (başarılı / `failure` / `locked` / `mfa_failure`), `auth.logout`, `auth.password_change`, `auth.password_reset_request`, `auth.password_reset`, `auth.mfa_setup`, `auth.mfa_enable`, `auth.mfa_disable`, `auth.mfa_recovery_codes`, `auth.user_create`, `auth.user_update`, `auth.user_delete`, `auth.role_change`, `auth.user_activate`, `auth.user_deactivate` |
| `config` | `config_audit_log` | `config.create` / `config.update` / `config.delete` (aktarım yapılandırmasının kendisindeki değişiklikler de dahil, önem 6) |
| `case_audit` | `case_audit_logs` | `case.<entity_type>.<action>` |

Ajan defteri için yalnızca defter koordinatları, tür, hash zinciri değerleri ve
`payload`'ın üst düzey skaler alanları (string'ler 256 karaktere kadar) gönderilir;
istemler ve araç çıktısı gibi iç içe içerik AutoSecOps'ta kalır.
`agent_event_kinds` ile yalnız belirli türler seçilebilir.

## Teslim garantisi

- **En-az-bir-kez.** Her (hedef, kaynak) çifti için kalıcı bir imleç
  (`$VIGIL_DIR/audit_export/cursors.json`) tutulur. İmleç, hedef bir partiyi
  kabul ettikten **sonra** ve atomik olarak (geçici dosya + fsync + rename)
  yazılır. Süreç dururken kuyrukta ya da yolda olan olaylar bir sonraki
  başlangıçta yeniden okunur; dolayısıyla nadiren tekrar gelebilir. Her olayın
  kararlı bir `id` alanı vardır; SIEM tarafında **`id` ile tekilleştirin**.
- **Alıcı kapalıyken kayıp yok.** Başarısız teslim üstel, sınırlı ve rastgele
  sarsıntılı (jitter) geri çekilmeyle (`max_backoff_s`, `Retry-After` dikkate
  alınır) süresiz yeniden denenir; olay atılmaz. Okuyucu sınırlı bir kuyruğu
  (`queue_max`) doldurur; kuyruk doluysa okuma durur (geri basınç), bellek büyümez.
- **Gecikmeli (uzun açık) işlemler.** Postgres'te veritabanı kaynakları
  satırı ekleyen/son güncelleyen işlemin kimliğine (`xmin`, 64 bite
  genişletilmiş) göre `(xid, anahtar)` sırasıyla okunur ve yalnızca
  `pg_snapshot_xmin(pg_current_snapshot())` — hâlâ çalışan en eski işlem —
  altındaki işlemlerin satırları okunur. Bu sınırın altındaki her işlem ya
  commit ya da rollback olmuştur; dolayısıyla daha düşük bir id'yi ya da daha
  eski bir zaman damgasını saatlerce açık tutan bir işlem **beklenir**, imleç
  asla commit edilmemiş bir satırın önüne geçmez ve o satır sonradan imlecin
  gerisine düşüp kaybolmaz. İmleç biçimi: `{"xid": …, "id": …}` (ajan defteri
  için `run_id`/`seq`, onaylar için `action_id`). `settle_s` Postgres'te
  kullanılmaz; yalnızca tek yazıcılı test veritabanlarında (SQLite) satırları
  `now - settle_s`'e kadar okur. Bedeli: uzun açık bir işlem, kendisinden sonra
  commit edilenlerin aktarımını o işlem bitene kadar geciktirir (kaybettirmez).
  İşlem kimlikleri küme (cluster) geneli olduğundan bu, aynı Postgres
  sunucusundaki **başka bir veritabanında** açık kalan yazma işlemleri için de
  geçerlidir. `idle in transaction` oturumları için Postgres
  `idle_in_transaction_session_timeout` ayarlayın; gecikmeyi `status`
  yanıtındaki `last_event_at_by_source` ile izleyin.
- **Tek istisna:** HTTP alıcısı tek bir olayı bile `413` ile reddederse olay
  önce `details` kırpılarak yeniden denenir; yine reddedilirse atılır ve
  `events_dropped` sayacı artar (aksi halde arkasındaki tüm olaylar sonsuza
  dek takılırdı).
- **Bozuk imleç dosyası** sessizce sıfırlanmaz; aktarım hata verir (olayları
  atlamaktansa durmak tercih edilir). Dosyayı inceleyip düzeltin veya silin
  (silmek `start_from` davranışına geri döner).
- **Syslog sınırı:** syslog'da uygulama seviyesinde onay yoktur (RELP
  desteklenmez). TCP/TLS üzerinde parti, hâlâ açık bir bağlantıya yazılıp
  boşaltıldığında teslim edilmiş sayılır; bağlantının kapandığı fark edilirse
  yeniden gönderilir. Ancak alıcı, veriyi çekirdek tamponuna aldıktan sonra
  çökerse o son parti kaybolabilir. Kanıt düzeyinde teslim gerekiyorsa HTTPS
  hedefini kullanın (2xx = kabul). UDP yalnızca laboratuvar içindir.

## Biçimler

### JSON (`autosecops.audit.v1`)

HTTPS `json` biçimi bir JSON dizisi gönderir (`Content-Type: application/json`).
Syslog `rfc5424` biçiminde MSG kısmı aynı nesnedir.

```json
{
  "schema": "autosecops.audit.v1",
  "id": "approvals:action-20261012-083015-123456:decided",
  "timestamp": "2026-10-12T08:30:15.123Z",
  "source": "approvals",
  "category": "approval",
  "action": "approval.approved",
  "outcome": "approved",
  "severity": 5,
  "message": "block_ip on 198.51.100.7: approval.approved (approved)",
  "actor": {"name": "alice", "id": null},
  "target": {"type": "approval_action", "id": "action-20261012-083015-123456"},
  "src_ip": null,
  "user_agent": null,
  "hash": null,
  "details": {"action_type": "block_ip", "status": "approved", "...": "..."},
  "observer": {"product": "AutoSecOps", "version": "x.y.z", "host": "soc-1"}
}
```

`id` biçimleri: `agent_events:<run_id>:<seq>`, `approvals:<action_id>:<geçiş>`,
`auth:<uuid>`, `config:<id>`, `case_audit:<audit_id>`.
`severity` 0–10 ölçeğindedir (CEF ile aynı).

### CEF

`CEF:0|AutoSecOps|AutoSecOps|<sürüm>|<source>:<action>|<message>|<severity>|<uzantılar>`

Başlıkta `\` ve `|` kaçışlanır; her satır sonu (CR, LF, NEL U+0085, U+2028,
U+2029, VT, FF) ve diğer kontrol karakterleri boşluğa çevrilir. Uzantı
değerlerinde `\` ve `=` kaçışlanır; CR/LF/TAB `\r`/`\n`/`\t`, diğer satır
sonları ve kontrol karakterleri `\uXXXX` olarak kodlanır. Böylece saldırganın
yazdığı bir değer (giriş adı, user agent) ikinci bir kayıt sahteleyemez. HTTPS
`cef` biçimi her satıra bir olay koyar (`text/plain`); JSON gövdelerinde de
U+2028/U+2029/NEL `\u` kaçışıyla yazılır.

### RFC 5424 syslog

`<PRI>1 <zaman> <host> autosecops <procid> <category> [autosecops@32473 ...] BOM<MSG>`

- `PRI = facility * 8 + önem`; facility varsayılanı 13 (log audit). Önem eşlemesi:
  CEF ≥9 → 2 (critical), ≥7 → 4 (warning), ≥4 → 5 (notice), diğerleri → 6 (info).
- SD-ID `autosecops@32473` (RFC 5612 belgeleme PEN'i; IANA kaydı gerektirmez).
  Parametre değerlerinde `"`, `\` ve `]` kaçışlanır; CR/LF/NEL/U+2028/U+2029 ve
  diğer kontrol karakterleri `\r`, `\n`, `\uXXXX` olarak yazılır (satır
  bölen alıcılar sahte kayıt görmez).
- MSG: `format: rfc5424` için JSON, `format: cef` için CEF satırı; UTF-8, BOM ile.
- TLS/TCP üzerinde RFC 5425 / RFC 6587 sekizli sayımlı (octet-counting)
  çerçeveleme; UDP'de her olay bir datagram.
- Mesaj `max_message_bytes`'ı aşarsa önce `details` atılır
  (`{"_truncated": true}`), sonra mesaj karakter sınırında kesilir.

## Alan eşlemesi

| JSON alanı | CEF | RFC 5424 SD parametresi | Açıklama |
|---|---|---|---|
| `id` | `externalId` | `id` | Kararlı tekilleştirme anahtarı |
| `timestamp` | `rt` (epoch ms) | başlık TIMESTAMP | Olayın kaynaktaki zamanı (UTC) |
| `source` | `cs3` (`cs3Label=source`), Signature ID öneki | `src` | Kaynak adı |
| `category` | `cat` | başlık MSGID | `agent`, `approval`, `authentication`, `configuration`, `case` |
| `action` | `act`, Signature ID | `act` | Olay türü |
| `outcome` | `outcome` | `outcome` | `success`, `failure`, `locked`, `approved`, `rejected`, `pending` … |
| `severity` | başlık Severity | `sev` (+ PRI önemi) | 0–10 |
| `message` | başlık Name (≤512) ve `msg` | — (MSG içinde) | İnsan tarafından okunur özet |
| `actor.name` | `suser` | `actor` | Kullanıcı adı, `agent` veya sistem |
| `actor.id` | `suid` | — | Kullanıcı kimliği (varsa) |
| `target.type` | `cs1` (`cs1Label=targetType`) | `targetType` | `user`, `approval_action`, `agent_run`, `case` … |
| `target.id` | `cs2` (`cs2Label=targetId`) | `targetId` | Hedef kimliği |
| `src_ip` | `src` (yalnız geçerli IP) | `srcIp` | İstemci adresi (auth, case_audit) |
| `user_agent` | `requestClientApplication` | — | İstemci UA (≤256) |
| `hash` | `cs5` (`cs5Label=eventHash`) | — | Ajan defteri `event_hash` |
| `details` | `cs4` (`cs4Label=details`, JSON, ≤1024) | — | Kaynağa özgü ayrıntı |
| `observer.host` | `dvchost` | başlık HOSTNAME | Aktaran AutoSecOps düğümü |
| `observer.version` | başlık Device Version | — | AutoSecOps sürümü |

## Maskeleme (redaction)

Olaylar kuyruğa girmeden önce maskelenir (`Redactor`, `redact_text`,
`secret_key`); `core/telemetry_sanitizer.py` anahtar ve değer kuralları da
yeniden kullanılır.

- **Hassas anahtar adları** her derinlikte `[REDACTED]` olur. Anahtar
  `. _ - /` ve camelCase'den bölünür; tek sözcükler (`password`, `passwd`,
  `pwd`, `passphrase`, `secret`, `token`, `credential(s)`, `creds`, `pin`, `sig`,
  `signature`, `otp`, `cookie`, `dsn`, `jwt`, `authorization`, `sas` …) bir
  bölüt, bileşikler (`api_key`, `access_key`, `secret_key`, `private_key`,
  `signing_key`, `encryption_key`, `client_secret`, `access_token`,
  `refresh_token`, `session_id`, `webhook_url`, `database_url`, `db_url`,
  `redis_url`, `connection_string`, `set_cookie`, `mfa_code`, `recovery_codes`
  …) ardışık bölütler olarak eşleşir (`webhookUrl`, `x-api-key`,
  `aws.secret_access_key`). `auth` yalnızca tek başına bir anahtarsa.
- **Serbest metin:** `anahtar=değer`, `anahtar: değer`, `"anahtar": "değer"`
  çiftleri (ön/son ekli anahtarlar dahil: `db_password=`), ODBC
  `Password=…;`/`Pwd={…};`; URL kullanıcı bilgisi (`scheme://kullanıcı:parola@`,
  `redis://:pw@`, `mongodb+srv://u:pw@` — tüm userinfo gider); gizli sorgu
  parametreleri (`?api_key=`, `access_token=`, `sig=`, `X-Amz-Signature=` …);
  `Authorization:` başlıkları (şema korunur) ve çıplak `Basic`/`Bearer`
  kimlik bilgileri; PEM özel anahtarları (sonu kesik olsa da); yolu kimlik
  bilgisi olan webhook URL'leri (Slack, Discord, Teams/Office, Logic Apps);
  biçiminden tanınan jetonlar (`sk-…`/`sk-proj-…`/`sk-ant-…`, Stripe
  `sk_live_…`, GitHub `ghp_…`/`github_pat_…`, GitLab `glpat-…`, Slack
  `xox?-…`/`xapp-…`, Google `AIza…`/`ya29.…`, AWS anahtar kimlikleri ve 40
  karakterlik gizli anahtarlar, Hugging Face, npm, PyPI, SendGrid, JWT);
  ayrıca sanitizer'ın kalıpları (kimlik bilgili DSN, ≥32 karakter onaltılık).
  İstisna: defterin kendi `prev_hash`/`event_hash` alanları.
- `redact_pii: true` (varsayılan) iken e-posta adresleri `[REDACTED-EMAIL]` olur
  ve `email`, `phone`, `full_name`, `address`, `tckn`, `national_id`, `ssn`
  anahtarları maskelenir.
- **Başarısız giriş:** yazılan kullanıcı adı doğrulanmamış girdidir (çoğu zaman
  yanlış kutuya yazılmış bir parola). Var olan bir hesabı adlandırıyorsa o
  hesabın adı/kimliği aktarılır; yoksa `actor` boş kalır ve yalnızca kurulum
  başına anahtarlı bir HMAC özeti (`identifier_digest`, tekrarlanan denemeleri
  ilişkilendirmeye yeter, tahminle doğrulanamaz; anahtar
  `$VIGIL_DIR/audit_export/identifier.key`, 0600) ile uzunluğu aktarılır.
- Dizeler 2048 karakterde, iç içe yapı 6 seviyede, listeler/sözlükler 100
  öğede kesilir. Maskelenen değer sayısı `redactions` metriğindedir.

## Yapılandırma

Yapılandırma `system_config['compliance.audit_export']` altında saklanır ve
yalnızca yönetici API'siyle değiştirilir (değişiklik `config_audit_log`'a
düşer ve kendisi de aktarılır).

| Uç nokta | İzin | Açıklama |
|---|---|---|
| `GET /api/compliance/audit-export/config` | `settings.read` | Yapılandırma; gizli değerler asla dönmez, yalnız `has_token` / `has_client_key` |
| `PUT /api/compliance/audit-export/config` | `settings.write` | `{"config": {...}, "secrets": {"<hedef>": {"token": "...", "client_key_pem": "...", "clear_token": false, "clear_client_key": false}}}` |
| `GET /api/compliance/audit-export/status` | `settings.read` | Çalışma durumu, metrikler, imleçler, güvensiz ayar uyarıları |
| `POST /api/compliance/audit-export/test` | `settings.write` | `{"destination": "<ad>"}` için sentetik bir test olayı gönderir |

Örnek:

```json
{
  "config": {
    "enabled": true,
    "start_from": "now",
    "redact_pii": true,
    "sources": {"agent_events": true, "approvals": true, "auth": true,
                "config": true, "case_audit": true},
    "destinations": [
      {"type": "syslog", "name": "qradar", "host": "siem.corp.example",
       "port": 6514, "protocol": "tls", "format": "rfc5424",
       "ca_pem": "-----BEGIN CERTIFICATE-----\n..."},
      {"type": "http", "name": "splunk", "format": "json",
       "url": "https://splunk.corp.example:8088/services/collector/raw",
       "auth_header": "Authorization", "auth_scheme": "Splunk"}
    ]
  },
  "secrets": {"splunk": {"token": "<HEC jetonu>"}}
}
```

| Alan | Varsayılan | Anlamı |
|---|---|---|
| `enabled` | `false` | Ana anahtar |
| `start_from` | `now` | İlk açılışta: `now` = yalnızca bundan sonrası, `beginning` = tüm geçmiş. İmleç ilk açılışta sabitlenir; yeniden başlatma "now"u kaydırmaz |
| `sources.*` | hepsi `true` | Kaynak seçimi |
| `agent_event_kinds` | `[]` (hepsi) | Ajan defteri tür filtresi |
| `redact_pii` | `true` | PII maskeleme |
| `batch_size` / `queue_max` | 100 / 1000 | Parti boyutu / kuyruk sınırı |
| `poll_interval_s` / `settle_s` | 5 / 5 | Yoklama aralığı / oturma penceresi (yalnız Postgres dışı; Postgres'te imleç en eski açık işlemle sınırlanır) |
| `max_backoff_s` | 60 | Yeniden deneme bekleme üst sınırı |
| `spool_max_bytes` | 256 MiB | Auth biriktiricisinin disk sınırı; dolunca yeni auth olayları atılır ve `spool_dropped` artar |

Hedef alanları: `name` (küçük harf, rakam, `-`, `_`; ≤32), `tls_verify`
(varsayılan **`true`**), `ca_pem` (sistem deposu yerine güvenilecek CA),
`client_cert_pem` (karşılıklı TLS; anahtarı gizli olarak). Syslog: `host`,
`port` (6514), `protocol` (`tls` | `tcp` | `udp`), `format` (`rfc5424` | `cef`),
`facility` (13), `max_message_bytes` (8192), `timeout_s`. HTTP: `url` (https;
`http://` yalnız `allow_plaintext: true` ile), `format` (`json` | `cef`),
`auth_header`, `auth_scheme`, `timeout_s`.

### Gizli değerler

Jeton ve istemci anahtarı `core/secrets_manager.py` ile
`AUDIT_EXPORT_<HEDEF>_TOKEN` ve `AUDIT_EXPORT_<HEDEF>_CLIENT_KEY` adlarıyla
saklanır (`<HEDEF>` = büyük harfli ad, `-` → `_`). Ad hedeften türetilir ve
yapılandırılamaz; böylece bir yapılandırma yazımı başka bir gizliyi (ör. bir
LLM anahtarını) seçip dışarı gönderemez. İstemci anahtarı diske yalnızca
`load_cert_chain` süresince, 0700 izinli geçici bir dizinde yazılır.

### Ağ güvenliği

- TLS 1.2+; doğrulama varsayılan açıktır. `tls_verify: false`, düz `tcp`/`udp`
  ve `http://` yalnız laboratuvar içindir ve `status` yanıtında `insecure`
  listesinde görünür.
- Adres denetimi `core/platform/url_safety.py` ile yapılır. Bulut metadata
  adresleri (`169.254.169.254`, `169.254.170.2`, `fd00:ec2::254`,
  `100.100.100.200`, `168.63.129.16`) ve adları, link-local, çoklu yayın,
  belirtilmemiş ve ayrılmış adresler hem yapılandırmada hem bağlantı anında
  reddedilir. Loopback, RFC 1918, CGNAT `100.64.0.0/10` (VPN kaplamaları) ve
  IPv6 ULA izinlidir (SIEM aktarıcıları genelde oradadır); metadata adresleri bu
  aralıkların içinde de reddedilir. Yanıttaki tek bir yasak adres ana makineyi
  reddeder.
- **DNS yeniden bağlama (rebinding) yok:** ad bir kez çözülür, denetlenir ve
  bağlantı yalnızca denetlenen IP'ye kurulur (syslog: IP'ye bağlanılır, TLS SNI
  ve doğrulama özgün ad ile; HTTPS: istek IP'ye gider, `Host` başlığı ve TLS
  SNI/sertifika doğrulaması özgün ad ile). httpx adı yeniden çözmez.
- HTTP yönlendirmeleri izlenmez; ortam proxy değişkenleri kullanılmaz.

## Çalışma modeli ve çok kopyalı kurulum

Servis API yaşam döngüsünde kurulur (`app.state.audit_export`). Bir denetçi
görev yapılandırmayı `refresh_s` (15 sn) aralıkla — ya da bir PUT'tan hemen
sonra — okur. Her süreç denetçiyi çalıştırır ama yalnızca Postgres danışma
kilidini (`pg_try_advisory_lock(8274136)`) alan süreç aktarım yapar; bağlantı
koparsa kilit düşer ve başka bir süreç devralır. Bir hattın okuyucu ya da
gönderici görevi beklenmedik biçimde biterse (`Pipeline.running` ikisinin de
canlı olmasını ister) `last_error` `task_died:<read|send>` olur, denetçi hemen
uyandırılır ve hat yeniden başlatılır; commit edilmemiş kuyruk yeniden okunur.

Auth olayları istek işleyicilerinde (`services/api/routers/auth.py`,
`users.py`) `record_auth_event` ile biriktiriciye yazılır (`async def`
işleyicilerde `arecord_auth_event`: `flock` ve `fsync` olay döngüsünü
bloklamasın diye bir iş parçacığında çalışır): kanca tüm
istisnaları yutar (oturum açma asla denetim yüzünden bozulmaz) ve
aktarım kapalıyken hiçbir şey yapmaz. Olay, isteğin veritabanı işlemi commit
edilmeden önce yazılır; bu nedenle nadiren, sonradan geri alınan bir işlem
(ör. 500 ile biten bir kullanıcı güncellemesi) için de olay görülebilir.
**Birden çok API kopyası varsa `$VIGIL_DIR/audit_export/` tüm kopyalar
arasında paylaşılan bir birimde olmalıdır**; aksi halde lider olmayan
kopyaların auth olayları aktarılmaz.

## Metrikler

`GET .../status` her hedef için `events_read`, `events_sent`,
`events_dropped`, `batches_sent`, `delivery_failures`, `source_errors`,
`redactions`, `queue_depth`/`queue_max`, `last_success_at`, `last_error`
(sabit kodlar: `connect_failed`, `tls_handshake_failed`, `http_<kod>`,
`timeout`, `dns_failed`, `egress_refused`, `source_failed:<kaynak>` …),
kaynak başına gönderim sayısı ve imleçleri döndürür.

Prometheus (`/metrics`):

| Metrik | Tür | Etiketler |
|---|---|---|
| `autosecops_audit_export_enabled` | gauge | — |
| `autosecops_audit_export_leader` | gauge | — |
| `autosecops_audit_export_events_sent_total` | counter | `destination`, `source` |
| `autosecops_audit_export_delivery_failures_total` | counter | `destination` |
| `autosecops_audit_export_events_dropped_total` | counter | `destination` |
| `autosecops_audit_export_spool_dropped_total` | counter | — |
| `autosecops_audit_export_queue_depth` | gauge | `destination` |
| `autosecops_audit_export_last_success_timestamp_seconds` | gauge | `destination` |

Önerilen alarmlar: `time() - last_success_timestamp_seconds > 600` (aktarım
durdu), `delivery_failures_total` artışı, `spool_dropped_total > 0`.

## Bilinen sınırlar

- `agent_events.ts` üzerinde indeks yoktur; çok büyük defterlerde
  `start_from: beginning` ilk taramayı yavaşlatır (ayrı WP).
- `approval_actions` bir günlük değil değişken bir satırdır. Postgres'te bir
  satırın her UPDATE'i `xmin`'ini değiştirir; bu yüzden satır sonradan
  güncellendiğinde önceden aktarılmış geçişleri yeniden okunur (aynı `id` ile
  tekrar — en-az-bir-kez; SIEM'de `id` ile tekilleştirin). Aynı geçiş
  sütununun yeniden yazılması (ör. yeniden onay) yeni bir `id` üretmez.
- `xmin` filtresi indeks kullanamaz: her yoklama kaynak tabloyu tarar
  (`agent_events.ts` için zaten indeks yoktur). Çok büyük tablolarda
  `poll_interval_s`'i büyütün.
- Mantıksal geri yükleme (pg_dump/restore) satırlara yeni işlem kimlikleri
  verir: imleç veritabanının işlem sayacından ilerideyse bu fark edilir ve
  kaynak baştan yeniden okunur (tekrarlar, kayıp yok). Sayacın imleci zaten
  geçtiği bir kümeye geri yükleme fark edilmez; geri yüklemeden sonra
  `cursors.json`'u silin (`start_from` uygulanır).
- Bağımlılık notu: ajan defteri hash zinciri (`prev_hash`, `event_hash`,
  `31_agent_ledger_hash_chain.sql`) olduğu gibi aktarılır. Paralel yürüyen
  denetim zinciri işi (W1.10, `core/audit/*`) bu modülce kullanılmaz; o iş
  birleştiğinde onun tablosu ayrı bir kaynak olarak eklenebilir.
