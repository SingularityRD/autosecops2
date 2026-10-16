# Güvenlik teknik belgesi

> **English summary.** Security architecture of AutoSecOps at `main` @ `b8795def`: components and data flows (with the durable webhook ingest
> spool), eight trust boundaries, the provenance/verdict contract (enforced on
> the live daemon triage path, with known limits; analysis fields in a payload
> are dropped), the human-approval rule, per-category autonomy tiers (default
> Approve; Autonomous only for reversible, TTL-bound actions while the QA
> false-negative bound holds, with a circuit breaker), and the response policy
> (protected assets, hourly limits, TTL expiry and revert, four-eyes approval
> with an optional distinct-role rule, a segregation-of-duties report). No
> model-facing surface (including `/mcp`) can approve or reject a pending
> action; people decide on the AI Decisions → Pending Approvals tab. An approval is bound to the
> tool call's arguments, shows them in full and is refused above 64 KB. Open gap: approved agent MCP tools
> bypass the response policy. Also: audit records and hash chains (approvals
> and case audit records in a trigger-filled `audit_chain`, Ed25519-signed
> checkpoints of the chain heads once a signing key is configured, the
> `python -m core.audit.verify` CLI; configuration audit and approval decisions
> are not chained), signed per-case evidence packs, three layers of egress
> control, SIEM audit export over syslog/HTTPS (free-text PII redaction is
> best effort; structured fields are the reliable path), OIDC single sign-on,
> secret storage, a cryptography inventory with FIPS 140-3 mode (checkpoint
> and evidence-pack signatures stay Ed25519; `ssh_tunnel` is unsupported), and
> the automated red-team regression suite.
> Everything that is planned is marked **Planlı** with its branch.

Bu belge, AutoSecOps'un güvenlik mimarisini denetçi ve güvenlik mimarı için
anlatır. Bileşen başına tehditler [tehdit modelinde](tehdit-modeli.md), işletim
ayarları [yönetici kılavuzunda](yonetici-kilavuzu.md), kapsam
[sürüm kapsamında](kapsam.md).

## 1. Mimari

| Bileşen | Teknoloji | Görev | Kurulumda |
|---|---|---|---|
| Web konsolu | React SPA (`clients/web`) | Analist ve yönetici arayüzü | backend tarafından sunulur |
| API | Python / FastAPI (`services/api`) | Bulgular, vakalar, onaylar, ayarlar, kimlik doğrulama | `backend` Deployment |
| SOC daemon | Python (`services/daemon`) | Alarm çekme (federation) ve webhook alımı, triage, yanıtlayıcı (onaylı eylemleri politika ve yürütücü kayıt defteri üzerinden uygular), zamanlanmış işler, saklama/imha işi, imzalı denetim kontrol noktası işi, vaka otomasyonu, kanarya | `daemon` StatefulSet; Helm'de iki kopya, Postgres danışma kilidiyle tek lider |
| LLM worker | Python ARQ (`services/worker`) | Kuyruktaki model çağrıları | `llm-worker` Deployment |
| Ajan katmanı | TypeScript (`services/agent`) | İş akışı çalışma zamanları (compose, investigate, root cause, hunt); ajan defteri | `agent-worker`, `agent-serve` |
| LLM ağ geçidi | Bifrost | Model sağlayıcılarına tek çıkış; air-gap'te yalnız Ollama | `k8s/llm-stack.yaml` |
| Yerel model | Ollama | Air-gap'te model çıkarımı | `k8s/llm-stack.yaml` |
| Veritabanı | PostgreSQL 16 | Tüm kalıcı durum; uygulama `vigil_app` rolüyle bağlanır | `postgres` StatefulSet |
| Önbellek / kuyruk | Redis 7 | Kuyruklar, tekilleştirme, oturum iptal listesi | `redis` StatefulSet |
| MCP sunucuları | alt süreçler | Entegrasyon araçları; varsayılan kapalı (iki yerel sunucu hariç) | backend içinde |
| Medic | ayrı servis | Kurulum sağlığı izleyicisi; varsayılan kapalı | isteğe bağlı |

Alarm akışı (bu sürüm): kaynak (federation poller, daemon webhook'u, dosya alımı) →
(webhook'ta) kalıcı alım kuyruğu → `FindingProcessor` → (bayrak açıksa alarm şeridi
seçimi) → tek çağrılık AI triage (Bifrost üzerinden model, açıksa küçük model
şeridinde yerel model; cevap karar şemasına uyan tek JSON nesnesi) → bulgu/vaka → yanıtlayıcı eylem önerir → müdahale politikası →
otonomi katmanı → `approval_actions` → insan onayı (ya da yalnızca Autonomous
katmanında kişisiz serbest bırakma) → politika + otonomi katmanının yeniden kararı +
yürütücü → doğrulama → süre dolunca geri alma → vaka zaman çizelgesi.

**Kalıcı alım kuyruğu (W0.12).** Daemon webhook'u (`/ingest`, `/webhook`) bir
bulguya 200 dönmeden önce onu diskte, `fsync` edilmiş ve yalnızca eklenen bir
kuyruğa (spool) yazar. Varsayılan yer durum dizininde `spool/webhook`'tur.
Veritabanı yazımı başarısız olursa bulgu bırakılmaz, kuyruğa geri döner ve yeniden
denenir. Daemon yeniden başlayınca kuyruk yeniden oynatılır; zaten yazılmış bulgu
ikinci satır üretmez ve ikinci kez triage edilmez (W0.12b). Yazımı reddeden bir
veritabanı (salt okunur, disk dolu, yetki, bağlantı hatası) kesinti sayılır; bulgu
karantinaya değil kuyruğa döner. Okunamayan tek bir satır yalnızca kendisini
karantinaya taşır. Kuyruk dosyaları `0600`, dizinleri `0700` izinlidir. Kuyruk
doluysa ya da yazılamıyorsa webhook `503` ve `Retry-After` döner; gönderen yeniden
denemelidir. Ayarlar:
`DAEMON_INGEST_SPOOL_ENABLED`, `DAEMON_INGEST_SPOOL_DIR`,
`DAEMON_INGEST_SPOOL_MAX_FINDINGS` (10000), `DAEMON_INGEST_SPOOL_MAX_MB` (128).
Ayrıntı: [docs/operations/ingest-durability.md](../operations/ingest-durability.md).

**Redis kesintisinde yeniden triage yok (W0.15).** Model kuyruğu Redis
üzerindedir. Redis kapalıyken model çağrıları hata verir ve zenginleştirme devre
kesicisi açılır. Kararı model gerektirmeyen bir bulgu (kural şeridi ya da kuyruğa
alınmış verdict run) kesici açıkken de hemen kaydedilir. Kesici kapanınca çalışan
backfill süpürmesi, bir bulguyu yeniden kuyruğa almadan önce `alert_lane_decisions`
tablosuna bakar: kapatan bir kararı olan bulgu yeniden şeritlenmez ve triage
edilmez, kayıtlı karar bulguya yazılır. Kararlar okunamazsa o turda hiçbir şey
kuyruğa alınmaz (kapalı başarısız) ve sayaçta görünür. İstisna:
`alert_lane_decisions` tablosu hiç yoksa (56 numaralı init SQL uygulanmamış kurulum)
backfill eski davranışa döner ve her bulguyu yeniden şeritler; bunu bir ERROR logu
ve `soc_daemon_backfill_lane_decisions_missing_total` sayacıyla bildirir. Bu
durumda Redis kesintisinden sonra çift triage yeniden mümkündür; init SQL'i
uygulayın. Modele ihtiyaç duyan
bulgular kesici kapanınca triage edilir; bu verdict'ten önce olduğu için çift
işlem değildir.

## 2. Güven sınırları

| # | Sınır | Karşı taraf | Uygulanan denetim |
|---|---|---|---|
| G1 | Tarayıcı ↔ API | kimliği doğrulanmış kullanıcı | TLS ingress'te sonlanır; HS256 JWT (çerez, `Secure`, `SameSite=strict`); isteğe bağlı OIDC SSO (PKCE, imzalı ID token, tek kullanımlık `state`); CSRF çift gönderim çerezi (oturum çerezi taşıyan alım istekleri dahil); rol izinleri her yazma rotasında sunucu tarafında; hız sınırları; Redis tabanlı oturum iptali (kapalı başarısız) |
| G2 | Alarm kaynakları → daemon/API | saldırganın etkileyebildiği veri | Daemon webhook'u (NetworkPolicy açıkken) `networkPolicies.daemon.webhookAllowFrom` CIDR'lerine sınırlı; alarm içeriği **güvenilmez** sayılır (bkz. §3); kanarya ve QA ile ölçüm |
| G3 | API ↔ ajan katmanı | iç servis | `/internal` uçları yalnızca `AGENT_INTERNAL_TOKEN` paylaşılan sırrıyla (sabit zamanlı karşılaştırma); NetworkPolicy ile hangi pod'ların bağlanabileceği sınırlı; onay gerektiren araçlar, argümanları onaylanan çağrınınkiyle aynı olan onaylanmış bir onay noktası olmadan reddedilir; karar araçları her durumda reddedilir. Onaydan sonra araç müdahale politikasından geçmez (açık risk R2) |
| G4 | Uygulama ↔ model | yerel ya da müşterinin seçtiği sağlayıcı | Tek çıkış Bifrost; air-gap'te bulut anahtarları boş ve egress kapalı; modelin çıktısı doğrudan hiçbir API çağrısına dönüşmez (araç etki sınıfları, onay kuyruğu); onay ve red kararı yalnızca kişinin kendi oturumlu HTTP isteğiyle verilir, hiçbir model yüzeyinde karar aracı yoktur |
| G5 | Uygulama → dış entegrasyonlar | SIEM, EDR, IdP, güvenlik duvarı | Kimlik bilgileri şifreli sır deposunda; TLS doğrulaması açık (kapatma CI ratchet'iyle yasak); SIEM aktarımı varsayılan kapalı, gönderimden önce maskeler; kullanıcı girdisi URL'ler için SSRF koruması; egress NetworkPolicy |
| G6 | Uygulama ↔ veri depoları | Postgres, Redis | Uygulama sahip olmayan `vigil_app` rolüyle bağlanır; `agent_events` üzerinde bu rolün UPDATE/DELETE/TRUNCATE yetkisi yoktur; `audit_chain`'i yalnızca okuyabilir, `audit_checkpoints`'e yalnızca ekleyebilir |
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
- Gönderenin yükte verdiği analiz alanları (`triage_confidence`,
  `recommended_action`, `ai_triage`, `enrichment`, `category`, önceki karar)
  işlemeden önce atılır (`drop_payload_analysis`). Böylece gönderen, AutoSecOps'un
  kendi analizi gibi görünen bir güven ya da öneri yazarak müdahaleyi
  yönlendiremez.
- `data_source` alanını gönderen seçer (webhook gövdesi, Kafka mesajı, içe aktarma).
  Gönderen bir adaptör adı yazarak o adaptörün daha geniş sensör haritasını
  alabilir. Güven sınırı gönderenin kimlik doğrulamasıdır.
- Ajan katmanındaki (TypeScript) iş akışları bu triage yolunu kullanmaz.
- Injection test seti (`eval/suites/injection/v1.jsonl`) `evalkit` ile çevrimdışı
  ölçülebilir. CI'da kayıtlı bir kasetle ölçülen saldırı başarı oranı kayıtlı tabanı
  (21/240) aşamaz; bu bir gerileme kapısıdır (§9).
  ≤ %5 saldırı başarısının kapı olması (Planlı — `wp/w1.4-injection-set`, bu sürümde yok).

Bu sürümde injection'a karşı **etkin** olan savunmalar:

- **Araç etki sınıfları** (`core/llm/tool_effects.py`): yazan/yıkıcı hiçbir araç,
  bir insanın yanıtladığı onay noktası olmadan çalışamaz. Sohbet bu araçları
  sunmaz. Tabloda olmayan araç en kısıtlayıcı sınıfa düşer.
- **Model onay veremez (W1.7b).** `decision` sınıfı yalnızca insana aittir
  (`HUMAN_ONLY`). `approve_action` / `reject_action` araçları kaldırıldı; önceki
  sürümde `/mcp` sunucusu bunları sunuyordu ve MCP ile bağlanan bir model kendi
  önerdiği eylemi onaylayabiliyordu. Kişiler konsolda **AI Decisions →
  Pending Approvals** ekranından karar verir. Sohbet,
  iş akışları, ajanların önerdiği araçlar, AutoSecOps'un `/mcp` sunucusu,
  `/internal/tools/invoke` ve MCP yürütücüsü karar araçlarını sunmaz ya da
  reddeder. Adı `approve`, `reject`, `decline` ya da `authorize` ile başlayan
  tanınmayan bir araç da karar sayılır. Onay ve red yalnızca kişinin kendi
  oturumlu HTTP isteğiyle verilir (`POST /api/v1/approvals/{action_id}/approve`,
  `.../reject`). CI'da `tests/unit/_ratchets/test_no_model_approvals.py` her model
  yüzeyinde karar aracı sayısının 0 olduğunu sınar.
- **Onay argümana bağlı (W1.7b).** Bir araç çağrısında duran onay noktası, onay
  satırına aracın adını, argümanlarının kanonik JSON özetini (`args_sha256`) ve
  kişiye gösterilen kısa özetini yazar. `/internal/tools/invoke` onaylı çağrıyı
  yalnızca gelen argümanların özeti satırdakiyle eşleşirse çalıştırır: A makinesi
  için onaylanan izolasyon B makinesi için tekrar oynatılamaz. Onay satırı
  kanonik argümanların tamamını ve hedef alanlarını taşır; kişiye gösterilen hedef
  değerleri 200 karakterle sınırlı, kontrol ve yön değiştiren Unicode karakterleri
  kaçışlıdır (W0.14, W0.16).
- **Argüman sınırı (W0.16).** Kanonik argümanları 64 KB'ı aşan bir araç çağrısı
  onaya park edilmez: `/internal/runs/{run_id}/checkpoints` ve `.../phases` 413
  döner, onay satırı yazılmaz; onay olmadığı için çağrı çalışamaz (kapalı
  başarısız). Böylece bir kişinin okuyamayacağı kadar büyük bir argüman onaya
  sunulamaz.
- **İnsan onayı olmadan eylem yok** (§4); tek istisna, bir kişinin kanıtla açtığı
  ve QA sınırına bağlı Autonomous katmanıdır.
- **Kanaryalar ve QA örneklemesi**: kaçırılan kötücül alarmların oranı ölçülür
  (yönetici açarsa); Karne yanlış negatif üst sınırını gösterir.
- **Kanarya bulguları** dış zenginleştirmeye, otomatik müdahaleye ve otonom
  soruşturmaya hiç gönderilmez.

## 4. Onaylar, otonomi katmanları, müdahale politikası ve dört göz onayı

Kural: **bir kişinin onaylamadığı müdahale eylemi uygulanmaz; tek istisna, bir
kişinin kanıtla açtığı Autonomous katmanıdır.** Onay kapısı
(`core/response/config.py`, `approval_requirement`) bir eylemin insan bekleyip
beklemeyeceğine karar verir ve kararı veren kuralı satıra yazar. Geri alınamaz
eylemler her zaman bekler. Yanıtlayıcı, `approved_by` alanı boş olan "onaylı" bir
satırı yalnızca otonomi katmanı onu serbest bıraktıysa uygular. Güven eşiğiyle
serbest kalan diğer satırlar loglanır, çalıştırılmaz. Onay `ai_decisions.approve`
izni ister ve onaylayanın kimliği oturumdan alınır.

**Otonomi katmanları** (`core/autonomy/`). Her (alarm kategorisi × eylem sınıfı)
çifti için dört katman vardır: **Watch** (satır oluşmaz), **Suggest** (öneri olarak
kaydedilir, bir kişi serbest bırakır), **Approve** (kişi onaylar) ve **Autonomous**.
Yapılandırılmamış her çiftin katmanı Approve'dur. Autonomous ancak şunların hepsi
doğruysa uygulanır:

- sınıf `block_domain` ya da `gateway_block`'tur ve eylem hem satırda hem yürütücü
  kaydında geri alınabilirdir. Çevreleme sınıfları (`isolate_host`, `disable_user`,
  `revoke_sessions`, `access_revoke`, `block_ip`, `waf_block`, `quarantine_file`)
  hangi katmanda olursa olsun her zaman kişi onayı bekler;
- sınıf dört göz onayı istemez; kategori `*` ya da `other` değildir;
- katmanda süre (en çok 7 gün) ve güven tabanı vardır, eylemin güveni tabana ve
  `DAEMON_CONFIDENCE_THRESHOLD`'a ulaşır; Assist kipi açık değildir;
- kategorinin QA sınırı tutar: en az 299 basit rastgele incelemeden tek taraflı
  %95 Clopper–Pearson yanlış negatif üst sınırı ≤ %1.

Sınır okunabilir ve tutmuyorsa devre kesici katmanı Approve'a düşürür, bunu
`config_audit_log`'a yazar ve uyarı loglar. Bu, karar anında, daemon'un 30 saniyelik
döngüsünde ve `POST /api/autonomy/check` ile olur. Kategori, sensörün yazdığı
alanlardan (MITRE tekniği, `data_source`) ve gerekirse triage kararından kodla
belirlenir; gönderenin yükte yazdığı kategori alanı okunmaz. Katmanı yalnızca bir
kişi, `https://` kanıt bağlantısıyla yükseltebilir; hizmet hesabı, ajan ya da MCP
yükseltemez. Yanıtlayıcı, kişisiz serbest kalan satırı uygulamadan hemen önce
katmanı yeniden kararlaştırır; artık Autonomous değilse satır onay kuyruğuna döner.
Autonomous eylem de müdahale politikasından geçer.

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

Korunan hedefler, varlık etiketleri, saatlik sınırlar ve dört göz türleri konsoldan
(Ayarlar → System → Response policy; `PUT /api/response/policy`, `settings.write`)
gerekçeyle değiştirilir; her değişiklik `config_audit_log`'a değiştiren, gerekçe ve
eski/yeni değerle yazılır (W0.36). Varsayılan korunan etiketler ve dört göz türleri
kaldırılamaz.

**Yürütücüler** `Executor` protokolünü (`validate`, `execute`, `verify`, `reverse`)
uygular ve süreç başına bir kez kurulan kayıt defteri üzerinden çalışır
(`core/response/executors/wiring.py`). Cloudflare her zaman kayıtlıdır. Defender,
Entra ID ve PAN-OS, entegrasyonları etkinse kayda alınır. Her yürütücünün kendi
kuralları da vardır (tek makineye çözümleme, korunan roller, yönetim IP'si).
Süresi dolan geri alınabilir eylemi daemon geri alır ve doğrular. Bir kişi de
gerekçeyle geri alabilir. Her geri alma `approval_actions`'a ayrı bir satır olarak
yazılır. Host izolasyonu için yürütücü yoksa eylem `failed` yazılır (sahte başarı
yoktur).

**Dört göz onayı.** Kimlik eylemleri (`disable_user`, `revoke_sessions`) iki farklı
kişinin onayını ister; liste `response.policy` ile genişletilebilir. Diğer eylemler
tek onaylıdır. **Farklı rol koşulu** eylem sınıfı başına açılır
(`distinct_role_types`; Ayarlar → Segregation of duties ya da
`PUT /api/response/four-eyes/{action_type}`, gerekçe zorunlu). Açık olan sınıfta
ikinci onaylayan, birincinin onay anındaki rolünden farklı bir rolde olmalıdır; aksi
409 alır. Rolü bulunamayan onaylayan da reddedilir. Varsayılan olarak hiçbir sınıfta
açık değildir. Her onay kararı karar verenin o anki rolüyle `approval_decisions`
tablosuna eklenir. **Görevler ayrılığı raporu**
(`GET /api/response/segregation`, CSV/JSON dışa aktarma
`GET /api/response/segregation/export`, izin `users.read`) her eylem için öneren,
onaylayan, ikinci onaylayan ve yürüteni rolleriyle ve ihlalleriyle listeler
(`self_approval`, `same_person`, `missing_second_approver`, `same_role`,
`unknown_role`, `executed_without_approval`).

**Açık risk: onaylanmış MCP araçları politikayı atlar.** Ajan iş akışlarında onay
gerektiren bir MCP aracı (`mde_isolate`, `aad_disable_user`, `pan_block_ip`,
`cb_quarantine`, Cloudflare `cf_*` araçları) bir kişi onay noktasını onayladıktan
sonra `/internal/tools/invoke` üzerinden satıcı API'sini doğrudan çağırır. Bu yolda
müdahale politikası, korunan varlık listesi, saatlik sınır, yürütücü kuralları,
süre dolumu ve dört göz onayı uygulanmaz. Onay araç adına ve argümanlarına bağlıdır;
yani kişinin gördüğü çağrı çalışır, ama politika denetimi yoktur. Ayrıntı ve telafi
edici önlem: [tehdit modeli R2](tehdit-modeli.md#açık-riskler).

## 5. Denetim kayıtları ve zincir

| Kayıt | Bütünlük |
|---|---|
| `agent_events` (ajan defteri) | Koşu başına hash zinciri: `event_hash = sha256(prev_hash ‖ payload)`, `BEFORE INSERT` tetikleyicisi atar (yazan kod değil). Uygulama rolü `vigil_app` bu tabloda UPDATE/DELETE/TRUNCATE yapamaz. Zincir başı imzalı kontrol noktasına girer (aşağıda). Doğrulama: `npm run ledger:verify` (ajan katmanı), koşu başına `GET /api/workflows/runs/{run_id}/verify` ya da `python -m core.audit.verify --agent-events` |
| `approval_actions` | Eylem, karar kuralı, onaylayan, uygulama sonucu, otonomi kaydı (`parameters.autonomy`), araç çağrısının argüman özeti; her INSERT, gerçek değişiklik içeren UPDATE, DELETE ve TRUNCATE `audit_chain`'e zincirlenir |
| `case_audit_logs` | Vaka alanı değişiklikleri; `audit_chain`'e zincirlenir (aynı tetikleyiciler) |
| `audit_chain` | Yukarıdaki iki tablonun tüm veritabanı için tek, yalnızca eklenen SHA-256 zinciri: `event_hash = sha256(prev_hash ‖ satır)`, sıra numarası, kaynak tablo ve anahtar, olay (`insert`, `update`, `delete`, `truncate`), satırın tamamı. Zincir satırları işlem commit edilirken tek bir danışma kilidiyle yazılır. `vigil_app` yalnızca okur; UPDATE/DELETE/TRUNCATE her rol için tetikleyiciyle reddedilir |
| `audit_checkpoints` | `agent_events` ve `audit_chain` başlarının Ed25519 imzalı kontrol noktaları; her biri öncekinin gövde özetine bağlı. `vigil_app` yalnızca okur ve ekler; değişiklik tetikleyiciyle reddedilir |
| `regulatory_clock_events` | Vaka başına hash zinciri; UPDATE ve `TRUNCATE` tetikleyiciyle reddedilir; zincirin son satırı tetikleyicinin tuttuğu `regulatory_clock_heads` çapasıyla karşılaştırılır (son olayların silinmesi ve sıra dışı ekleme görünür); her olay `case_audit_logs`'a da yazılır; zincir kontrolü API yanıtında |
| `config_audit_log` | Ayar değişikliği, değiştiren kullanıcı ve gerekçe; saklama/imha çalıştırmaları ve yasal saklama kararları (`config_type='retention'`); geri yükleme; **zincirsiz** |
| `approval_decisions` | Her onay kararı (onay, ilk onay, ikinci onay, red), karar verenin hesabı ve o anki rolü; UPDATE/DELETE/TRUNCATE her rol için tetikleyiciyle reddedilir; **zincirsiz** |

**İmzalı kontrol noktaları.** Daemon'un `audit_checkpoint` işi
`AUDIT_CHECKPOINT_INTERVAL_SECONDS` (varsayılan 3600; `0` kapalı, en az 60 sn)
aralıkla iki zincirin başını, satır sayılarını ve önceki kontrol noktasının
özetini imzalar. İmza anahtarı `AUDIT_CHECKPOINT_SIGNING_KEY` sırrıdır (Ed25519);
anahtar yoksa iş uyarı loglar ve **hiçbir şey yazmaz**. Anahtar kurulumda
üretilir (W0.36: Compose'da `signing-keys` servisi sır deposuna, Helm'de
`<release>-vigil-signing-key-checkpoint` Secret'ına; var olan anahtar değiştirilmez); elle
`python -m core.audit.checkpoint keygen` ile de üretilebilir. Doğrulamada
kullanılacak açık anahtar (`AUDIT_CHECKPOINT_PUBLIC_KEY`)
`python -m core.audit.signing_keys export` ile alınır. İmza yapılandırılmamışsa
`/api/health` `warnings` listesinde bunu bildirir.
`AUDIT_CHECKPOINT_FILE` verilirse her kontrol noktası ayrıca bir dosyaya JSON satırı
olarak eklenir; bu kopya veritabanı dışında, başka bir makinede tutulmalıdır.
`AUDIT_TSA_URL` verilirse her kontrol noktası için bir RFC 3161 zaman damgası
alınır ve saklanır (varsayılan ve air-gap profilinde kapalı; token kriptografik
olarak doğrulanmaz, yalnızca varlığı raporlanır).

**Doğrulama.** `python -m core.audit.verify` zinciri yürür; hash'leri, sıra
boşluklarını, kontrol noktalarının imzasını, birbirine bağlantısını ve kaydettiği
başları, kaynak tabloların zincirle tutarlılığını (zincir dışı ekleme, değişiklik,
silme, kaydırılmış geçmiş, eksik kolon, takılı olmayan tetikleyici) denetler. İlk
kırılmayı nedeniyle raporlar; temizse 0, kırılmada 1, kullanım ya da bağlantı
hatasında 2 ile çıkar. `--require-signature` ile güvenilir açık anahtar yoksa ya da
hiç imzalı kontrol noktası yoksa da 1 ile çıkar; zamanlanmış doğrulamalarda bu
bayrağı ve `--public-key` ile veritabanı dışından verilen açık anahtarı kullanın.
Bayraksız doğrulama, güvenilir anahtar bulamazsa kontrol noktalarını kendi
satırlarındaki anahtarla denetler ve bunu UNTRUSTED olarak yazar.

Sınırlar (bu sürüm):

- Kontrol noktası zinciri yalnızca kaydettiği başa kadar korur. Son kontrol
  noktasından sonra yazılan zincir satırları ve ajan defteri olayları, tablo sahibi
  ya da süper kullanıcı tarafından tespit edilmeden silinebilir ya da yeniden
  yazılabilir. Aralığı kısa tutun.
- Koruma, imza anahtarının verilmesine, işin açık olmasına ve doğrulamanın
  veritabanı dışında tutulan açık anahtarla (ve dosya kopyasıyla) yapılmasına
  bağlıdır. Kontrol noktalarının kendisi silinirse bu yalnızca dosya kopyası ya da
  TSA token'ı ile görülür.
- Tablo sahibi ya da süper kullanıcı tetikleyicileri kapatabilir. Hedef önleme
  değil tespittir: tetikleyici atlanarak yapılan değişiklik doğrulayıcıda görünür.
- Denetlenen tablolarda kolon silmek ya da yeniden adlandırmak doğrulayıcıda
  kırılma olarak görünür. Bilinçli bir şema değişikliğinden sonra
  `python -m core.audit.checkpoint rebaseline --table <tablo> --reason "<neden>"`
  imzalı bir yeniden temel alma kaydı yazar.
- Düzenleyici an zincirinin çapası aynı veritabanındadır. Tablo sahibi ya da süper
  kullanıcı iki tabloyu birlikte yeniden yazabilir (R27).
- `config_audit_log` (imha tutanağı dahil) ve `approval_decisions` zincirde
  değildir.
- SIEM aktarımı (aşağıda) açılmadıkça olayların veritabanı dışında bir kopyası
  yalnızca `AUDIT_CHECKPOINT_FILE` ile tutulur.

**SIEM'e denetim aktarımı (W3.6).** Varsayılan kapalı. Açıldığında
(`PUT /api/compliance/audit-export/config`, `settings.write`) ajan defteri, onay
geçişleri, kimlik doğrulama olayları, `config_audit_log`, `case_audit_logs` ve
imzalı kontrol noktaları RFC 5424 syslog (TLS) ya da HTTPS (JSON, CEF) ile SIEM'e
akar. Kontrol noktaları gövde, imza ve açık anahtarla olduğu gibi gider; SIEM böylece
zincir başlarının veritabanı dışındaki kopyası olur. Teslim en az bir kezdir
(kalıcı imleç, kararlı `id`, üstel geri çekilme, sınırlı kuyruk). Olaylar
gönderilmeden önce sırlar ve kişisel veri maskelenir. Yapısal alanlarda (anahtar adı
`password`, `email`, `diagnosis` gibi) maskeleme güvenilirdir. Serbest metinde ise
en iyi çaba ile yapılır ve tanınmayan düzyazı biçimleri olduğu gibi gider. Aktarımı
tek bir süreç yapar (Postgres danışma kilidi). Ayrıntı:
[core/compliance/AUDIT_EXPORT.md](../../core/compliance/AUDIT_EXPORT.md).

**Kanıt paketi (W3.7).** Vaka sayfasındaki **Evidence pack** düğmesi
(`GET /api/cases/{case_id}/evidence-pack`, `cases.read`) vakanın imzalı ZIP
arşivini indirir: vaka, bulgular, kanıt, vaka denetim kaydı, eylemler (onaylar,
yürütme sonucu, önceki/sonraki durum, doğrulama, geri alma), vakanın ajan koşularının
defter olayları, AI karar kökeni, düzenleyici an olayları ve (varsa) `audit_chain`
satırları. `manifest.json` her dosyanın SHA-256 özetini, `manifest.sig` manifestin
Ed25519 imzasını taşır. Anahtar `EVIDENCE_PACK_SIGNING_KEY` sırrıdır; kurulumda
üretilir (W0.36) ya da `scripts/autosecops evidence-keygen` ile verilir; yoksa paket her seferinde üretilen geçici
bir anahtarla imzalanır ve manifest bunu `key_source: "ephemeral"` olarak söyler,
bu durumda imza yalnızca paketin kendi içinde tutarlı olduğunu kanıtlar.
`scripts/autosecops verify-bundle <paket> --public-key <anahtar>` ağ ve
veritabanı olmadan imzayı, her dosyanın özetini, eksik ya da fazla dosyayı ve
defter, düzenleyici an ve denetim zincirlerinin yeniden hesabını denetler;
kurcalanmış paketi 1 ile reddeder. Paket redaksiyon yapmaz: `cases.read` sahibine
vakanın ham kayıtlarını verir.

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
yönlendirme izlenmez ve ortam vekili kullanılmaz. W3.6'dan beri global olmayan her
adres, CGNAT 100.64.0.0/10 (ör. 100.100.100.200 metadata adresi) dahil, varsayılan
olarak reddedilir. Şirket içi bir LLM ağ geçidi bu aralıktaysa
`LLM_PROVIDER_ALLOWED_CIDRS` ile, giden webhook hedefi için `WEBHOOK_ALLOWED_CIDRS`
ile izin verilir; metadata adresleri bu aralıkların içinde de reddedilir. SIEM
aktarımı şirket içi (RFC 1918, CGNAT, ULA) hedeflere izin verir, metadata
adreslerini reddeder.

## 7. Sırlar

| Sır | Nerede |
|---|---|
| Entegrasyon ve sağlayıcı kimlik bilgileri | Şifreli sır deposu (`SECRETS_BACKEND`). Compose ve tek sunucu (`encrypted`): `secrets.enc` (Fernet), anahtar aynı durum dizininde `master.key` (dizin 0700, dosya 0600). Kubernetes (`database`, Helm varsayılanı): PostgreSQL `platform_secrets` tablosunda veri anahtarıyla Fernet şifreli satırlar; tüm kopyalar paylaşır, yeniden başlatmada kaybolmaz, hiçbir dosyaya yazılmaz. Entegrasyon yapılandırmasına ve JSON'a yazılmaz; API yanıtlarında maskelenir |
| `AUDIT_CHECKPOINT_SIGNING_KEY` | Sır deposu ya da ortam / Secret (Ed25519 tohumu; hex, base64 ya da PEM). Kurulumda üretilir (Compose: sır deposu; Helm: `<release>-vigil-signing-key-checkpoint` Secret'ı, yalnızca daemon'a verilir). Yalnızca daemon'un kontrol noktası işi ve `python -m core.audit.checkpoint` kullanır. Doğrulayıcıya yalnızca açık anahtar (`AUDIT_CHECKPOINT_PUBLIC_KEY`) verilmelidir |
| `EVIDENCE_PACK_SIGNING_KEY` | Sır deposu ya da ortam / Secret (Ed25519); kurulumda üretilir (Helm: `<release>-vigil-signing-key-evidence`, yalnızca backend'e verilir); yalnızca kanıt paketini imzalayan API kullanır |
| `JWT_SECRET_KEY` | Sır deposu (`secrets.enc`), ortam / Kubernetes Secret ya da `.env`; okuma önceliği aşağıda. Anahtar verilmemişse `start.sh` durum dizininde bir `jwt_secret` dosyası üretir ve onu ortama verir. `DEV_MODE=false` iken zorunlu, yoksa backend açılmaz. Yalnızca oturumları, parola sıfırlama bağlantılarını ve araç çağrısı kimliğini imzalar; veri şifrelemez |
| Veri anahtarı (`VIGIL_DATA_KEY`) | Ortam / Kubernetes Secret (`secrets.dataEncryptionKey`); virgülle ayrılmış birden çok anahtar (ilki şifreler, hepsi çözer), her biri HKDF-SHA256 ile Fernet anahtarına türetilir. Tanımlı değilse durum dizinindeki `master.key`. `SECRETS_BACKEND=database` ve `DEV_MODE=false` iken zorunlu, yoksa backend açılmaz |
| OIDC istemci sırları | Sır deposu (`OIDC_CLIENT_SECRET_<ID>`); API geri döndürmez |
| SIEM aktarım jetonları ve istemci anahtarları | Sır deposu (`AUDIT_EXPORT_<HEDEF>_TOKEN`, `AUDIT_EXPORT_<HEDEF>_CLIENT_KEY`); ad hedeften türetilir, başka bir sırra yöneltilemez; saklı jeton uç noktaya bağlıdır |
| `AGENT_INTERNAL_TOKEN` | Ortam / Secret; API ile ajan katmanı arasındaki tek kimlik doğrulama |
| Postgres / Redis parolaları | Secret (`existingSecret` desteklenir) |
| TOTP sırları | Veritabanında, veri anahtarıyla Fernet şifreli (`dk:` önekli). 2.0 öncesinden kalan, `JWT_SECRET_KEY`'den türetilen anahtarla şifreli satırları backend açılışta bir kez ve idempotent olarak veri anahtarına taşır (`core/crypto/rekey.py`) |
| Giden webhook imza anahtarları | Sır deposu; tabloda yalnız `secret_ref` |
| Air-gap paket imza anahtarı | Yalnızca imzalama makinesi; pakette hiçbir anahtar yok |

Okuma önceliği: (`SECRETS_BACKEND=database` ise) veritabanı deposu → şifreli dosya →
ortam değişkeni → depo kökündeki `.env` (salt okuma) → durum dizinindeki `.env` →
(açıkça etkinleştirilirse) işletim sistemi anahtarlığı. Veritabanı deposu düz
dosyaya geri düşmez: anahtar yoksa ya da veritabanı açık değilse kaydetme başarısız
olur. Kubernetes'te durum dizini varsayılan olarak geçicidir ve sır tutmaz; Secret
ya da ExternalSecrets Operator (`secrets.externalSecret.enabled`; Vault, AWS
Secrets Manager vb.) ile verilen değerler de okunur.

Döndürme: her sır için sıra ve neyin bozulduğu yönetici kılavuzundadır
([Sır döndürme](yonetici-kilavuzu.md#sır-döndürme)). `JWT_SECRET_KEY`'i döndürmek
yalnızca oturumları düşürür. Veri anahtarı üç yayılımla kesintisiz döndürülür
(`K1,K2` → `K2,K1` → `K2`); `master.key` için `python -m core.crypto.rekey
rotate-master-key` vardır (servisler dururken). Veritabanı yedeğinden geri yükleme
bekleyen onayları reddeder. `JWT_SECRET_KEY` `secrets.enc`'te, `.env`'de ya da
`jwt_secret` dosyasındaysa onu döndürür; hâlâ JWT'den türetilen anahtarla şifreli
TOTP sırlarını önce veri anahtarına taşır. Anahtar yalnızca geri yükleme sürecine
verilen ortam değişkeninden geliyorsa yeni anahtar `secrets.enc`'e yazılır. Backend
anahtarı `secrets.enc`'ten ortamdan önce okur (`core/secrets_manager.py`,
`core/auth/auth_service.py`). Bu yüzden aynı durum dizinini okuyan servisler
yeniden başlayınca yeni anahtarı kullanır ve eski oturumlar düşer. Geri yüklemenin
kendi çıktısı bunun tersini söyler ("an environment value outranks secrets.enc");
o ileti yanlıştır. Anahtar kurulum dışında tanımlıysa ve sürece verilmediyse
(ör. Kubernetes Secret) geri yükleme onu döndüremez ve hata ile biter. Bu durumda
anahtarı tanımlandığı yerde döndürün
(bkz. [yönetici kılavuzu](yonetici-kilavuzu.md#docker-compose--tek-sunucu)).
Bilinen sınır: Compose ve tek sunucuda `master.key`, çözdüğü `secrets.enc` ile aynı
birimde ve aynı yedektedir. Önlem: `VIGIL_DATA_KEY`'i birimin dışından verin (MFA
sırlarının anahtarı birimde durmaz), entegrasyon kimlik bilgilerini mümkünse
Secret/ortamdan verin. Kubernetes'te anahtar veritabanından ayrı bir Secret'tadır.
KMS, HSM ve Vault transit desteklenmez. Loglarda URL kullanıcı bilgisi
(`core/platform/log_redaction.py`) ve telemetri öznitelikleri
(`core/telemetry_sanitizer.py`) maskelenir.

## 8. Kriptografi envanteri

| Kullanım | Algoritma / yapı | Kütüphane |
|---|---|---|
| Parola ve kurtarma kodu özeti | bcrypt (tuzlu; 72 bayt üst sınır); FIPS modunda ya da `PASSWORD_HASH_SCHEME=pbkdf2_sha256` ile PBKDF2-HMAC-SHA256 (16 bayt tuz, varsayılan 600 000 yineleme) | `bcrypt`, `hashlib` |
| Parola sıfırlama belirteci | HMAC-SHA256 (itsdangerous, SHA-256 anahtar türetme) | `itsdangerous` |
| OIDC ID token doğrulaması | RS256 / ES256 (sağlayıcının JWKS'i); PKCE S256 | PyJWT, `cryptography` |
| Oturum belirteci | JWT, HMAC-SHA256 (HS256); erişim 30 dk, yenileme 7 gün | PyJWT |
| Sır deposu, TOTP sırrı şifrelemesi | Fernet (AES-128-CBC + HMAC-SHA256); veri anahtarı HKDF-SHA256 ile türetilir | `cryptography` |
| MFA | TOTP (RFC 6238) | `pyotp` |
| Giden webhook imzası | HMAC-SHA256, zaman damgalı (`t=…,v1=…`) | standart kütüphane |
| Ajan iç belirteci | sabit zamanlı karşılaştırma (`hmac.compare_digest`) | standart kütüphane |
| Defter, denetim zinciri (`audit_chain`) ve düzenleyici an zinciri | SHA-256 | PostgreSQL `sha256()` |
| Denetim kontrol noktası imzası | Ed25519; kontrol noktaları SHA-256 gövde özetiyle birbirine bağlı | `cryptography` |
| Kontrol noktası zaman damgası (isteğe bağlı, varsayılan kapalı) | RFC 3161 TSA isteği, SHA-256 özet | standart kütüphane + `httpx` |
| Kanıt paketi imzası | Ed25519 manifest imzası; dosya başına SHA-256 | `cryptography` (doğrulayıcı onsuz da saf Python Ed25519 ile çalışır) |
| Air-gap paket imzası | Ed25519 (OpenSSL) ya da cosign / minisign; SHA-256 özetler | OpenSSL ve araçlar |
| Yedekler (Compose/host) | restic deposu şifrelemesi (AES-256 + Poly1305-AES) | restic |
| Yedekler (Helm CronJob) | şifreleme yok; özet SHA-256; PVC / nesne deposu şifrelemesi kurumun | `pg_dump` |
| Taşıma | TLS (ingress'te, entegrasyon istemcilerinde ve SIEM aktarımında; TLS 1.2+, sertifika doğrulaması açık) | platform |

**FIPS 140-3 modu (W3.10).** Varsayılan kapalı. `FIPS_MODE=true` iken API, daemon
ve worker yalnızca OpenSSL 3 FIPS sağlayıcısı hem `hashlib` hem `cryptography`
için etkinse başlar; değilse 78 (`EX_CONFIG`) ile çıkar. FIPS modunda yeni parola
ve kurtarma kodu hash'leri PBKDF2-HMAC-SHA256'dır; eski bcrypt hash'i doğru parolayla
ilk girişte yeniden yazılır (`FIPS_LEGACY_BCRYPT_VERIFY=false` göç bitince bcrypt
doğrulamasını kapatır). MD5/SHA-1 yalnızca güvenlik dışı amaçla
(`usedforsecurity=False`) kullanılır. FIPS dışı ilkellerin envanteri CI'da bir
ratchet ile sayılır. JWT (HS256), Fernet ve TOTP (HMAC-SHA1) onaylı ilkellerdir ve
değişmez. Modun kendisi FIPS etkin ayrı bir imaj gerektirir. **Bilinen boşluklar:**
denetim kontrol noktası ve kanıt paketi imzaları FIPS modunda da **Ed25519 kalır**
ve FIPS onaylı sayılmaz. Veritabanı proxy'sinin `ssh_tunnel` türü algoritma seçimini
kısıtlamaz ve FIPS modunda desteklenmez. Medic'in Ed25519 güven kökü ayrı bir
imajdadır. Ayrıntı: [docs/fips.md](../fips.md).

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
- Otomatik kırmızı takım regresyon paketi (W4.3), her PR'da:
  - **Rol × rota matrisi.** `tests/security/route_role_matrix.json`, API'nin her
    rotası için her yerleşik rolün sonucunu (`allow`, `deny`, `conditional`) tutar.
    Matris rotanın kapısından ve tohum SQL'inden üretilir. `allow` ve `deny`
    hücreleri gerçek HTTP davranışına karşı sınanır. Yeni ya da değişen bir rota,
    dosya yeniden üretilip gözden geçirilene kadar testi düşürür.
  - **SSRF matrisi** (`tests/security/test_ssrf_matrix.py`): metadata adresleri,
    sayısal IPv4 yazımları, IPv4-mapped IPv6, DNS rebinding ve tehlikeli şemalar
    LLM sağlayıcı keşfine ve giden webhook'lara karşı sürülür.
  - **Injection eşiği** (`tests/security/test_injection_asr_regression.py`):
    injection setinin saldırı başarı oranı kayıtlı tabanı (21/240 = 0,0875)
    aşamaz. Oran, depodaki kayıtlı bir model yanıtları kasetinin
    (`evalkit/cassettes/stub-v1.jsonl`) yeniden oynatılmasıyla ölçülür: istem ya
    da set değişince test düşer, ama gerçek bir modelin oranını ölçmez. Bu bir
    gerileme kapısıdır; ≤ %5 hedefi değildir.
- Gecelik staging ortamı (`infra/staging/`): bir VM'de kurulduğunda `main` her gece
  k3s üzerine kurulur ve yerel modelle duman testi yapılır.
- İç kırmızı takım incelemesinin bulguları
  ([docs/security/w4.3-redteam-findings.md](../security/w4.3-redteam-findings.md))
  tehdit modelinde R26 ve R28 olarak kayıtlıdır; düzeltmeleri W0.11 ile birleşti.
- Yük ve kaos test araçları (`tests/perf/`,
  [docs/operations/load-chaos-runbook.md](../operations/load-chaos-runbook.md))
  isteğe bağlıdır; CI'da koşmaz ve bu sürüm için kapasite ölçümü yoktur.
- SBOM, imzalı imajlar ve sürüm notları (Planlı — `wp/w4.7-release`, bu sürümde yok).
- Dış pentest (Planlı — dal yok, W4.4, bu sürümde yok).
