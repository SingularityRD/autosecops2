# Düzeltme listesi — doğrulamada kalan iş paketleri

Doğrulayıcı (round 2, 12 Ekim 2026) bulguları. Her madde için önerilen düzeltme verildi. Düzeltmeyi yapan ajan:
kendi dalında çalışır (dal zaten remote'ta), önce `git merge integration` ile güncel integration'ı alır, düzeltir, bulguyu
regresyon testine çevirir, gates'i koşar, commitler, push'lar. Sonra AYRI bir doğrulayıcı `docs/wp/briefs/VERIFY_ROUND2.md`
ile yeniden doğrular. Satır numaraları yaklaşıktır (verify anındaki HEAD'e göre).

Önerilen sıra: W2.4 → (W2.5, W2.7) → geri kalanlar paralel. W3.4 önemsiz, ilk turda bitir.

---

## W2.4 executor kaydı + politika — `wp/w2.4-executors-policy` (a1febbb8) — YÜKSEK
1. `core/response/autonomous_response_service.py` `_typed`: `ttl_seconds` üst sınırı yok (1e12 → `to_approval_columns` içinde `OverflowError`, `mark_executed` öncesi). Sonuç: satır `approved` kalıyor, her döngüde yeniden execute (gateway_block için 30 sn'de bir yeni Cloudflare kuralı) ve kuyruğun kalanı çalışmıyor. Düzeltme: TTL'yi doğrula/sınırla (örn. ≤30 gün) ve sütunları execute'tan ÖNCE hesapla; per-row try/except ile satırı failed işaretle, döngü devam etsin.
2. `core/response/policy.py` `_identifiers`/`protected_reason`: yalnızca trim+lower ile birebir eşleşme. Geçenler: `dc01.corp.local`, `DC01.CORP.LOCAL.`, `dc01.`, `CORP\dc01`, başka IP + `hostname=dc01…`, `fs01.corp.local` (tag'li kısa ad), `waf_block` için `10.0.0.5/32`, `::ffff:10.0.0.5`, `10.0.0.0/8`, `0.0.0.0/0`. Düzeltme: host adını normalize et (sondaki nokta, domain\ öneki, ilk etiket = kısa ad eşleşmesi), IP'leri `ipaddress` ile kanonikleştir (IPv4-mapped), CIDR hedeflerde korunan IP/aralıkla örtüşmeyi reddet, /0 ve çok geniş aralıkları (örn. < /24 IPv4, < /64 IPv6) reddet; tüm tanımlayıcıları (target + parameters.hostname/ip/domain) kontrol et.
3. Orkestratör LLM `parameters` (mode, ip, domain) Cloudflare `_subject` içinde onaylayanın gördüğü hedefi geçersiz kılıyor. Düzeltme: parametre allowlist'i; hedefi değiştiren alanlar target ile çelişirse reddet; `mode` enum.
4. `core/response/executors/wiring.py` `EXECUTOR_SOURCES`: id'ler `microsoft-defender` ve `azure-ad` olmalı (descriptor id). Entra için `client_secret` secret store'da: wiring çözülmüş config geçmeli (Cloudflare gibi `resolve(...)`), yoksa W2.6 `build_executor` `ExecutorConfigError` verir.
5. Reverse yolu: `reverse_action` önce `executors.validate(typed)` çağırıyor; Defender gibi ad yeniden çözen yürütücülerde host yeniden adlandırılınca reverse reddediliyor. Düzeltme: `reverse_of` set ise validate hedef çözümlemesini atlasın / kayıtlı kimliği kullansın (sözleşmeyi bozmadan, wiring tarafında).
6. Düşük: `revoke_sessions` `ActionType` değil → `custom` saklanıyor ve oluşturmada four-eyes uygulanmıyor; `workflows_router.py:~555` `SecondApproverConflict` yakalanmıyor → 500 (409 olmalı).
7. Önceden var: `core/integrations/cloudflare/tool.py` `cf_*` MCP araçları `auto_responder` için öneriliyor ve `on_its_own`; politika/onay yok. W1.7 birleştikten sonra bunların gated sınıfta olduğunu doğrula; değilse sınıfla.

## W2.5 Defender — `wp/w2.5-defender-executor` (a37b812e) — YÜKSEK
1. `executor.py:~184` kısa ad `startswith(computerDnsName,'web')` + `find_machines $top=50`, `@odata.nextLink` yok sayılıyor → 2. eşleşme görülmeden tek host izole edilebiliyor. Düzeltme: sayfa doluysa veya nextLink varsa reddet (ya da tüm sayfaları gez); kısa adda `startswith` yerine tam kısa ad eşleşmesi (ilk etiket).
2. `client.py list_isolation_actions` `$top=50` sıralamasız → yanlış "zaten izole" noop. Düzeltme: `$orderby=creationDateTimeUtc desc`.
3. `executor.py:~325-344` POST zaman aşımı/5xx/beklenmeyen 400 → durum yeniden okunmadan `failed`; host izole kalabilir ve otomatik geri alınmaz. Düzeltme: belirsiz sonuçta makine aksiyonlarını yeniden oku; pending/succeeded varsa `executed` (veya `unknown`) dön.
4. `build_executor` (`~551`) `api_base`'i integration config'ten alıyor; `integrations.write` sahibi kendi host'una yönlendirip MDE bearer token alabilir. Düzeltme: `api_base`'i config'ten kaldır veya resmi MDE uç noktaları allowlist'i.
5. W2.4 #4 ve #5'e bağlı (id ve reverse validate).

## W2.7 Palo Alto — `wp/w2.7-paloalto-executor` (b1510242) — YÜKSEK
1. `executor.py:~449` `verify` `reverse_of`'u yok sayıyor → her reverse/TTL sweep `failed`, `reversed_at` hiç set edilmiyor. Düzeltme: `want_present = action.reverse_of is None` (Cloudflare yürütücüsündeki gibi) ve tip yönüne göre.
2. `~192-194, 422-425` `unblock_ip`'in reverse'ü blok kontrollerini çalıştırmadan tag'i yeniden kaydediyor (yönetim IP'si / protected_cidrs engellenebiliyor). Düzeltme: reverse'ten önce ters yön için tam validate.
3. `~422` noop blok (tag zaten vardı) reverse'ü, tag arada süresi dolduysa yeni 24 saatlik blok ekliyor. Düzeltme: noop aksiyonların reverse'ü noop olmalı (before_state'e dön, ekleme yapma).
4. Düşük: IPv6 scope id (`%…`) kabul ediliyor ve `op` cmd XML'ine kaçışsız giriyor (`~252-256`) → scope id'yi reddet, XML'i escape et. `default_ttl_seconds=True` (bool) 1 sn TTL oluyor → bool'u reddet.

## W1.9 OIDC SSO — `wp/w1.9-oidc` (98692318) — YÜKSEK
1. `core/auth/oidc_router.py:~507` `upsert_provider` `link_by_verified_email`'i yetki kontrolüne almıyor. Manager kendi IdP'sini ekleyip linking açarak Admin e-postasıyla Admin hesabına MFA'sız giriyor (`oidc_accounts.py:~246-265`). Düzeltme: linking'i açmak için tüm rollerin tüm izinleri (fiilen Admin) gereksin; ve sağlayıcının izin verilen rol eşlemelerini aşan hesaplara (özellikle Admin) linking'i, `allow_admin_mapping` açık değilse reddet; linking ile girişte yerel MFA'yı zorunlu tut ya da Admin'e linklemeyi tamamen kapat.
2. Orta `~591`: SSO-only (`!sso-only`) Admin tek break-glass hesabı seçilebiliyor → parola hash'i olmayan hesabı reddet.
3. Düşük `~490`: yerel giriş kapalıyken son etkin sağlayıcı `enabled:false` ile kapatılabiliyor (delete 409 veriyor) → aynı kontrol. `oidc_accounts.py:~192` JIT kullanıcı adı `preferred_username`'den; başka kullanıcının e-postası gibi görünen ad oluşabiliyor → e-posta biçimli adları reddet/benzersizleştir. IdP `error` parametresi log/audit'e kaçışsız → kontrol karakterlerini temizle.
4. Birleştirme: yalnızca `schema.d.ts` çakışır → birleştirmeden sonra `npm run generate:api` (clients/web).

## W1.10 Denetim zinciri — `wp/w1.10-audit-chain` (b1a1e57d) — YÜKSEK
1. `core/audit/chain.py` `_SOURCE_CHECK` (~175-215) yalnızca kaynak satırı en SON zincir satırıyla karşılaştırıyor. `session_replication_role=replica` ile yapılan değişiklik, aynı satıra sonraki normal UPDATE/DELETE ile gizleniyor ve verify OK. Düzeltme: her `update`/`delete` zincir satırı için ön-görüntüyü (`row` üzerine `old`) kur ve aynı `source_id`'nin önceki zincir satırıyla eşleştir; uyuşmazlık → `source_modified_hidden` gibi bir hata. Probe'u regresyon testine çevir.
2. Düşük: anahtar yokken verify exit 0 + "UNTRUSTED" → `--require-signature` bayrağı ekle ve dokümante et (GA'da varsayılan zorunlu olabilir). Global kilit beklemesi dokümante.

## W2.1 Verdict run — `wp/w2.1-verdict-run` (e8e92293) — YÜKSEK
1. `services/agent/workflows/hunt/verdict.ts` `lastConclude()` (~95) reddedilen CONCLUDE'u kullanıyor; bütçe sonlanınca (`controller.ts ~2005` concludeOrRefuse → budgetCheckpoint → park) benign 0.9, gap'siz hüküm yazılıyor. Düzeltme: CONCLUDE'u yalnızca hunt CONCLUDE ile sonlandıysa (outcome budget_terminated/budget_exhausted/error değilse veya controller CONCLUDE'u kabul ettiyse) kullan; aksi halde `inconclusive`, `confidence: 0` + gap. Wall-clock yolu için de test.
2. Düşük: `verdict_run.py` `{finding_id, hypothesis}` gönderiyor, spec `context` de istiyor.

## W2.2 Alert lanes — `wp/w2.2-alert-lanes` (d87beb3b) — YÜKSEK
1. `core/lanes/alert_lanes.py:~820-829` `wants_llm_triage` + `processor.py:~410`, `_AI_ANALYSIS_KEYS`'e `alert_lane` eklenmiş: bayrak KAPALIYKEN webhook payload'ındaki sahte `alert_lane` triage'ı atlatıyor ve ai_enrichment dolu olduğu için backfill de atlıyor. Düzeltme: hook'tan önce gelen `alert_lane`'i at; yalnızca bu çalıştırmanın kararına güven.
2. Orta: `tenant_of()` (~433) tenant'ı payload'dan alıyor → güvenilir kaynaktan al (yoksa `default`), payload'u yok say.
3. Orta (~455): şiddeti olmayan/bilinmeyen uyarılar medium sayılıp bastırılabiliyor → bilinmeyen şiddet bastırılmasın (triage'a gitsin).
4. Düşük: `matches()` (~304) listede herhangi bir eleman eşleşince eşleşiyor → spec'e göre daralt.

## W3.5 Saklama / KVKK — `wp/w3.5-retention` (2a098dbe) — YÜKSEK (geri dönüşsüz silme)
1. Legal hold atlatmaları: (a) `run_purge` held case listesini döngüden önce bir kez okuyor (`retention.py:~995`), `set_legal_hold` run kilidini almıyor → her sınıf için yeniden oku ve set_legal_hold aynı advisory lock'u alsın; (b) `_llm_select` (~730-740) sohbet LLM loglarını (`session_id = conversations.id`, conversation'da `case_id`) korumuyor; (c) bulgu silmek `ai_decision_logs`/`sketch_mappings`'i `ON DELETE CASCADE` ile held vakadan siliyor → held/open vakaya bağlı cascade hedefi olan bulguları atla; (d) `_chat_select`/`_llm_select` açık vaka kontrolü yapmıyor.
2. `export_agent_ledger_archive` `action='ledger_archive_export'` (21 karakter) → `config_audit_log.action VARCHAR(20)` taşması; her çağrı çöküyor. Düzeltme: ≤20 karakterlik ad (örn. `ledger_archive_exp`) ve spec'i güncelle. Test external_service işaretli olduğu için gates yakalamadı — AC komutunu ayrıca koş.
3. Küçük: `data_classes: []` "hepsi" anlamına geliyor → boş liste 400 ya da hiçbiri.
4. Birleştirme: `tests/security/test_route_permissions.py` (iki tarafı da tut), `core/compliance/__init__.py` (W3.8 ile add/add, docstring).

## W3.6 Denetim dışa aktarımı — `wp/w3.6-audit-export` (1f25dd72) — YÜKSEK
1. Redaksiyon (`core/compliance/audit_export.py:~353-449`) yalnız 5 telemetry pattern: `password=…`, ODBC `Password=…;`, PEM özel anahtar, `Authorization: Basic`, `sk-proj-`, `ghp_`, `xoxb-`, Slack webhook URL, `redis://:pw@`, `mongodb+srv://u:pw@`, `?api_key=`, AWS secret key ve `credentials/access_key/webhook_url/database_url/signing_key/pwd/pin/sig` anahtar adları geçiyor. Düzeltme: kapsamlı pattern seti + anahtar adı listesi, URL userinfo ve query parametresi maskeleme; her biri için test.
2. İmleç (~1301-1338 ve agent_events/approvals keyset'leri) `settle_s`'den uzun açık transaction'daki satırı atlıyor → kalıcı kayıp. Düzeltme: `pg_snapshot_xmin`/`xmin` tabanlı güvenli üst sınır ya da tamamlanmamış en eski xid'e kadar ilerle; docstring ve AUDIT_EXPORT.md'yi düzelt.
3. Orta (~531-534, 588): `sd_escape` CR/LF bırakıyor; login kullanıcı adı (doğrulanmamış girdi) `actor`'a gidiyor → CR/LF/U+2028/NEL kaçışla.
4. Düşük: HTTP egress kontrolü DNS rebinding'e açık (çözümlenen IP'ye pin'le), `fd00:ec2::254` ve `100.100.100.200` reddedilmiyor (W1.8'deki `core/platform/url_safety.py`'yi yeniden kullan ve CGNAT'ı orada da kapat); async handler'larda spool flock/fsync event loop'u blokluyor (`to_thread`); başarısız login'de ham kullanıcı adı (parola olabilir) → hash'le/kısalt; `Pipeline.running` `any()` → ölü sender yeniden başlatılmıyor (`all()`/sağlık kontrolü).

## W3.3 Air-gap paketi — `wp/w3.3-airgap` (a5c26cc9) — ORTA-YÜKSEK
1. `infra/airgap/install.sh` doğrulama ile kullanım arasında TOCTOU (doğrula ~98-130, kullan ~210-259). Düzeltme: paketi önce `mktemp -d` (0700) özel dizine kopyala, kopyada doğrula ve yalnızca kopyadan kur.
2. Düşük: listelenmemiş FIFO/boş dizin kabul (`~138` yalnız `-type f -o -type l`) → tüm tipleri say ve reddet; `build-bundle.sh:~208` kural tar'larında symlink korunuyor → `--dereference` ya da symlink'leri reddet; README:~118 dış tar'ı boş dizine açmayı/önce listelemeyi önersin; `values-airgap.yaml:10` "Vigil" → AutoSecOps.

## W1.2 Triage JSON + provenance — `wp/w1.2-triage-provenance` (e969453b) — YÜKSEK
Tam düzeltme brief'i: `docs/wp/briefs/1.2_fix.txt`.

## W1.5 Canary — `wp/w1.5-canary` (7af15f83) — YÜKSEK
1. AC6 başarısız: `core/storage/canary_exclusion.py:~710-723` tablo yokken sonucu önbelleğe almıyor → metrik çağrısı başına ekstra `to_regclass` (test_query_count_does_not_grow_with_cases 5 parametre). Düzeltme: yokluk sonucunu da önbelleğe al (TTL'li).
2. Orta: 216 kaydın hepsi RFC 5737 TEST-NET IP'leri ve 3 anahtarlı `raw_event` kullanıyor → gerçekçi (ama yönlendirilemeyen/sahte olduğu bilinen) adresler ve vendor metadata ile çeşitlendir; `build_canary_finding` (`canary.py:~188-207`).
3. Orta: `POST /api/findings/{id}/intake` (`services/api/routers/findings.py:~181`) canary'de `withhold_response` kontrolü yapmıyor → ekle.
4. Düşük: threat-intel/sandbox (`processor.py:~840-871`) hook'tan önce canary IOC'lerini dışarı gönderiyor → hook'u öne al; IOC filtresi yalnız entity_context (`~850`) → metin içi IP'leri de yakala; `canary.py:~336` log satırı enjeksiyon anını ele veriyor → kaldır/debug.
5. Birleştirme: `core/quality/__init__.py` add/add (docstring) → W1.6'nınkini tut. Birleşince W1.6 `core/quality/sampling.py:~204` `AIDecisionLog` okumasına canary filtresi ekle.

## W3.4 Sıfır egress — `wp/w3.4-egress-zero` (118d174b) — önemsiz
1. `.github/workflows/airgap.yml:14` yorumundaki "secrets" kelimesi AC5 `grep -c secrets` = 0 beklentisini bozuyor → yorumu yeniden yaz.
2. Düşük (isteğe bağlı): `tests/airgap/egress_scan.py` PY_RULES'a `asyncio.open_connection`, `loop.create_connection`, ftplib, xmlrpc, grpc, websocket, slack_sdk, litellm, google-genai ekle; `scripts/`'i PY_ROOTS'a ekle; guard'da `sendmsg`'i sar, `*.localhost`'u gerçek resolver'a gönderme; workflow'da `persist-credentials: false`.

## Birleşmiş ama takip gerektiren (PASS, engelleyici değil)
- W1.8: `core/platform/url_safety.py:~76-97` CGNAT 100.64.0.0/10 izinli → `not ip.is_global` ile engelle. `docs/outbound-webhooks.md` de-dup'ı imzalı gövde `id`'sine göre önersin. `record_attempt` geç sonuç sıralaması; SLA de-dup için unique constraint.
- W2.6: id-only rol stub'ını reddet (`executor.py:~253-261`).
- W3.8: zincir başı çapası (son olay silinmesi tespit edilmiyor); anların sıra kontrolü; `dora.initial` başlamamışken `met` göstermesin; taslak metnindeki `[evidence:N]` referanslarını da doğrula.
- W1.7: onayı argümanlara bağla; isim sezgiselinde yalnız ilk token fiili say; `_names_tool` argüman içi isimleri eşleştirmesin.
- W1.6: `seed`'i test dışı yok say; Disagree diyalog metni.
- W2.8: 502 nesne `detail`'i göster ve `onReverted` çağır.
- W0.9: `services/api/routers/storage_status.py:255,316` "Vigil" metinleri.
