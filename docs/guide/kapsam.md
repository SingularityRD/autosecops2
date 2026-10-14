# Sürüm kapsamı: bu sürümde ne var, ne yok

> **English summary.** What `main` @ `7a22e8b6` contains and what it does not.
> Merged: the measurement core, structured JSON triage with code-assigned field
> provenance and `prompt_version` on the live path, tool-effect gating (models
> can no longer approve or reject a pending action; an approval is bound to the
> tool call's arguments), outbound webhooks, canaries and QA scorecard, alert
> lanes and a local model lane behind flags, the executor registry with response
> policy (protected assets, hourly limits, TTL expiry and revert, four-eyes
> approval for identity actions) driving the Cloudflare, Defender, Entra ID and
> PAN-OS executors, per-category autonomy tiers with a circuit breaker (default
> Approve), an optional distinct-role rule for the second approver and a
> segregation-of-duties report, the tamper-evident audit chain for approvals and
> case audit records with signed checkpoints, signed per-case evidence packs,
> lessons (store, replay-gated promotion and API; not yet applied to live
> triage), a durable webhook ingest spool, the automated red-team regression
> suite, the security hotfix for detection-rule sources and viewer write routes,
> verdict runs behind a flag, retention / KVKK purge with legal hold, daemon hot
> standby and a Helm backup CronJob, load/chaos tooling, the 0.7 → 2.0 upgrade
> script, a nightly staging environment, action timeline, DORA/NIS2 clocks,
> air-gap bundle and zero-egress proof. Not merged: OIDC SSO, SIEM audit export,
> FIPS mode, the injection-set gate, SBOM / signed images and an external
> pentest. Those are marked **Planlı** everywhere in this guide.

Bu sayfa, belge setinin geri kalanının dayandığı tek kapsam listesidir. Bir özellik
burada "var" değilse, belgelerin hiçbirinde "var" diye anlatılmaz.

## Bu sürümde olanlar (main @ 7a22e8b6)

| İş paketi | Özellik | Varsayılan | Nerede |
|---|---|---|---|
| W0.2 | Kullanıcıya görünen her yerde AutoSecOps markası | — | konsol, e-posta, OpenAPI |
| W0.3 | Tam CI; her PR'da backend, web, agent, Helm, güvenlik işleri | — | `.github/workflows/ci-cd.yml` |
| W0.5 | Donmuş sözleşmeler: karar (verdict) şeması, `Executor` protokolü, 46–49 numaralı init SQL dosyalarındaki tablo iskeletleri | — | `core/contracts/verdict.schema.json`, `core/response/executors/base.py` |
| W0.6 | Gece kurulan staging ortamı (k3s, yerel model, duman testi) | operatör VM'de kurar | `infra/staging/` |
| W0.7, W1.1 | Etiketli eval korpusu ve çevrimdışı değerlendirme düzeneği | — | `eval/corpus/v1`, `evalkit` |
| W0.12 | Kalıcı webhook alım kuyruğu (200 yalnızca bulgu diskteyken; doluysa 503), açılışta yeniden oynatma, LLM worker'ın Redis kaybında yeniden bağlanması | açık (`DAEMON_INGEST_SPOOL_ENABLED=true`) | `core/ingestion/spool.py`, `docs/operations/ingest-durability.md` |
| W0.13 | Commit geçmişi incelemesi düzeltmesi: gönderenin yükteki analiz alanları (`triage_confidence`, `recommended_action`, `enrichment` vb.) işlemeden önce atılır | her zaman açık | `services/daemon/processor.py` |
| W0.10 | Birleşmiş paketlerin takip düzeltmeleri (düzenleyici zincir başı çapası ve an sırası, webhook teslim yarışı, Entra rol denetimi, araç adı sezgiseli, QA `seed`) | — | bkz. [tehdit modeli](tehdit-modeli.md#açık-riskler) |
| W1.2, W1.3 | JSON şemalı triage; alan kökeni (provenance) kodla atanır; kararda model ve `prompt_version` | her zaman açık | `services/daemon/processor.py`, `core/federation/provenance.py` |
| W1.5 | Gizli kanarya alarmları (yakalama oranı ölçümü) | **kapalı**; yalnızca Admin açar | `core/quality/canary.py` |
| W1.6 | QA örnekleme, inceleme kuyruğu, Karne (Scorecard) ekranı | açık (örnekleme elle tetiklenir) | `core/quality/sampling.py` |
| W1.7 | Araç etki sınıfları; yazan/yıkıcı araç yalnızca onay hattından | her zaman açık | `core/llm/tool_effects.py` |
| W1.8 | HMAC imzalı giden webhook'lar, vaka bildirim dağıtıcısı, SLA izleyicisi | uç nokta tanımlanana kadar hiçbir şey gönderilmez | `core/integrations/outbound_webhooks.py` |
| W2.1 | Verdict run: tek alarm için sıfır hipotezli, eleştirmenli kısa soruşturma | **kapalı** (`VERDICT_RUN_ENABLED=false`; daemon henüz çağırmaz) | `core/workflows/verdict_run.py` |
| W2.2 | Üç şeritli alarm yönlendirici (kural / küçük model / verdict) | **kapalı** (`ALERT_LANES_ENABLED=false`) | `core/lanes/alert_lanes.py` |
| W2.4 | Yürütücü kayıt defteri ve müdahale politikası: korunan varlıklar, saatlik etki sınırı, süre dolunca geri alma, elle geri alma, kimlik eylemlerinde dört göz onayı | her zaman açık | `core/response/policy.py`, `core/response/executors/wiring.py` |
| W2.5 | Microsoft Defender for Endpoint izolasyon yürütücüsü | entegrasyon etkinse kayda alınır | `core/integrations/microsoft_defender/executor.py` |
| W2.6 | Entra ID kullanıcı devre dışı bırakma / oturum iptali yürütücüsü | entegrasyon etkinse kayda alınır | `core/integrations/azure_ad/executor.py` |
| W2.7 | Palo Alto PAN-OS süreli IP engeli yürütücüsü | entegrasyon etkinse kayda alınır | `core/integrations/palo_alto/executor.py` |
| W2.8 | Vaka sayfasında eylem zaman çizelgesi (Actions sekmesi) ve Revert düğmesi | açık | `core/response/action_timeline.py` |
| W3.1 | Otonomi katmanları (alarm kategorisi × eylem sınıfı: Watch, Suggest, Approve, Autonomous), QA sınırına bağlı devre kesici, yalnızca kişinin kanıtla yükseltmesi | varsayılan katman **Approve** (yüksek güven tek başına eylemi serbest bırakmaz) | `core/autonomy/`, Ayarlar → Limits & autonomy |
| W3.2 | İkinci onaylayanın farklı rolde olması (sınıf başına), karar başına rol kaydı (`approval_decisions`), görevler ayrılığı raporu ve dışa aktarımı | farklı rol koşulu **kapalı** (hiçbir sınıf) | `core/response/segregation.py`, Ayarlar → System → Segregation of duties |
| W3.3 | İmzalı internetsiz kurulum paketi | — | `infra/airgap/` |
| W3.4 | Sıfır egress profili ve kanıtı (statik envanter + çalışma zamanı testi) | profil uygulanınca | `infra/airgap/airgap.env`, `tests/airgap/` |
| W3.5 | Veri sınıfı başına saklama, KVKK periyodik imha, yasal saklama, imha tutanağı | zamanlayıcı **kapalı**; açılınca kuru çalıştırma | `core/compliance/retention.py` |
| W3.8 | DORA / NIS2 bildirim sayaçları ve rapor taslakları | açık | `core/compliance/` |
| W4.3 | Otomatik kırmızı takım regresyon paketi: her rota × her rol yetki matrisi, SSRF matrisi, injection başarı oranının kayıtlı tabanı aşmaması; bulgu raporu | CI'da her PR | `tests/security/`, `docs/security/w4.3-redteam-findings.md` |
| W3.9 | Daemon sıcak yedeği (lider seçimi, çitleme), Helm yedek CronJob'u, RPO/RTO belgesi | Helm'de lider seçimi açık, CronJob **kapalı** | `core/coordination/leader.py`, `docs/operations/rpo-rto.md` |
| W0.11 | Güvenlik acil düzeltmesi: kural kaynağı uçları `settings.write` ister, git kaynağı yalnızca `https://` ve dış (ya da izinli iç) adres, sertleştirilmiş git çağrısı; düzenleyici an tabloları `TRUNCATE`'i reddeder; Viewer'a açık yazma uçlarının çoğu izinle kapılandı | her zaman açık | `core/detections/detection_rules_service.py`, `tests/security/auth_only_write_routes.txt` |
| W0.13 | Veri/altyapı incelemesi: Helm db-init Job'u hatalı SQL dosyasını uygulanmış saymaz, uygulama tablolarını bekler ve eski kurulumlardaki eksik düzenleyici tabloları kendiliğinden onarır | Helm'de açık | `infra/helm/vigil/templates/db-init-job.yaml` |
| W0.13 | Müdahale incelemesi: onaylı eylemlerin dağıtımı en eskiden başlar ve çalışamayacak satırları atlar; geri alma tipleri (`unblock_ip`, `unisolate_host`, `enable_user`) kayıtta; yarım kalan geri alma talebi 1 saat sonra devralınır | her zaman açık | `core/response/approval_service.py`, `core/response/autonomous_response_service.py` |
| W1.7b | Hiçbir model yüzeyi (sohbet, iş akışları, `/mcp`, `/internal/tools/invoke`) bir onayı veremez ya da reddedemez; onay, kişiye gösterilen araç argümanlarının özetine (`args_sha256`) bağlıdır | her zaman açık | `core/llm/tool_effects.py`, `core/response/checkpoints.py` |
| W1.10 | `approval_actions` ve `case_audit_logs` için tetikleyiciyle doldurulan, yalnızca eklenen tek hash zinciri (`audit_chain`); ajan defteri ve bu zincirin başları için Ed25519 imzalı kontrol noktaları; `python -m core.audit.verify` | zincir her zaman açık; kontrol noktası işi saatlik ama imza anahtarı verilmeden **atlanır** | `core/audit/`, `infra/database/init/51_audit_chain.sql` |
| W2.3 | Yerel model şeridi: küçük model şeridindeki triage, Bifrost üzerinden yerel Ollama modeline JSON şemasıyla kısıtlı gider; model eval ile seçilir | **kapalı** (seçim dosyası ya da `LOCAL_LANE_MODEL` yoksa); yalnızca alarm şeritleri açıkken | `core/llm/local_lane.py` |
| W3.7 | Vaka başına imzalı kanıt paketi (ZIP, Ed25519 imzalı manifest) ve çevrimdışı doğrulayıcı | açık (`cases.read`) | `core/compliance/evidence_bundle.py`, `scripts/autosecops` |
| W3.11 | Dersler: analist düzeltmesinden kapsamlı ve süreli ders, geçmiş alarmlarda replay ile terfi, geri alma, olay kaydı; Karne → Lessons sekmesi | açık; **canlı triage dersleri henüz uygulamaz** | `core/lessons/`, `services/api/routers/lessons.py` |
| W4.1 | Yük ve kaos test araçları (sürekli/ani yük, şerit başına gecikme raporu; model, Postgres, Redis, daemon ve yavaş satıcı arızaları) | isteğe bağlı, CI'da koşmaz | `tests/perf/`, `docs/operations/load-chaos-runbook.md` |
| W4.5 | Vigil 0.7.x → AutoSecOps 2.0 veritabanı yükseltme betiği (ön kontrol, deneme, yedek, şema karşılaştırması) ve CI'da 0.7.1 dökümünden yükseltme testi | elle çalıştırılır | `scripts/upgrade_database.py`, `docs/upgrade-0.7-to-2.0.md` |

Bu belgelerin dayandığı ve 0.7.1'den gelen temel özellikler de bu sürümdedir:

- rol tabanlı yetki (beş sistem rolü), yerel hesap + TOTP MFA, hesap kilitleme,
  parola politikası, Redis tabanlı oturum iptali;
- onay kuyruğu (`approval_actions`);
- ajan defterinde (`agent_events`) koşu başına SHA-256 hash zinciri, ayar değişikliği
  denetim kaydı (`config_audit_log`), vaka denetim kaydı (`case_audit_logs`; W1.10
  ile zincirli);
- Fernet ile şifreli sır deposu;
- restic ile şifreli ve doğrulanan yedek/geri yükleme (`python -m core.backup`);
- Helm grafiği (NetworkPolicy, ExternalSecrets desteği) ve Docker Compose kurulumu.

### Yürütücüler nasıl bağlanır?

API ve daemon açılışta bir kez yürütücü kayıt defteri kurar. Cloudflare yürütücüsü
her zaman kayıttadır. Defender, Entra ID ve PAN-OS yürütücüleri, ilgili entegrasyon
etkinse kayda alınır. Entegrasyonu açtıktan ya da kapattıktan sonra API ve daemon
yeniden başlatılmalıdır. Onaylanan (ya da Autonomous katmanının serbest bıraktığı)
her eylem önce müdahale politikasından, sonra kayıt defterindeki yürütücüden geçer. `isolate_host` için Defender kayıtlı değilse
eylem "No EDR executor is configured" ile `failed` kaydedilir; hiçbir eylem başarılı
gibi gösterilmez (bkz. [yönetici kılavuzu](yonetici-kilavuzu.md#müdahale-politikası-ve-onaylar)).

**Önemli istisna.** Ajan iş akışlarının kullandığı onay gerektiren MCP araçları
(`mde_isolate`, `aad_disable_user`, `pan_block_ip`, `cb_quarantine`, `cf_waf_block_ip`
gibi) bu yoldan geçmez. Bir kişi iş akışının onay noktasını onaylayınca araç,
`/internal/tools/invoke` üzerinden doğrudan çalışır. Onay, kişiye gösterilen
argümanlara bağlıdır (W1.7b): başka bir hedefle tekrar oynatılamaz. Ama müdahale
politikası, korunan varlık listesi, saatlik sınır, süre dolumu, otonomi katmanı ve
dört göz onayı burada uygulanmaz.
Bu açık risk [tehdit modelinde R2](tehdit-modeli.md#açık-riskler) olarak kayıtlıdır.

## Bu sürümde olmayanlar (Planlı)

Aşağıdaki iş paketleri kodlanmıştır ya da kodlanmaktadır, ancak bağımsız
doğrulamadan geçip `main`'e birleşmemiştir. Bu sürüme dahil değildirler.
Birleşmiş dalların tam listesi `tests/unit/docs/merged_wps.txt` dosyasındadır;
belge testi bu listedeki bir dalı "Planlı" diye anan satırı reddeder.

| İş paketi | Özellik | Durum |
|---|---|---|
| W1.4 | Injection test setinin kapı olarak kullanılması (≤ %5) | Planlı — `wp/w1.4-injection-set`, bu sürümde yok |
| W1.9 | OIDC SSO (Entra ID, Okta, Keycloak), grup → rol eşlemesi | Planlı — `wp/w1.9-oidc`, bu sürümde yok |
| W3.6 | Denetim akışının syslog/HTTPS ile SIEM'e aktarımı; `url_safety`'nin CGNAT aralığını reddetmesi | Planlı — `wp/w3.6-audit-export`, bu sürümde yok |
| W3.10 | FIPS modu | Planlı — `wp/w3.10-fips`, bu sürümde yok |
| W4.4 | Dış pentest | Planlı — dal yok, bu sürümde yok |
| W4.7 | SBOM, imzalı imajlar, sürüm notları | Planlı — `wp/w4.7-release`, bu sürümde yok |

Canlı triage'ın etkin dersleri karar ipucu olarak kullanması ayrı bir iş
paketidir; dalı yoktur (Planlı — dal yok, bu sürümde yok).

W0.5 iskeletindeki tabloların durumu: `lessons` tablosunu ders deposu
(`core/lessons/store.py`) ve `/api/lessons` uçları okur ve yazar; daemon'un canlı
triage yolu dersleri okumaz. `autonomy_tiers` otonomi denetleyicisi (W3.1),
`retention_policies` imha işi (W3.5) tarafından okunur.
`suppression_rules` yalnızca alarm şeritleri açıkken okunur.

## Bilinen açıklar

Birleşmiş paketlerin doğrulamada "engelleyici değil" diye kaydedilen takip
maddeleri, incelemelerde bulunan açıklar ve birleşmemiş paketlerin yokluğundan
doğan riskler [tehdit modelinin açık riskler bölümünde](tehdit-modeli.md#açık-riskler)
tek tek listelenmiştir. En önemlisi R2'dir: onaylanmış MCP araçları müdahale
politikasından geçmez. Önceki sürümün iki yüksek riski bu sürümde kapandı: kural
kaynağı ucundaki SSRF ve git argüman enjeksiyonu (R26, W0.11) ve sohbetten onay
(R30, W1.7b).
