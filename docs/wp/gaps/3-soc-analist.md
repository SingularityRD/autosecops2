# 3 — SOC analisti (L1 triyaj, L2/L3 soruşturmacı, olay müdahalecisi, tehdit avcısı) eksik analizi

Kod tabanı: `/root/wt/gap` @ `87b1438e` (salt-okunur). Tüm kanıtlar bu ağaca göredir. Uygulama başlatılmadı; yalnızca grep/okuma.

Zaten bilinen ve listelenmiş (tekrar keşfedilmedi, yalnızca sayılıyor): rc.1 etiketi/imajlar, Kapı C (temiz VM < 30 dk) yapılmadı, dış pentest, W1.4 kararı, yüksek riskli WP ürün onayları, tag ruleset'leri, katalog yer tutucuları, otomatik kapatma ve çok kiracılık Kasım'a ertelendi. Ayrıca bilinen: logo işareti hâlâ Vigil'in devre-kalkan çizimi (NORTHSTAR "Fork stratejisi"), R2 (onaylı MCP araçları politikasız çalışıyor, `docs/guide/tehdit-modeli.md:169`).

---

## A. Personalar ve vardiya boyu user story'ler (adım adım, kod karşılığıyla)

Roller (seed): Viewer, Analyst, Senior Analyst, Manager, Admin (`infra/database/init/06_auth_tables.sql:60-140`). L1 = Analyst (onay yok, `ai_decisions.approve:false`), L2/L3 = Senior Analyst (onay var), vardiya amiri = Manager.

### A1. L1 triyaj analisti — 8 saatlik vardiya
| # | Adım | Kodda karşılığı | Durum |
|---|---|---|---|
| 1 | SSO ile girer | `core/auth/oidc_router.py` (W1.9) | Var |
| 2 | Önceki vardiyanın devir notunu okur | aranan: `handover\|shift` (clients/web/src, core, services) → bulunamadı | **YOK** |
| 3 | Home "Needs you" / Triage kuyruğunu açar | `screens/home/HomeScreen.tsx`, `screens/triage/TriageScreen.tsx` | Var, kısıtlı |
| 4 | Kuyruğu önem/SLA'ya göre sıralar, kendine alır (claim) | `TriageScreen.tsx:291` "no column carries a sortVal: rows stay in the server's order"; claim/assign yok | **YOK** |
| 5 | AI kararını, alıntılanan kanıt alanlarını ve güveni görür | Daemon kaydediyor (`services/daemon/processor.py:1817-1823` `ai_triage.verdict`), ama UI'da render edilmiyor: aranan `ai_triage\|triage_reasoning` (clients/web/src) → bulunamadı. Kuyrukta Score her zaman "—" (`TriageScreen.tsx:303`), Trust/Weight "Not measured" (`:237-239`) | **YOK** |
| 6 | Toplu seçim, toplu kapatma/atama | Triage'da yok; Cases'te checkbox `disabled` "Coming in a later release" (`screens/cases/CasesScreen.tsx:363-364`) | **YOK** |
| 7 | Bulguyu "gürültü" işaretler / IP hariç tutar | `OverviewScreen.tsx:221-236` → `services/api/routers/findings.py:147-187`; `FindingPopup.tsx:279` exclusions | Var |
| 8 | Bulguyu mevcut vakaya ekler | Vaka oluşturma `finding_ids: []` sabit (`CasesScreen.tsx:650-656`, `CommandBar.tsx:371`); FindingPopup'ta "Add to case" yok | **YOK** |
| 9 | AI'ya katılıyor/katılmıyor geri bildirimi verir | Vaka sayfasında Agree/Disagree `disabled` (`CasePage.tsx:960-962`); AI Decisions ekranında feedback var ama L1 o ekranı göremez (`shell/SocConsole.tsx:80` `ai_decisions.approve`) | Kısmi |
| 10 | L2'ye eskale eder | API var (`services/api/routers/cases.py:661-674`), UI çağırmıyor: `casesApi.escalate` çağıran yok (grep) | **YOK (UI)** |
| 11 | Klavye kısayolu ile hızlı ilerler | Yalnızca Ctrl/Cmd+K komut çubuğu (`shell/CommandBar.tsx:159`) ve Esc | Kısmi |
| 12 | Vardiya sonu devir notu yazar | bulunamadı | **YOK** |

### A2. L2/L3 soruşturmacı
| # | Adım | Kodda karşılığı | Durum |
|---|---|---|---|
| 1 | Vakayı açar: özet, açıklamalar, kanıt, kontrol edilenler, hafıza/kör noktalar, eylemler, kayıt | `CasePage.tsx:52` TABS | Var |
| 2 | Varlıkları (kullanıcı/host/IP) ve zaman çizelgesini görür | IOCs kartı (`CaseSections.tsx:427`), Dashboard Timeline sekmesi; ayrı varlık görünümü/grafiği yok | Kısmi |
| 3 | Tehdit istihbaratı zenginleştirmesi (VT, Shodan) | `processor.py:1829-1990` doğrudan `api.shodan.io` / VT çağrısı; air-gap'te kapalı kalır; MISP UI'dan gizli (`integrationsData.ts:18-23` WIP) | Kısmi |
| 4 | Hunt / kök neden koşusu başlatır, AI ile sohbet eder | `screens/workflows/*`, `shell/Chat.tsx`, `services/agent/arch/verdict.yaml` | Var (Chat'te "Tell"/"Do" `disabled`, `Chat.tsx:1242-1243`) |
| 5 | Kanıt dosyası yükler | Evidence kartı yalnızca ad + "file path" metni alır, dosya yüklemez (`CaseSections.tsx:129-150`); `attachDocument` yalnızca komut çubuğundaki hunt belgesi için (`CommandBar.tsx:399`) | **YOK (gerçek yükleme)** |
| 6 | Not/yorum yazar, @mention yapar | Yorum var, ama yazar istemci tarafında sabit `'SOC Analyst'` (`CaseSections.tsx:14,374`) ve sunucu bunu doğrulamıyor (`cases.py:387-411`); @mention ayrıştırılıyor (`core/cases/case_collaboration_service.py:51-74`) ama yazar adı sahte olduğu için bildirim yanlış | **HATALI** |
| 7 | İlgili vakaları bağlar | API var (`cases.py:640-675` relationships), UI'da yok (`casesApi` içinde relationships yok, `services/api.ts:329-412`); yalnızca merge var (`CasesScreen.tsx:887`) | Kısmi |
| 8 | MITRE eşlemesi | `FindingPopup.tsx:113,385`, Dashboard ATT&CK sekmesi | Var |
| 9 | Eylem önerir (ör. "bu hostu izole et") | İnsan için öneri endpoint'i yok: `core/api/v1/approvals_router.py:159-278` yalnızca GET/approve/reject; öneri yalnızca ajan aracı `create_approval_action` ile (`core/agents/builtins.py:133`) — analist sohbetten istemek zorunda | **YOK (doğrudan)** |

### A3. Olay müdahalecisi (Senior Analyst)
| # | Adım | Kodda karşılığı | Durum |
|---|---|---|---|
| 1 | Bekleyen onayı görür (masaüstü bildirimi dahil) | `shell/useDesktopNotifications.ts`, `DecisionsScreen.tsx` approvals sekmesi, `CasePage.tsx:205-230` | Var |
| 2 | Dört göz: ilk onaydan sonra "ikinci, farklı kişi bekleniyor" durumunu görür | Tabloda ilk onaylayan / kalan onay sayısı gösterilmiyor (`DecisionsScreen.tsx:308-340`); aynı kişi ikinci kez basınca 409 banner'ı | Kısmi |
| 3 | Defender/Entra/PAN-OS üzerinden uygular, doğrular | `core/response/executors/wiring.py:46-53`; executor'lar gerçek | Var (ama UI'dan kurulamıyor, bkz. SA-01) |
| 4 | Eylem zaman çizelgesi ve gerekçeli geri alma | `CaseActions.tsx:106-177` (`getActionTimeline`, `revert`) | Var |
| 5 | Executor'u olmayan ürün için (Fortinet, Check Point, CrowdStrike, AD) elle eylem kontrol listesi | Yalnızca serbest görev (Tasks) (`CaseSections.tsx:196-260`); eylem tipine bağlı runbook şablonu yok | **YOK** |
| 6 | Etkilenen iş birimine bildirim | aranan `business.?unit\|stakeholder\|iş birimi` → bulunamadı | **YOK** |

### A4. Vardiya amiri / tehdit avcısı
| # | Adım | Kodda karşılığı | Durum |
|---|---|---|---|
| 1 | SLA ihlali yaklaşan vakaları görür | `CasesScreen.tsx:307` "Near SLA"; SLA politikaları (`SlaPoliciesSection.tsx`) | Var |
| 2 | Teams/SMS/PagerDuty ile nöbetçiyi arar | Dağıtıcı yalnızca e-posta, Slack, giden webhook (`core/cases/notification_dispatcher.py:1-20,50`) | Kısmi |
| 3 | Kaydedilmiş görünüm ile vardiya panosu | aranan `saved.?view\|savedSearch` → bulunamadı | **YOK** |
| 4 | Vakayı yönetime/regülatöre PDF/Word olarak verir | PDF route var ama sunucuda `TestOutputs/`a yazar, indirme yok, UI çağırmıyor (`cases.py:211-266`); kanıt paketi yalnızca JSON+imza ZIP (`core/compliance/evidence_bundle.py:227-254`) | **YOK (insan okunur rapor)** |
| 5 | Kapanış: kategori + gerekçe + olay sonrası inceleme | Kapatma yalnızca liste "Edit case" diyaloğunda, kategori + tek gerekçe (`CasesScreen.tsx:768-775`); API'nin `root_cause`, `lessons_learned`, `recommendations`, `executive_summary` alanları (`core/api/v1/cases_router.py:224-239`) UI'da toplanmıyor | Kısmi |
| 6 | Analist düzeltmesinden ders üretir | `POST /api/lessons` var (`services/api/routers/lessons.py:226`), UI yalnızca listeler/terfi/geri alır (`services/lessonsApi.ts:8-16`); öneri butonu yok | **YOK (UI)** |
| 7 | Yeniden açma | `CasePage.tsx:837,964` | Var |

---

## B. Entegrasyon/konnektör matrisi (gerçek mi, stub mu)

Kaynak: `core/integrations/*`, `mcp-config.json`, `core/federation/registry.py:39-45`, `core/response/executors/wiring.py:46-53`, `clients/web/src/screens/settings/integrationsData.ts:18-23` (WIP = "Add integration" kataloğundan gizli).

| Ürün | Alarm alımı (federation/webhook) | Sorgu/zenginleştirme (MCP) | Yanıt executor'u | UI'dan kurulabilir mi | Değerlendirme |
|---|---|---|---|---|---|
| Splunk | Var (`splunk/adapter.py` 268 satır, REST) | Var (self-hosted + resmi uzak MCP) | — | Evet | Çalışıyor görünüyor |
| QRadar | **Yok** | **Yok** | — | — | aranan `qradar` → bulunamadı |
| Microsoft Sentinel | Kod var (`azure_sentinel/ingestion.py`) ama `azure-identity`/`azure-mgmt-securityinsight` requirements.txt/lock'ta yok → çalışma anında "Azure SDK not installed" (`:65-66,191-194`) | Uzak Microsoft MCP (internet, air-gap'te yok) | — | Evet | **Kırık (bağımlılık)** |
| Elastic | Var (`elastic/adapter.py`, httpx) | Var | — | Evet | Çalışıyor görünüyor |
| OpenSearch | Var | Var | — | Evet | Çalışıyor görünüyor |
| ArcSight | **Yok** | **Yok** | — | — | bulunamadı |
| Wazuh | **Yok** | **Yok** | — | — | bulunamadı |
| Logsign (yerli SIEM) | **Yok** | **Yok** | — | — | bulunamadı |
| Defender for Endpoint | Var (`microsoft_defender/ingestion.py`, legacy `/api/alerts`) | Var (yerel tool) | `isolate_host`/`unisolate_host` | **Hayır — WIP listesinde gizli** | Kod gerçek, kurulum yolu kapalı |
| CrowdStrike | Var (`crowdstrike/adapter.py`) | falcon-mcp (uvx) | **Yok** | Evet | Alım var, containment yok |
| SentinelOne | **Yok** | purple-mcp (yalnızca descriptor, 20 satır) | Yok | Evet | Yalnızca MCP |
| Carbon Black | Yok | Yerel tool (WIP, gizli); `cb_quarantine` politikasız (R2) | Yok | Hayır | Stub/WIP |
| Trend Micro, Kaspersky, ESET | **Yok** | **Yok** | Yok | — | bulunamadı |
| Palo Alto | Yok (log alımı yok) | Yerel tool (WIP) | `block_ip`/`unblock_ip` (DAG etiketi) | **Hayır — WIP** | Executor gerçek, kurulum yolu kapalı |
| Fortinet/FortiGate | **Yok** | **Yok** | **Yok** | — | bulunamadı |
| Check Point | **Yok** | **Yok** | **Yok** | — | bulunamadı |
| Cloudflare | Webhook (`cloudflare_webhooks_router.py`) | Var | `waf_block`, `gateway_block`, `access_revoke` (her zaman kayıtlı) | Evet | Çalışıyor görünüyor (TR bankasında nadir) |
| Darktrace | Webhook (`darktrace_webhook_router.py:234-266`) | — | — | Descriptor yok | Yalnızca webhook |
| AWS Security Hub | Var | aws-security MCP | — | Evet | Çalışıyor görünüyor |
| E-posta güvenliği (Proofpoint, Mimecast, Trend ETP) | **Yok** (Proofpoint yalnızca kanarya/korpusta, `core/quality/canary.py:398`) | Yok | Yok (mail geri çekme yok) | — | bulunamadı |
| Entra ID | Yok (alım) | Yerel tool (WIP) | `disable_user`, `enable_user`, `revoke_sessions` (dört göz) | **Hayır — WIP** | Executor gerçek, kurulum yolu kapalı |
| On-prem Active Directory | **Yok** | **Yok** | **Yok** | — | aranan `ldap\|active directory` (core/integrations) → bulunamadı |
| Okta | — | docker MCP | — | — | Yalnızca MCP |
| ServiceNow | **Yok** | **Yok** | — | Buton `disabled` "Coming in a later release" (`OverviewScreen.tsx:367-369`) | Yok |
| Jira | — | Atlassian uzak MCP (internet) | Tek yönlü issue oluşturma (`services/api/routers/jira_export.py:70-195`, REST v2), geri senkron yok | Evet | Kısmi |
| VirusTotal / Shodan | Daemon doğrudan HTTP (`processor.py:1944-1990`) + npx MCP (`descriptor.py` 17 satır) | — | — | Evet | İnternet gerekir; air-gap'te devre dışı |
| MISP / TAXII | TAXII çekme (`core/threat_intel/threat_feed_service.py:265`) | MISP tool WIP (gizli) | — | MISP hayır | Air-gap için tek yerel istihbarat yolu gizli |
| USOM/TR-CERT zararlı bağlantı listesi | **Yok** | — | — | — | bulunamadı |
| Slack | Dağıtıcı (`notification_dispatcher.py:50`, `slack.com` – internet) | Tool WIP | — | Hayır (WIP) | Kısmi |
| Microsoft Teams | **Dağıtıcıda yok**; yalnızca ajan aracı, legacy MessageCard incoming webhook (`microsoft_teams/tool.py:55-80`) | — | — | Hayır (WIP) | Stub |
| PagerDuty | Yok (dağıtıcı) | `pagerduty-mcp` uvx `--enable-write-tools` | — | Evet | Yalnızca MCP |
| SMS (Netgsm, Twilio vb.) | **Yok** | — | — | — | bulunamadı |
| E-posta (SMTP) | Var (`core/platform/email_service.py`, varsayılan `console`) | — | — | env | Çalışıyor görünüyor |
| Giden webhook (W1.8) | Var (HMAC, yeniden deneme; `core/integrations/webhooks_router.py`, `docs/outbound-webhooks.md`) | — | — | API | Çalışıyor görünüyor |

Genel alım:
- Webhook: Var. Daemon `/ingest`, `/webhook`, bearer token, fail-closed (`services/daemon/poller.py:235-326`). Ama yalnızca AutoSecOps'un kendi bulgu JSON'unu kabul ediyor, eşleme/normalizasyon yok. Hata gövdesinde `str(e)` dönüyor (`:318`).
- Kafka: Var, yalnızca JSON. Avro, Schema Registry ve DLQ yok (`core/ingestion/kafka_consumer_service.py:1-13`). Mesaj AutoSecOps bulgu şemasında olmalı.
- Syslog / CEF / LEEF alımı: **Yok.** Syslog/CEF yalnızca denetim kaydını dışarı aktarmak için kullanılıyor (`core/compliance/audit_export.py:24-25`). QRadar, ArcSight, FortiGate ve Logsign'ın en yaygın çıkışı tam olarak bu.
- Dosya/S3 yükleme: Var (`services/api/routers/ingestion.py:117-400`).

---

## C. Ekran envanteri (`clients/web/src`)

Rotalar: `/login`, `/setup`, `/:screen` (`App.tsx`). Ekran haritası `shell/SocConsole.tsx:59-73`, navigasyon `data/data.ts:27-41`.

| Ekran | Ne yapıyor | Not / stub |
|---|---|---|
| Home | "Needs you" onayları, demo modu | Demo verisi yükleme (`HomeScreen.tsx:506`) |
| Overview | Akış diyagramı, alarm rayı, gürültü işareti, triyaja gönder, Jira bileti | ServiceNow butonu disabled (`:367`) |
| Triage queue | Gelen alarm ve triyaj sonucu, kind/source/state filtreleri, 10 sn yoklama, 200 satır tavanı | Score "—", Trust floor/weight/score "Not measured", Rescue disabled (`:245`), sıralama, atama ve toplu işlem yok, saat yalnızca UTC |
| Dashboard | Bulgu tablosu (sıralama, arama, kolon seçici, sayfalama, CSV), ATT&CK kapsamı, zaman çizelgesi, hariç tutmalar | Çalışıyor görünüyor |
| Cases | Liste, filtreler (durum, öncelik, kaynak, SLA, atanan), arama, IOC araması, oluştur, düzenle/kapat, birleştir, sil | Toplu seçim disabled (`:363`) |
| Case page | Özet, Açıklamalar, Kanıt, Kontrol edilenler, Hafıza ve kör noktalar, Eylemler (zaman çizelgesi + geri al), Kayıt (zincir doğrula, denetim/kanıt paketi), regülasyon saatleri | Agree/Disagree, "+ Add an explanation", "Rule one out", Withdraw, "Record a blind spot", Replay, "What it changed"/"Planned next" disabled; vaka güveni "Not measured" (`:930`) |
| Case Metrics, Analytics | Metrikler ve grafikler | — |
| AI Decisions | Karar listesi, feedback formu, onay sekmesi | Yalnızca `ai_decisions.approve` iznine açık |
| Scorecard | Karne, QA örnekleme incelemesi, Dersler sekmesi (terfi, geri alma) | Ders önerme UI'ı yok |
| Agents & workflows | Ajanlar, iş akışları, run izleme, hunt | — |
| Auto Ops | Otomatik soruşturmalar | — |
| Health | Sağlık | — |
| Settings | Entegrasyonlar, AI modelleri/sağlayıcılar/bütçe, otonomi katmanları, SLA, SSO, kullanıcılar, görevler ayrılığı, federation, veri alımı (dosya, S3, Kafka), tespit kuralları, MCP yüzeyi | 12 sunucu WIP olarak gizli (Defender, Entra, PAN-OS, Teams, Slack, MISP…) |
| Setup | İlk açılış sihirbazı (sağlayıcı, kaynak, limitler, iş akışları, sistem kontrolleri) | — |
| NotFound, Login | — | Login başlığı "Vigilant, Open, Trustworthy." (`LoginScreen.tsx:158`) |

Grep sayımları (test ve generated hariç, `clients/web/src`):

| İfade | Adet | Öne çıkan |
|---|---|---|
| TODO / FIXME / HACK | 0 / 0 / 0 | — |
| XXX | 2 | Yanlış pozitif (`\uXXXX`) |
| mock | 4 | DEV_MODE sahte kullanıcı (`contexts/AuthContext.tsx:91,133,160`) |
| placeholder | 208 | Büyük çoğunluğu input placeholder'ı (İngilizce) |
| "coming soon" | 0 | — |
| "Coming in a later release" / LATER | 9 dosya-satırı + `CasePage` LATER sabiti (toplam ~17 disabled kontrol) | Rescue, ServiceNow, toplu seçim, Agree/Disagree, Tell/Do, Withdraw, Record a blind spot, EvidenceTrail satır eylemleri, komut çubuğu satırları |
| NotMeasured | 12 kullanım | Triyaj güven tabanı, vaka güveni, maliyet |
| "demo data" | 17 | Demo modu bandı (`SocConsole.tsx:574`) |
| Vigil (büyük/küçük) | 130 | Çoğu iç ad (`VigilMark`, `vigil.*` localStorage, yorumlar). Görünenler: logo işareti (bilinen), login başlığı, MCP sunucu adı `"vigil"` (`tools/mcp/vigil.py:26`) |

---

## D. Bulgular

| ID | Persona | Flow adımı | Eksik (ne yok / ne yanlış) | Kanıt | Önem | Sahip | Tahmini efor |
|---|---|---|---|---|---|---|---|
| SA-01 | Müdahaleci, Admin | 4. Yanıt: executor kurulumu | Defender, Entra ID ve Palo Alto (ürünün tanıttığı üç executor) UI'da "WIP" listesinde. "Add integration" kataloğundan çıkarılıyor; yalnızca zaten açılmışsa listede "WIP" rozetiyle görünüyor. Müşteri bunları konsoldan bağlayamıyor | `screens/settings/integrationsData.ts:18-23`, `integrationCatalog.ts:60`, `IntegrationsSection.tsx:242`; kılavuz "entegrasyon etkinse" diyor (`docs/guide/yonetici-kilavuzu.md:262`) | GA-ENGELİ | Mühendislik + Ürün | S-M |
| SA-02 | L1 | 2. Triyaj: AI kararı | W1.2 yapılandırılmış karar (verdict, alıntılanan alanlar, köken, inconclusive nedeni) daemon tarafından `ai_triage.verdict` olarak saklanıyor ama hiçbir ekranda gösterilmiyor. Triyaj kuyruğunda Score her zaman "—". "Kanıt öncelikli AI SOC" vaadi analistin önünde görünmüyor | `services/daemon/processor.py:1817-1823`; aranan `ai_triage\|triage_reasoning` (clients/web/src) → bulunamadı; `TriageScreen.tsx:290-306` | GA-ENGELİ | Mühendislik | M |
| SA-03 | Tümü | 7. Dil | UI'da i18n çatısı ve Türkçe çeviri yok. `index.html lang="en"`, tüm metinler İngilizce sabit. Türk banka/kamu ihalesi Türkçe arayüz ister | `clients/web/package.json` (i18n bağımlılığı yok); aranan `i18next\|useTranslation\|formatjs` → bulunamadı; `clients/web/index.html:2` | SATIŞ-ENGELİ | Ürün + Mühendislik | L |
| SA-04 | Tümü | 7. AI dili ve raporlar | Prompt'larda dil yönergesi yok (triyaj, verdict, hunt anlatısı, sohbet). Türkçe yanıt ya da rapor garanti değil. Eval korpusunda Türkçe metin 0. Air-gap varsayılan modeli `llama3.1:8b`, Türkçe yeterliliği ölçülmemiş | aranan `same language\|respond in\|Turkish` (core/llm, core/agents, services/agent) → bulunamadı; `grep -cP "[şğı]" eval/corpus/v1/test.jsonl` = 0; `infra/airgap/build-bundle.sh:60` | SATIŞ-ENGELİ | Ürün + Mühendislik | L |
| SA-05 | L1/L2 | 1. Alım: QRadar | QRadar yok (alım, sorgu, offense durumu geri yazma). Türk bankalarında en yaygın SIEM | aranan `qradar` → bulunamadı | SATIŞ-ENGELİ (QRadar müşterisi için) | Mühendislik | L |
| SA-06 | L1 | 1. Alım: genel | Syslog, CEF ve LEEF alımı yok. Webhook ve Kafka yalnızca AutoSecOps'un kendi JSON şemasını alıyor; eşleme ya da normalizasyon katmanı yok. FortiGate, ArcSight, Logsign ve Wazuh ancak müşterinin kendi dönüştürücüsüyle bağlanabilir | `services/daemon/poller.py:235-318`; `core/ingestion/kafka_consumer_service.py:1-13`; syslog/CEF yalnızca giden (`core/compliance/audit_export.py:24-25`) | SATIŞ-ENGELİ | Mühendislik | L |
| SA-07 | L1, Müdahaleci | 1/4. Fortinet, Check Point | Fortinet (alım + engelleme) ve Check Point yok. Türkiye'de yaygın, PAN-OS'tan daha sık | aranan `fortinet\|fortigate\|checkpoint` → bulunamadı | YÜKSEK | Mühendislik | L |
| SA-08 | L1/L2 | 1. Sentinel | Sentinel alımı Azure SDK'ya bağlı ama SDK bağımlılıklarda yok. Gönderilen imajda her yoklama "Azure SDK not installed" hatası verir | `core/integrations/azure_sentinel/ingestion.py:65-66,191-194`; requirements.txt/lock'ta yok; `python -c "import azure.mgmt.securityinsight"` → ModuleNotFoundError | YÜKSEK | Mühendislik | S |
| SA-09 | L1/L2 | 1. EDR | SentinelOne, Trend Micro, Kaspersky ve ESET için alım yok. CrowdStrike ve SentinelOne için containment executor'u yok. Kaspersky Türk kamusunda yaygın | `core/federation/registry.py:39-45`; `core/integrations/sentinelone/descriptor.py` (yalnızca MCP) | YÜKSEK | Mühendislik | L |
| SA-10 | Müdahaleci | 4. Kimlik | On-prem Active Directory için executor ya da sorgu yok (yalnızca Entra). Türk bankalarının çoğu hibrit veya on-prem AD kullanıyor | aranan `ldap\|active directory` (core/integrations) → bulunamadı | YÜKSEK | Mühendislik | L |
| SA-11 | L1/L2 | 1. E-posta güvenliği | E-posta güvenlik ürünü entegrasyonu ve posta geri çekme eylemi yok. Phishing en sık alarm türü | Proofpoint yalnızca kanaryada (`core/quality/canary.py:398`) | YÜKSEK | Mühendislik | L |
| SA-12 | L1/L2 | 2/6. Ticketing | ServiceNow yok (buton disabled). Jira tek yönlü; kapatma/durum geri senkronu yok. Jira MCP Atlassian bulutu (air-gap'te yok) | `OverviewScreen.tsx:367-369`; `jira_export.py:185-195`; `mcp-config.json` jira → `mcp.atlassian.com` | ORTA | Mühendislik | M-L |
| SA-13 | L2, Denetçi | 3. Yorum ve atıf | Yorum yazarı istemcide sabit `'SOC Analyst'`, sunucu da `author`ı istemciden alıyor. Kanıt kaydında `collected_by` aynı şekilde sabit. Kim ne yazdı bilinemiyor: düzenlenmiş sektörde denetim izi ve delil zinciri bozuk. Kapanışta bu sorun zaten çözülmüş (`cases_router.py:227-230`), burada çözülmemiş | `screens/cases/CaseSections.tsx:14,143,374`; `services/api/routers/cases.py:387-411` | GA-ENGELİ | Mühendislik | S |
| SA-14 | L2, Denetçi | 3. Yorum düzenleme/silme | Yorum güncelleme ve silme `case_id` ya da yazar sahipliği kontrol etmiyor. `cases.write` iznine sahip herkes her yorumu siliyor veya değiştiriyor | `cases.py:423-447` (`update_comment(comment_id, …)`) | YÜKSEK | Mühendislik | S |
| SA-15 | L2 | 3. Kanıt yükleme | Vaka kanıtına dosya yüklenemiyor (yalnızca ad + yol metni). Hash ve delil zinciri bu yüzden boş kalıyor | `CaseSections.tsx:129-150`; `attachDocument` yalnızca `CommandBar.tsx:399` | YÜKSEK | Mühendislik | M |
| SA-16 | L1 | 2. Kuyruk ergonomisi | Triyaj kuyruğunda sıralama, sahiplenme/atama, toplu işlem, SLA sayacı, sayfalama (200 tavan) yok; "Rescue" disabled. Vakalarda toplu seçim disabled; atanan serbest metin, kullanıcı seçici yok | `TriageScreen.tsx:17,245-247,291`; `CasesScreen.tsx:363-364,613,252` | YÜKSEK | Ürün + Mühendislik | M-L |
| SA-17 | L1/L2 | 2. Geri bildirim → ders (W3.11) | Vaka sayfasında Agree/Disagree disabled. Ders önerme yalnızca API'den. AI Decisions feedback'i `ai_decisions` tablosunda kalıyor, derslere akmıyor; gözden geçirenin adı serbest metin. "Gürültü" işareti de derse ya da bastırmaya dönmüyor | `CasePage.tsx:960-962`; `services/lessonsApi.ts:8-16` (propose yok); `DecisionsScreen.tsx:378-392`; `findings.py:147-165` | YÜKSEK | Ürün + Mühendislik | M |
| SA-18 | L1 | 5. Eskalasyon | Eskalasyon API'si var ama UI çağırmıyor (yalnızca geçmiş listeleniyor). `escalated_from` istemciden geliyor | `services/api.ts:399-403`; `casesApi.escalate` çağıran yok; `cases.py:661-674` | YÜKSEK | Mühendislik | S-M |
| SA-19 | L1, Amir | 5. Vardiya devri | Vardiya devir notu, nöbet çizelgesi ve "vardiyam" görünümü yok | aranan `handover\|shift` (UI/core) → bulunamadı | ORTA | Ürün | M |
| SA-20 | Amir, Müdahaleci | 5. Bildirim | Vaka bildirim dağıtıcısı Teams'i (Türkiye'de yaygın), SMS'i ve PagerDuty'yi desteklemiyor. Teams yalnızca ajan aracı ve legacy O365 MessageCard webhook'u. Slack `slack.com` (air-gap'te yok) | `core/cases/notification_dispatcher.py:1-20,50`; `core/integrations/microsoft_teams/tool.py:55-80`; aranan `sms\|twilio\|netgsm` → bulunamadı | YÜKSEK | Mühendislik | M |
| SA-21 | L2, Müdahaleci | 3/4. İnsan eylem önerisi | Analistin doğrudan "izole et / engelle / devre dışı bırak" önerebileceği UI ya da API yok. Tek yol sohbetteki ajandan `create_approval_action` istemek | `core/api/v1/approvals_router.py:159-278` (POST create yok); `core/agents/builtins.py:133` | YÜKSEK | Ürün + Mühendislik | M |
| SA-22 | Müdahaleci | 4. Dört göz UI'ı (W3.2) | İlk onaydan sonra "ikinci onaylayıcı bekleniyor; ilk onaylayan X" görünmüyor. Tablo ilk onayı, gerekli onay sayısını ve rol koşulunu göstermiyor. Analist ikinci kez basıp 409 alarak öğreniyor | `DecisionsScreen.tsx:308-340`; `CasePage.tsx:205-230` | ORTA | Mühendislik | S |
| SA-23 | Müdahaleci | 4. Executor'u olmayan ürün | Eylem tipine göre manuel runbook veya kontrol listesi (ör. FortiGate'te elle engelle, kanıtı ekle) yok; yalnızca serbest görev | `CaseSections.tsx:196-260`; aranan `runbook\|playbook` yalnızca workflows ekranında | ORTA | Ürün | M |
| SA-24 | Müdahaleci | 4. İş birimi bildirimi | Etkilenen iş birimine/varlık sahibine bildirim, varlık sahipliği (CMDB) eşlemesi yok | aranan `business.?unit\|stakeholder` → bulunamadı | ORTA | Ürün | M |
| SA-25 | Amir, Uyum | 6/8. Regülatör raporu | Vaka için insan okunur rapor yok. PDF endpoint'i sunucuda `TestOutputs/`a yazıyor, indirme rotası yok, UI çağırmıyor; reportlab Helvetica Türkçe ğ/ş/ı glifi içermiyor. Kanıt paketi yalnızca JSON. Word çıktısı yok | `cases.py:211-266`; `core/reporting/report_service.py:145` (Helvetica); `core/compliance/evidence_bundle.py:227-254` | YÜKSEK | Mühendislik | M |
| SA-26 | Amir, Uyum | 6. Regülasyon saatleri | Vaka regülasyon saatleri yalnızca DORA ve NIS2. KVKK 72 saat ihlal bildirimi, BDDK ve USOM/SOME bildirimi yok (Türk pazarı için asıl gerekenler) | `screens/cases/RegulatoryClocks.tsx:7-10`; `core/compliance/regulatory_router.py:112,165` (`Literal["dora","nis2"]`) | YÜKSEK | Uyum + Mühendislik | M |
| SA-27 | Amir | 6. Olay sonrası inceleme | Kapatma UI'ı API'nin `root_cause`, `lessons_learned`, `recommendations` ve `executive_summary` alanlarını toplamıyor. Kapatma yalnızca listedeki "Edit case" diyaloğundan; vaka sayfasında Kapat butonu yok | `CasesScreen.tsx:714-775`; `core/api/v1/cases_router.py:224-239` | ORTA | Ürün + Mühendislik | S-M |
| SA-28 | Tümü | 7. Saat/zaman dilimi | Triyaj ve vaka ekranları UTC'ye sabit, başka yerlerde 35 adet `toLocaleString` tarayıcı yereli ve dilimiyle gösteriyor: ekranlar arası tutarsız saat. Europe/Istanbul ya da kullanıcı tercihi ayarı yok | `shared/utc.ts:1-2`; `TriageScreen.tsx:60-70`; `grep toLocale*` = 35 | YÜKSEK | Mühendislik | M |
| SA-29 | L2 | 3. Air-gap zenginleştirme | Air-gap'te VT/Shodan yok. Yerel istihbarat için MISP UI'dan gizli (WIP); TAXII var. USOM listesi yok. Bağlıyken iç (RFC1918) IP'ler de Shodan'a gönderiliyor (KVKK/sır riski, işe yaramaz) | `integrationsData.ts:18-23`; `processor.py:1847-1958` (özel IP süzgeci yok) | YÜKSEK | Mühendislik | M |
| SA-30 | Tümü | 2. Sınama kapsamı | Eval korpusunda QRadar, Fortinet, Palo Alto ve Türkçe alarm yok. Kaynaklar: crowdstrike, sentinel, guardduty, entra, proofpoint, zeek, defender, dlp, k8s. Doğruluk iddiası Türk müşterinin gerçek kaynaklarında ölçülmemiş | `eval/corpus/v1/test.jsonl` kaynak dağılımı | YÜKSEK | Mühendislik + Ürün | M-L |
| SA-31 | L2 | 3. Varlık görünümü | Kullanıcı/host/IP için vaka içi varlık sayfası veya grafiği ve varlık geçmişi (bu host önceki vakalarda) yok; yalnızca IOC listesi ve hafıza | `CasePage.tsx:52` TABS; `CaseSections.tsx:427` | ORTA | Ürün | M |
| SA-32 | L2 | 3. Alarm–vaka bağlama | Bulguyu elle vakaya ekleme ve vakaları ilişkilendirme UI'ı yok. Relationships API'si var ama kullanılmıyor | `CasesScreen.tsx:650-656`; `cases.py:640-675`; `services/api.ts:329-412` | ORTA | Mühendislik | S-M |
| SA-33 | Tümü | 8. Arama ve görünümler | Global arama yalnızca vakalarda (tam metin + IOC). Bulgu/alarm metni araması komut çubuğunda yok. Sunucu tarafı kaydedilmiş görünüm yok (yalnızca yerel kolon tercihleri) | `shell/CommandBar.tsx:72-73`; aranan `saved.?view` → bulunamadı | ORTA | Mühendislik | M |
| SA-34 | Tümü | 2. Klavye | Liste gezinme ve aksiyon kısayolları (j/k, a=assign, c=close vb.) yok; yalnızca Ctrl+K ve Esc | `CommandBar.tsx:159`; `SocConsole.tsx:387` | ORTA | Mühendislik | S-M |
| SA-35 | Tümü | 7. Erişilebilirlik | Otomatik a11y denetimi (jsx-a11y, axe) yok. aria etiketleri bol (381) ama ölçülmemiş. Kamu ihalelerinde erişilebilirlik uygunluğu istenebilir | `clients/web/package.json` (axe/jsx-a11y yok) | ORTA | Mühendislik | M |
| SA-36 | L1/L2 | 9. Destek | "Share feedback" menüsü herkese açık GitHub issue sayfasına gidiyor (`SingularityRD/autosecops2`). Air-gap'te çalışmaz, ekran ve sürüm bilgisi dışarı gider, kurumsal destek kanalı (portal/e-posta/telefon) yok | `shell/UserMenu.tsx:9-17,136-139` | ORTA | Destek-Operasyon | S |
| SA-37 | Tümü | Eğitim / ilk değer | SOC analisti kullanıcı kılavuzu (Türkçe, vardiya akışı, ekran ekran) yok; belge seti yönetici, kurulum, güvenlik ve mevzuat odaklı. Yalnızca konsol turu var | `docs/guide/README.md` tablo; `shell/ConsoleTour.tsx` | YÜKSEK | Ürün + Destek-Operasyon | M |
| SA-38 | Tümü | 9. Bozulma görünürlüğü | Durum satırı DB, şema, federation, MCP ve "routable provider" kapsıyor; daemon/webhook alıcısı durumu, Kafka tüketicisi ve executor kayıt defteri yok. Executor'lar entegrasyon açılınca API ve daemon yeniden başlatılmadan devreye girmiyor | `shell/statusLine.ts:52-95`; `yonetici-kilavuzu.md:262-264` | ORTA | Mühendislik | S-M |
| SA-39 | L1 | 9. Hata mesajları | Daemon webhook 400 gövdesi ham `str(e)` dönüyor; bazı API'ler `detail=str(e)` (çoğu doğrulama). API'nin genel 500 işleyicisi iç ayrıntıyı gizliyor (iyi) | `services/daemon/poller.py:318`; `services/api/errors.py:44,82` | DÜŞÜK | Mühendislik | S |
| SA-40 | L1 | 2. Rol/ekran erişimi | AI Decisions ekranı (feedback dahil) yalnızca `ai_decisions.approve` iznine açık. L1 Analyst AI kararlarını puanlayamıyor | `SocConsole.tsx:80`; `06_auth_tables.sql:69-85` | DÜŞÜK | Ürün | S |
| SA-41 | L2 | 3. Sohbet modları | Sohbette "Tell" ve "Do" modları disabled; vaka sayfasında "+ Add an explanation", "Rule one out", "Withdraw", "Record a blind spot", "Replay" disabled. Analist gördüğü butonların yarısını kullanamıyor | `Chat.tsx:1242-1243`; `CasePage.tsx:1004-1005,1127,1260,1272` | ORTA | Ürün | M (gizle: S) |
| SA-42 | Tümü | Marka | Login başlığı "Vigilant, Open, Trustworthy." ve MCP sunucu adı `"vigil"` dış istemcilere görünüyor (logo işareti zaten biliniyor) | `screens/login/LoginScreen.tsx:158`; `tools/mcp/vigil.py:26` | DÜŞÜK | Satış-Pazarlama + Mühendislik | S |
| SA-43 | L1 | 1. Kafka/webhook dayanıklılığı | Kafka'da DLQ yok, bozuk mesaj yalnızca loglanıp atlanıyor; analist kaybolan alarmı göremiyor | `kafka_consumer_service.py:7-8` | ORTA | Mühendislik | M |
| SA-44 | Müdahaleci | 4. Teams bağlantısı | Teams aracı O365 Incoming Webhook ve MessageCard kullanıyor. Microsoft bu bağlayıcıları Workflows'a taşıyor; güncel destek doğrulanmalı | `microsoft_teams/tool.py:55-80` | ORTA | Mühendislik | S-M |
| SA-45 | Tümü | Sözleşme bitişi / veri iadesi | Analist verisinin toplu dışa aktarımı (vakalar, yorumlar, eylemler) için UI yok. Yalnızca bulgu CSV'si ve vaka başına kanıt paketi | `DashboardScreen.tsx:155-158`; `EvidencePackButton.tsx` | ORTA | Mühendislik | M |

---

## E. Yaşam döngüsü (analist açısından) özeti

| Aşama | Analistin ihtiyacı | Durum |
|---|---|---|
| Keşif/değerlendirme (POC) | Türkçe demo, QRadar/Fortinet ile POC, Türkçe verdict | Demo verisi var; QRadar/Fortinet/Türkçe yok (SA-03..07) |
| Kurulum / ilk açılış | Kaynağı bağla, ilk alarm | Setup sihirbazı var; Defender/Entra/PAN-OS sihirbazda ve katalogda yok (SA-01) |
| İlk değer | İlk gün triyaj kararını kanıtıyla görmek | Karar UI'da yok (SA-02) |
| Günlük kullanım | Kuyruk, claim, eskalasyon, devir, bildirim | Bkz. SA-16..22 |
| Genişleme | Yeni EDR/FW/e-posta, ITSM | Bkz. SA-07..12 |
| Yükseltme/yama | Uygulama içi sürüm notu, değişen ekran | Sürüm yalnızca "About" notunda (`UserMenu.tsx:139`); uygulama içi "neler değişti" yok (DÜŞÜK) |
| Destek/olay | Kurumsal destek kanalı | GitHub linki (SA-36) |
| Yenileme | Kanıtlanmış değer raporu (GKAO, MTTR) Türkçe | Scorecard ve metrikler var, İngilizce ve dışa aktarımsız |
| Sözleşme bitişi | Vaka/yorum/eylem toplu dışa aktarımı | SA-45 |

---

## F. Var ve çalışıyor görünüyor

- Federation alımı: Splunk, Elastic, OpenSearch, CrowdStrike, Defender, AWS Security Hub (+ Sentinel kodu, SA-08 hariç). Darktrace ve Cloudflare webhook'ları. Genel bearer token'lı webhook (fail-closed), Kafka JSON, dosya ve S3 yükleme, Redis dedup, kalıcı spool.
- Yanıt hattı: politika → executor kayıt defteri → doğrulama → süre dolumu/geri alma. Defender, Entra ve PAN-OS executor'ları gerçek ve belgeli (`EXECUTOR.md`). Cloudflare her zaman kayıtlı. Politika yapılandırması okunamazsa fail-closed reddediyor (`core/response/policy.py:675`).
- Dört göz: aynı kişi 409, farklı rol koşulu; görevler ayrılığı ekranı (`SegregationSection.tsx`).
- Vaka eylem zaman çizelgesi ve gerekçeli Revert (`CaseActions.tsx`), kayıt sekmesinde zincir doğrulama ve imzalı kanıt paketi (ZIP).
- Kapanış: kategori zorunlu, FP için gerekçe zorunlu, kapatan oturumdaki kullanıcı (`cases_router.py:227-230`). Yeniden açma var.
- Vaka: yorum (iç içe), görev, IOC, SLA ve "Near SLA" filtresi, "Assigned to me", birleştirme, tam metin ve IOC araması (Ctrl+K).
- Dashboard bulgu tablosu: sıralama, arama, kolon seçimi, sayfalama, CSV dışa aktarım, ATT&CK kapsamı, zaman çizelgesi, IP hariç tutma.
- Hunt/verdict run'ları, açıklamalar sekmesi ve kanıt izi (köken ile); sohbet (Ask) ve vaka @mention araması.
- QA örnekleme incelemesi ve dersler (terfi, replay, geri alma) Scorecard'da.
- Bildirim: SMTP e-posta, Slack, HMAC imzalı giden webhook (yeniden denemeli). Kanarya vakaları dışarı gitmiyor. Onaylar için masaüstü bildirimi.
- Bozulma: durum satırı (DB, şema, federation, MCP, sağlayıcı). API 500'leri iç ayrıntıyı gizliyor. Ekranlarda yükleniyor/hata/boş durumları ve Retry tutarlı.
- Air-gap: MCP npx/uvx paketleri imaja gömülü (`core/integrations/mcp/packaged.py`); kanarya için harici zenginleştirme kapalı.
- TODO/FIXME yok. Sahte veri yalnızca açıkça etiketli demo modunda ve DEV_MODE'da.
