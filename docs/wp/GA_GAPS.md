# AutoSecOps 2.0 — Satışa hazırlık eksik listesi (14 Ekim 2026)

Kaynak: `main` @ `87b1438e` (= `v2.0.0-rc.1`) üzerinde yedi bağımsız, salt-okunur inceleme. Her bulgu
kanıtlı (dosya:satır ya da boş dönen arama). Ayrıntılı raporlar ve her bulgunun kanıtı:
`docs/wp/gaps/1…7-*.md` (ID'ler: S- satıcı, PY- platform, SA- analist, SOC4- yönetici/CISO, U- uyum/KVKK,
K6- kalite/doküman, KS- kurulum sihirbazı/yaşam döngüsü). Toplam ~340 bulgu: 36 SATIŞ-ENGELİ, 39 GA-ENGELİ,
145 YÜKSEK, 96 ORTA, 23 DÜŞÜK satırı (alanlar arası tekrarlar dahil; aşağıda tekilleştirildi).

**Önem:** SATIŞ-ENGELİ = bu olmadan Türk banka/kamu kurumu sözleşme imzalayamaz veya kuramaz.
GA-ENGELİ = GA etiketinden önce kapanmalı. **Sahip:** Müh / Ürün / Hukuk / Satış / Destek / Uyum.

## 0. rc.1 durumu

`v2.0.0-rc.1` Release iş akışı (run 38644995176) **başarılı**: 3 imaj (amd64+arm64) GHCR'de,
SBOM, cosign imza + SLSA provenance, SHA256SUMS, müşteri betiğiyle öz-doğrulama, taslak Release.
Release sayfası "Latest" görünüyordu; pre-release işaretlenmeli (insan).

## 1. Ürünün tezini doğrudan etkileyenler (önce bunlar)

| # | Eksik | Kanıt (ayrıntı) | Önem | Sahip |
|---|---|---|---|---|
| T1 | **Otonomi varsayılanı plana ters.** Sihirbaz "Act"ı "Recommended" işaretliyor, Helm `DAEMON_FORCE_APPROVAL=false`, başlık çipi varsayılanda "Act" gösteriyor; "host izolasyonu her zaman insan ister" metni yanlış — `isolate_host` `AUTONOMOUS_ELIGIBLE` içinde | KS-20, K6-13 (`WorkflowsStep.tsx:197`, `core/autonomy/tiers.py:79-81`, `SocConsole.tsx:57`) | GA-ENGELİ | Müh+Ürün |
| T2 | **Verdict şeridi bağlı değil** (`enqueue_verdict_run` çağrılmıyor); "her belirsiz alarmda soruşturma" vaadi teslim edilmiyor, sürüm notu kendi içinde çelişiyor | K6-11 (`core/lanes/alert_lanes.py:875,914`) | GA-ENGELİ | Müh |
| T3 | **Yapılandırılmış AI kararı (W1.2) hiçbir ekranda görünmüyor**; triyajda skor "—" | SA-02 | GA-ENGELİ | Müh |
| T4 | **Gerçek modelle ölçülmüş tek sonuç yok** (kaset stub); FN ölçülmedi, recall görülmemiş veride 0,833, injection 0,0875 (> %5), maliyet −%60 verisiz; Karne yayımlanmamış | SOC4-01/04/06/07, S-40 | SATIŞ-ENGELİ | Müh+Ürün |
| T5 | **Müşteri kendi verisiyle eval yapamıyor**, POC raporu/karne dışa aktarımı yok ("Export report" düğmesi ölü), POC kılavuzu yok | SOC4-02/03/42, S-07/08 | SATIŞ-ENGELİ | Müh+Satış |
| T6 | **Tanıtılan üç executor (Defender, Entra, Palo Alto) arayüzden bağlanamıyor** ("WIP" listesinde); açılan executor yeniden başlatmadan çalışmıyor | SA-01, KS-18 | GA-ENGELİ | Müh |
| T7 | SLO: kural şeridi p95 18,8 sn (hedef < 5 sn), staging ölçümü yok | SOC4-10, K6-33 | GA-ENGELİ | Müh |

## 2. Satış engelleri (tekilleştirilmiş)

### 2a. Ticari ve hukuki (repo dışı, insan işi)
| # | Eksik | Kanıt | Sahip |
|---|---|---|---|
| H1 | Lisans modeli kararı (eklediğimiz kod Apache mi, ticari mi), fiyat/paket modeli, lisans anahtarı/entitlement (şu an imajlar `licenses=Apache-2.0`, yeniden dağıtım serbest) | S-03, S-09, K6-23 | Ürün+Hukuk |
| H2 | EULA / müşteri koşulları, SLA ve destek koşulları (P1–P4, yanıt süreleri), AI kararları için sorumluluk sınırı | S-10, S-12, S-43, K6-42 | Hukuk |
| H3 | KVKK veri işleyen sözleşmesi (DPA), BDDK destek hizmeti eki (denetim hakkı, alt işleyen listesi — LLM sağlayıcıları) | S-11, S-24, U-11 | Hukuk |
| H4 | Destek kanalı ve bilet sistemi; üründe satıcı iletişimi yok ("Share feedback" GitHub'a gidiyor) | S-31, SA-36, K6-21 | Destek |
| H5 | Marka araştırması/tescili ("AutoSecOps") | S-18 | Hukuk |
| H6 | SOC 2/ISO beyanı, satıcı BCP/DR, CAIQ/SIG-lite cevap seti, escrow | S-23, S-26, S-27, U-49 | Uyum |

### 2b. Mevzuat ve KVKK (ürün + belge)
| # | Eksik | Kanıt | Sahip |
|---|---|---|---|
| K1 | **Giriş/kullanıcı yönetimi olayları kalıcı kaydedilmiyor** (yalnız varsayılan-kapalı SIEM kuyruğuna); mevzuat belgesi "Karşılanıyor" diyor — yanlış | U-15 (`users.py:72-76,546,570,595`) | Müh |
| K2 | **İlgili kişi hakları aracı yok** (bul/dışa aktar/sil, KVKK md. 13 30 gün); denetim zinciri kaynak satırın kopyasını tuttuğu için silme ile çatışıyor | U-30, U-31 | Müh+Uyum |
| K3 | Kişisel veri envanteri (VERBİS için) yok | U-10 | Uyum |
| K4 | Düzenleyici saatler yalnız DORA/NIS2: **KVKK 72 saat, BDDK, USOM/SOME yok**; şablonlar İngilizce | U-26/27, SOC4-36, SA-26 | Müh+Uyum |
| K5 | CBDDO Bilgi ve İletişim Güvenliği Rehberi eşlemesi yok; 7545 sayılı Siber Güvenlik Kanunu ele alınmamış (hukuk teyidi) | U-01, U-02 | Uyum+Hukuk |
| K6 | Mevzuat eşlemesi düzeltmeleri: KVKK md. 9 (2024 değişikliği), BDDK/SPK madde no, A.8.32 kapsamı, SBOM/imza "Planlı" → mevcut | U-04, U-05 | Uyum |

### 2c. Türkiye pazarı
| # | Eksik | Kanıt | Sahip |
|---|---|---|---|
| P1 | **Türkçe arayüz yok** (i18n altyapısı yok, `lang="en"`), saat dilimi Europe/Istanbul seçilemiyor | SA-03, K6-27, SOC4-25, KS-15, SA-28 | Müh |
| P2 | **AI'nın Türkçe çalıştığı ölçülmemiş** (prompt'ta dil yok, korpusta Türkçe 0, varsayılan `llama3.1:8b`) | SA-04, SA-30 | Müh |
| P3 | **Türkçe PDF basılamıyor** (Helvetica/WinAnsi; ş ğ ı İ yok); PDF indirilemiyor, aylık SOC raporu yok | SOC4-24, SA-25 | Müh |
| P4 | **QRadar yok; syslog/CEF/LEEF alımı yok** (FortiGate, ArcSight, Logsign, Wazuh bağlanamıyor); Fortinet/Check Point executor yok | SA-05/06/07 | Müh |
| P5 | Bildirim: Teams/SMS yok; air-gap'te hiçbir bildirim kanalı kurulamıyor (yalnız Slack) | SA-20, KS-23 | Müh |

### 2d. Kurulum ve işletim
| # | Eksik | Kanıt | Sahip |
|---|---|---|---|
| O1 | Boyutlandırma rehberi (alarm hacmi → CPU/RAM/GPU, model, disk), GPU/TCO kılavuzu | PY-01, SOC4-43 | Müh |
| O2 | **OpenShift uyumsuz** (sabit UID 1000, `chgrp 0` yok, PG/Redis/Ollama root) | PY-02 | Müh |
| O3 | Bağlantılı (air-gap olmayan) Helm için Türkçe kılavuz yok; README/Chart upstream'e yönlendiriyor | PY-06, S-20 | Müh |
| O4 | Helm grafiği Bifrost/Ollama'yı kurmuyor ama `BIFROST_URL` varsayıyor | PY-07 | Müh |
| O5 | KMS/HSM/Vault-transit yok; `master.key` sırların yanında, TOTP anahtarı JWT'den türetiliyor | PY-21, U-44 | Müh |
| O6 | Yanıt politikası (korunan varlık, saatlik sınır, dört göz türleri) yalnız doğrudan SQL ile; denetlenmiyor | SOC4-11, KS-19 | Müh |
| O7 | Çıkış planı: tam veri dışa aktarımı, kaldırma, güvenli silme, imha tutanağı | SOC4-41, S-41, KS-37/38, U-50, PY-55/56, K6-41 | Müh+Destek |
| O8 | `SECURITY.md` upstream: açık bildirimleri `security@deeptempo.ai`/Vigil-SOC'a gidiyor, "0.5.x destekli"; 2.x destek/EOL politikası yok | S-22, K6-02, PY-46, U-40 | Ürün |

## 3. GA engelleri (§1 dışında)

| # | Eksik | Kanıt | Sahip |
|---|---|---|---|
| G1 | **İlk admini ağdan ilk gelen alıyor** (kurulum token'ı yok) | KS-02 (`auth.py:94-100`) | Müh |
| G2 | **Helm'de konsoldan girilen sırlar düz `.env`'e yazılıyor ve kalıcı değil** (emptyDir, 2 replika); belgeler "şifreli secrets.enc" diyor | PY-19/20 | Müh |
| G3 | JWT döndürme MFA'lı hesapları kilitliyor (TOTP JWT'den türetilmiş anahtarla); sır döndürme runbook'u yok | PY-35 | Müh |
| G4 | Kurulumda checkpoint/kanıt paketi imza anahtarları istenmiyor → imzalı checkpoint yok, kanıt paketi geçici anahtarla | U-13 | Müh |
| G5 | Ayar değişiklikleri denetlenmiyor: LLM sağlayıcı (yurt dışı aktarım kimin kararı?), skills, workflows, detection rules, bütçe, SLA politikaları (Analyst değiştirebiliyor) | U-16/21, SOC4-12 | Müh |
| G6 | Vaka yorumu/kanıtında yazar istemcide sabit `'SOC Analyst'`; sunucu doğrulamıyor | SA-13 (`CaseSections.tsx:14,143,374`) | Müh |
| G7 | Toplu bulgu dışa aktarma Viewer dahil herkese açık ve kaydedilmiyor | U-17 | Müh |
| G8 | Marka: kök README, logo/favicon, Helm Chart meta, NOTES.txt ("Vigil SOC has been installed"), `noreply@vigil.local`, masaüstü `ai.deeptempo.vigil`, `vigil-support`, login başlığı "Vigilant, Open, Trustworthy." | K6-01/04/05/06, S-17/20, KS-05, SA-42 | Müh |
| G9 | Apache-2.0 §4: LICENSE şablon ("Copyright [yyyy]"), NOTICE yok, değiştirildi bildirimi yok, LICENSE imaj/paket/destek tarball'ına girmiyor; üçüncü taraf lisans envanteri yok | S-13/14, K6-23 | Müh+Hukuk |
| G10 | Paketlenen bileşen lisansları: `redis:7-alpine` kayan etiket (7.4+ RSALv2/SSPL), Llama lisansı/"Built with Llama"/AUP yok, Elastic (ELv2) ve Sigma (DRL) kuralları yeniden dağıtılıyor | S-15 | Hukuk+Müh |
| G11 | Ajan imajı `node:20-slim` (Node 20 EOL Nisan 2026); düzeltmesiz OS CVE'leri için VEX/risk kabulü yok; `ubuntu-latest` runner sabitlenmeli (19 Ekim) | S-34, K6-45, F-10/12 | Müh |
| G12 | Belgeler koda ters: SBOM/imza "Planlı", taban `b8795def`; analist kullanıcı kılavuzu yok; konsol İngilizce/belgeler Türkçe | U-05/07, PY-51, K6-24/28 | Müh |
| G13 | Air-gap kurulumda metrik yok (OTEL kapalı); GA OTEL panolarının çoğu yok; Helm'de Grafana/PrometheusRule yok | PY-28, SOC4-22 | Müh |
| G14 | Port/güvenlik duvarı/DNS/TLS matrisi; GHCR görünürlüğü ve pull secret belgesi; Helm grafiği yayımlanmıyor | PY-04/09, S-28 | Müh+Destek |
| G15 | Model değişikliği eval kapısından geçmiyor; canlıda injection izleme yok | SOC4-29/32 | Müh |
| G16 | Init SQL sabit `deeptempo` rolü (farklı DB kullanıcısında 6 dosya uygulanmaz) | K6-44, F-09 | Müh |
| G17 | Sihirbaz boş kurulumu "hazır" sayıyor; ilerleme yalnız tarayıcıda; `reset-setup.sh` CSRF'te kırık | KS-09/10/25 | Müh |
| G18 | Demo tezi göstermiyor (onay, geri alma, kanıt paketi, DORA yok); air-gap profilinde demo kapalı | S-04/05, K6-39, KS-40 | Müh+Satış |

## 4. Yüksek öneme sahip başlıklar (ayrıntı dosyalarda)

- **Analist deneyimi:** triyaj kuyruğunda sıralama/sahiplenme/toplu işlem/SLA sayacı yok, 200 satırda kesiliyor; eskalasyon UI'sı yok; analist doğrudan eylem öneremiyor; kanıt dosyası yüklenemiyor; yorumları herkes silebiliyor; Agree/Disagree derslere akmıyor; vardiya devri, runbook, global arama, kaydedilmiş görünüm yok; ~17 kontrol "Coming in a later release" (SA-14…41).
- **Entegrasyonlar:** Sentinel alımı kırık (Azure SDK yok); SentinelOne/Trend/Kaspersky/ESET alımı, on-prem AD executor'ı, e-posta güvenliği yok; 36+43 entegrasyonun hiçbirinde destek düzeyi yok (SA-07…11, K6-17).
- **Yönetici/CISO:** zamanlanmış raporlar yalnız log'a yazılıyor; bütçe uyarısı yok; MTTA yok, "yanıt süresi" yanlış formül; otomatik/eskale trendi, eylem panosu, kanarya/recall UI'da yok; atama/vardiya/kuyruk modeli yok; erişim gözden geçirme ve genel denetim görüntüleyici yok; ROI kanıtı yok (SOC4-05…39).
- **KVKK/denetim:** LLM'e gitmeden PII maskelenmiyor; prompt kayıtları süresiz (Bifrost `logs.db` saklama dışı); uygulamada bulut LLM kilidi yok; saklama kör noktaları (episodik bellek, dersler, onaylar, exports); imha kayıtları zincirsiz; yedekler saklamaya uymuyor; kanıt paketi Türkçe/PDF değil, e-imza/zaman damgası yok; çevrimdışı zincir doğrulama DB istiyor; vakada kişisel veri ihlali işareti yok; servisler arası trafik şifresiz; AI yönetişim paketi (model kartı) yok (U-17…45).
- **Platform:** `start.sh` geliştirme sunucularını başlatıyor; Compose kaynaktan derliyor, TLS yok; gömülü Redis parolasız, NetworkPolicy kapalı; kurumsal proxy desteği yok; harici PG TLS kullanılmıyor; SAML/LDAP/SCIM, MFA zorlaması, boşta zaman aşımı yok; PDB yok; Helm yedeği şifresiz ve yalnız DB; yükseltme öncesi yedek kancası yok, `helm rollback` uyarısı yok; `readOnlyRootFilesystem: false`; FIPS imajı yayımlanmıyor; config-as-code yok (PY-*).
- **Sihirbaz ve yaşam döngüsü:** KVKK veri yerleşimi onayı, yerel model/GPU doğrulama, SSO, davet, SLA, saklama, SIEM, yedek adımları yok; rehberli ilk alarm ve "neler eksik" sayfası yok; yedek hatası, disk dolması, sertifika/lisans/kimlik bilgisi süresi, çevrimdışı güncelleme UI'da görünmüyor; yapılandırma dışa/içe aktarımı yok (KS-*).
- **Kalite:** e-posta karşılaştırması büyük/küçük harfe duyarlı (`Ali@`≠`ali@`), OIDC'de Türkçe `İ` katlama hatası; ~287 yerde 200 + `{"error"}` (bazıları istisna metniyle); e2e test yok; 11 test görmeyen core modülü; upstream yüzeyleri (Skills, AutoOps, LogLM, VStrike, masaüstü) belgesiz ama açık — GA'da gizle veya "Önizleme" (K6-*).
- **Profesyonel hizmetler ve satış:** saha keşif/kabul tutanağı, analist eğitim müfredatı, kurulum runbook'u, rakip karşılaştırması, LTS/backport politikası, müşteri portalı/teslim kanalı (S-29…37).

## 4b. Kapanış durumu (17 Ekim 2026, `main`)

| Boşluk | WP | Durum |
|---|---|---|
| T1, G1, G2, G3, G4, G5, G6, G7, G8, G9, G10, G11, G16, G17, K1, O6, O8, T6 | W0.32–W0.39 | Kapandı (batch 1) |
| P3 Türkçe vaka raporu PDF | W0.40 | Kapandı |
| P4 syslog/CEF/LEEF + QRadar | W0.41 | Kapandı (QRadar Deneysel; Fortinet/Check Point yürütücüsü yok) |
| K4 KVKK/BDDK/USOM saatleri | W0.42 | Kapandı (BDDK/USOM süreleri kurum içi hedef) |
| Batch-1 doğrulayıcı takipleri | W0.44 | Kapandı |
| T3 AI kararı UI'da | W0.45 | Kapandı (triyaj kuyruğu, bulgu penceresi) |
| P5 bildirim | W0.46 | Kısmi: e-posta listesi ve Teams; SMS yok |
| O1, G14, O3, O7 | W0.47 | Belgelendi (boyutlandırma ölçülmedi; grafik bir Helm deposunda yayımlanmıyor) |
| K2 ilgili kişi hakları | W0.48 | Kısmi: kayıt, arama, dışa aktarım; silme saklama araçlarıyla |
| T5 müşteri verisiyle eval + POC raporu | W0.49 | Kapandı |
| G18 demo tezi | W0.50 | Kapandı (air-gap'te çalışır) |
| G13 air-gap metrikleri, alarmlar, pano | W0.51 | Kapandı |
| G12 belgeler ve analist kılavuzu | W0.52 | Kapandı (konsol İngilizce kalır) |
| G15 model kapısı, canlı injection sayaçları | W0.53 | Kapandı (kapı varsayılan olarak zorlanmaz) |
| O2 OpenShift | W0.54 | Önizleme (gerçek kümede doğrulanmadı) |
| O4 LLM yığını Helm'de | W0.55 | Kapandı (gerçek kümede doğrulanmadı) |
| P4 FortiGate yürütücüsü | W0.57 | Kapandı (Deneysel; Check Point müşteri talebiyle) |
| P5 SMS, K2 silme aracı | — | Açık (müşteri talebiyle) |
| T2, T4, P1, H1–H6, K3, K5, K6 | — | Sahip kararı / hukuk / ölçüm bekliyor |

## 5. Önerilen sıra

1. **Bu hafta, mühendislik (rc.2 için):** T1 otonomi varsayılanı, G1 kurulum token'ı, G2/G3 sırlar, G6 yazar sahteciliği, G7 dışa aktarma yetkisi, K1 kimlik olaylarını kalıcı kaydet, G5 eksik denetim kayıtları, G4 imza anahtarı kurulumu, O6 politika UI/API, T6 executor bağlama, G8/G9/O8 marka-lisans-SECURITY dosyaları, G10/G11 bağımlılık sabitleme, G16, G17. Sonra rc.2.
2. **Ürün kararı gerektirenler (kullanıcı):** H1 lisans/fiyat modeli; T2 verdict şeridini bağla mı yoksa iddiayı geri çek mi; P1 Türkçe UI kapsamı (GA mı, Kasım mı); upstream yüzeylerini gizleme listesi; T4 iddiaları gerçek ölçüm gelene kadar yumuşatma.
3. **Paralel, mühendislik (GA'ya kadar):** P3 Türkçe PDF, P4 syslog/CEF/LEEF + QRadar, K4 KVKK/BDDK/USOM saatleri, K2 ilgili kişi hakları, T3 AI kararı UI'da, T5 müşteri verisiyle eval + POC raporu, O2 OpenShift, O3/O4 bağlantılı Helm + LLM yığını, O7 çıkış prosedürü, G13 metrikler, P5 Teams/e-posta air-gap.
4. **Gerçek modelle ölçüm (T4):** air-gap varsayılan modeli ve en az bir bulut modeli için tam eval + injection + maliyet; Türkçe vaka seti; sonuçları Karne olarak yayımla — pazarlama iddiaları buna bağlanmalı.
5. **Hukuk/uyum (paralel, repo dışı):** H2–H6, K3, K5, K6.
