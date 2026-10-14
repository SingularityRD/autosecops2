# 5 — Uyum, denetim, KVKK ve düzenleyici beklentiler: satışa hazırlık eksik analizi

Kod: `/root/wt/gap` (main @ 87b1438e, salt-okunur). Personalar: **UY** Uyum sorumlusu, **İD** iç denetçi, **DD** dış (bağımsız / BDDK / SPK) denetçi, **DPO** KVKK irtibat kişisi / veri sorumlusu temsilcisi, **HK** hukuk ekibi, **DÜZ** düzenleyici (KVK Kurulu, BDDK, SPK, Siber Güvenlik Başkanlığı/USOM, CBDDO).

Bu belge hukuki görüş değildir. Madde numarası verilen her yerde, eşleşmenin hukuk ekibince teyit edilmesi gerekir. Özellikle BDDK, USOM/SOME, EPDK, BTK süreleri ve 7545 sayılı Siber Güvenlik Kanunu'nun ikincil düzenlemeleri için "hukukça teyit" notunu ciddiye alın.

Zaten bilinen ve listelenmiş olanlar burada yeniden keşfedilmedi, yalnızca sayıldı: rc.1 etiketi atıldı, Kapı C yapılmadı, dış pentest (W4.4), W1.4 kararı, yüksek riskli WP ürün onayları, etiket ruleset'leri, katalog yer tutucuları, otomatik kapatma ve çok kiracılığın Kasım'a ertelenmesi. Tehdit modelinde zaten kayıtlı riskler (R2, R3, R6, R7, R8, R9, R13, R15, R16, R17, R18, R27, R31, R32) da yalnızca ilgili satırda anıldı.

---

## A. Yaşam döngüsü boyunca user story'ler ve adım doğrulaması

Her adımda ✅ var, ◐ kısmi, ❌ yok. Kanıt kolonu en sağda; bulgu ID'si varsa §C'deki satıra bağlanır.

### A1. Keşif ve değerlendirme (UY, HK, DPO, DÜZ beklentisi)

| # | Story / adım | Durum | Kanıt / bulgu |
|---|---|---|---|
| 1 | UY, tedarikçi değerlendirme paketinde mevzuat eşlemesini okur: BDDK, KVKK, SPK, ISO, DDO, USOM, EPDK/BTK | ◐ | Eşlemede BDDK, KVKK, DORA, NIS2, SPK ve ISO var. DDO, USOM/SOME, 7545, EPDK, BTK ve AI Act yok: `docs/guide/mevzuat-eslemesi.md` (bölüm başlıkları 57–152); `grep -i "ddo\|usom\|epdk\|btk\|7545" docs/guide` → yok. **U-01, U-02, U-03** |
| 2 | HK, eşlemedeki madde numaralarını kontrol eder | ◐ | BDDK ve SPK satırlarında madde numarası yok (`mevzuat-eslemesi.md:59-69, 108-117`). KVKK md. 9 satırı 2024 değişikliğini (7499 s. Kanun: standart sözleşme, 5 iş günü içinde Kurul'a bildirim) anmıyor (`:74`). **U-04** |
| 3 | UY, eşlemedeki "Karşılanıyor" iddialarını koda karşı doğrular | ◐ | Birkaç iddia yanlış ya da eskimiş. **U-05 … U-09** |
| 4 | DPO, VERBİS ve kişisel veri envanteri girdisini ister: hangi tablolarda hangi kişisel veri, amaç, alıcı, saklama | ❌ | `grep -rni "verbis\|envanter\|veri kategorisi"` → yalnızca `core/compliance/RETENTION.md:5` ("VERBİS veri sorumlusunun sorumluluğunda"). **U-10** |
| 5 | HK, veri işleyen sözleşmesini (KVKK md. 12/2), destek hizmeti sözleşme eklerini (BDDK denetim hakkı, sır saklama) ve EULA'yı ister | ❌ | `LICENSE` Apache-2.0. `grep -rli "eula\|veri işleyen\|data processing agreement"` → yok. **U-11** |
| 6 | DÜZ (BDDK), verinin yurt içinde kalmasını ve dış hizmet olmamasını bekler | ◐ | Air-gap profili ve NetworkPolicy var (`infra/airgap/values-airgap.yaml:13-15`). Uygulama içinde bulut LLM'i yasaklayan bir kilit yok. **U-20, U-21** |
| 7 | UY, tedarikçi güvence paketini ister: SBOM, imzalı imaj, pentest, tehdit modeli, SDLC | ◐ | SBOM ve cosign `release.yml`'de var (`.github/workflows/release.yml:12-20`), ama belgeler hâlâ "Planlı" diyor. SECURITY.md eski (Vigil 0.5.x). Pentest bilinen eksik. **U-07, U-40, U-41** |

### A2. Satın alma ve sözleşme (HK, DPO)

| # | Story / adım | Durum | Kanıt / bulgu |
|---|---|---|---|
| 8 | HK, tedarikçinin kişisel veriye erişip erişmediğini belirler: destek paketi, uzaktan erişim | ◐ | `vigil-support` paketi sırları maskeliyor (`scripts/vigil-support/redact.awk`), kişisel veriyi maskelemiyor (IP/e-posta kuralı yok). Tedarikçiye gönderilen log, kullanıcı adı ve IP taşıyabilir. **U-42** |
| 9 | DPO, aydınlatma metni şablonu ister: SOC'nin çalışan ve müşteri verisini işlediğine dair | ❌ | `grep -rni aydınlatma` → yok. **U-12** |
| 10 | HK, sözleşme bitişinde veri iadesi ve imha prosedürünü sözleşmeye ekler | ❌ | `grep -rli "uninstall\|decommission\|veri iade"` → yalnızca `docs/operations/rpo-rto.md`. **U-50** |

### A3. Kurulum ve ilk açılış (UY'nin kurulum günü kanıtı)

| # | Story / adım | Durum | Kanıt / bulgu |
|---|---|---|---|
| 11 | UY, kurulumda K1 egress kanıtını ve K3 paket imzasını alır | ✅ | `tests/airgap/test_egress_inventory.py`, `test_runtime_egress.py`, `infra/airgap/install.sh verify` |
| 12 | Kurulum sihirbazı, denetim kontrol noktası imza anahtarını ve kanıt paketi anahtarını üretir ya da ister | ❌ | Setup ekranında anahtar adımı yok (`clients/web/src/screens/setup/*` → `grep -i checkpoint\|signing` → yok). Helm ve airgap değerlerinde anahtar alanı yok (`grep -rn CHECKPOINT\|EVIDENCE_PACK infra/helm infra/airgap` → yalnızca SQL). Sonuç: kontrol noktası yazılmaz, paketler geçici anahtarla imzalanır (`docs/guide/kapsam.md` W1.10 satırı; `evidence_bundle.py:22-25`). **U-13** |
| 13 | Sihirbaz saklama politikası, SIEM aktarımı ve "yalnız yerel model" tercihini sorar | ❌ | Kurulumda politika yok (`mevzuat-eslemesi.md:75` "kurulumda politika yoktur"). SIEM aktarımı varsayılan kapalı (`core/compliance/AUDIT_EXPORT.md:8`). **U-14** |
| 14 | Sihirbaz, bulut sağlayıcı seçilince veri yerleşimini gösterir | ✅ | `clients/web/src/screens/setup/providerResidency.ts:5-7` ("Hosted: data leaves your site") |

### A4. Günlük kullanım: denetim izi (İD, DD)

| # | Story / adım | Durum | Kanıt / bulgu |
|---|---|---|---|
| 15 | İD, her kullanıcı ve AI eyleminin değişmez kaydını görmek ister | ◐ | Zincire giren yalnızca `approval_actions`, `case_audit_logs` (`core/storage/audit_chain.py:30-33`) ve `agent_events`. Zincir dışında kalanlar: `config_audit_log`, `approval_decisions` (R6). Giriş, rol değişikliği ve kullanıcı oluşturma ise SIEM aktarımı açık değilse **hiç kaydedilmiyor** (`services/api/routers/users.py:546, 570, 595`; `_audit_on` = spool etkin mi). **U-15** |
| 16 | İD, LLM sağlayıcısı ekleyen, beceri, tespit kuralı ya da iş akışı değiştiren kişiyi bulmak ister | ❌ | `services/api/routers/llm_providers.py:167-206` (create; audit yok). `grep -c audit` sonucu: llm_providers, bifrost_config, skills, detection_rules, budgets ve custom_integrations için 0. `core/workflows/*` → ConfigAuditLog yok. **U-16** |
| 17 | İD, toplu veri dışa aktarımının (bulgu exportu) kaydını ister | ❌ | `services/api/routers/findings.py:239-258`: `POST /api/findings/export` girişli her rol için açık (Viewer dahil, `tests/security/route_role_matrix.json:2663-2669`). Kim aktardı, kayıt yok. **U-17** |
| 18 | İD, kişisel veriye salt okuma erişiminin kaydını ister | ❌ | Eşlemenin kendisi söylüyor: "salt okuma erişimleri kaydedilmez" (`mevzuat-eslemesi.md:77`). **U-18** |
| 19 | İD, konsolda genel denetim kaydı görüntüleme ve arama ister | ❌ | Var olan ekranlar yalnızca vaka Record sekmesi, Autonomy audit ve SoD (`grep -rli audit clients/web/src/screens`). `config_audit_log` için okuma API'si yok (`grep '@router.get(".*audit'` → yalnızca `core/autonomy/autonomy_router.py:179`). K6 "tablo" diyor, yani DB erişimi gerekiyor. **U-19** |
| 20 | DD, zinciri çevrimdışı doğrular | ◐ | `python -m core.audit.verify` canlı DB bağlantısı ister (`core/audit/verify.py:41-44`, `get_db_manager`). Tüm zincir için çevrimdışı dışa aktarım ve doğrulama yok. Vaka başına kanıt paketinde ve ajan defteri arşivinde var (`RETENTION.md` §5). **U-22** |
| 21 | DD, FIPS modunda imzaların onaylı algoritma olmasını bekler | ❌ (bilinen) | Ed25519 (`core/audit/checkpoint.py:1, 44-47`; R31) |
| 22 | UY, olayları SIEM'e aktarır | ◐ | W3.6 var. Varsayılan kapalı, `approval_decisions` aktarılmıyor, serbest metin maskelemesi en iyi çaba (R32). |
| 23 | UY, log saklama ve arşiv ister (BDDK ve DDO uzun süreli iz kaydı saklama bekler) | ◐ | `agent_events` için arşivle-sonra-kes yolu var (`RETENTION.md` §5, elle SQL). `audit_chain` için arşiv yok, sınırsız büyür. Auth spool boyutla sınırlı, 256 MB (`audit_export.py:268`). **U-23** |

### A5. Vaka kanıt paketi (DD, DÜZ)

| # | Adım | Durum | Kanıt / bulgu |
|---|---|---|---|
| 24 | Analist vaka için imzalı paket indirir, indirme vaka kaydına yazılır | ✅ | `core/compliance/evidence_router.py:7, 57`; `EvidencePackButton.tsx:53` geçici anahtar uyarısı |
| 25 | DD, paketi bağımsız doğrular (stdlib, ağsız) | ✅ | `core/compliance/verify_bundle.py:1-50`; `scripts/autosecops verify-bundle` |
| 26 | DÜZ ya da mahkeme Türkçe, insan okunur bir rapor (PDF) bekler | ❌ | README İngilizce (`evidence_bundle.py:108-130`), içerik yalnızca JSON. **U-24** |
| 27 | HK, imzanın hukuki geçerliliğini sorar: 5070 s. Kanun, nitelikli e-imza, zaman damgası | ❌ | Ed25519 öz-anahtar. Pakete TSA zaman damgası yok (TSA yalnızca kontrol noktalarında, isteğe bağlı: `core/audit/tsa.py`; `grep -i tsa evidence_bundle.py` → yok). **U-25** |
| 28 | DD, paketin içeriğini kontrol eder: vaka, bulgu, kanıt, denetim, eylem, defter, AI kökeni, saat | ✅ | `evidence_bundle.py:3-20`. Sohbet ve LLM istem kayıtları pakette yok (ai_provenance yalnızca karar). |

### A6. Düzenleyici saatler ve bildirim (UY, DÜZ)

| # | Adım | Durum | Kanıt / bulgu |
|---|---|---|---|
| 29 | UY, KVKK veri ihlali saatini (farkına varma + 72 saat, Kurul Kararı 2019/10) ve ilgili kişilere bildirimi başlatır | ❌ | `core/compliance/clocks.py:39` `REGIMES = ("dora", "nis2")` |
| 30 | UY, BDDK ve USOM/SOME (7545 s. Kanun sonrası Siber Güvenlik Başkanlığı) bildirim saatlerini başlatır | ❌ | aynı yer. **U-26** |
| 31 | UY, Türkçe bildirim taslağı üretir (KVKK Veri İhlali Bildirim Formu alanları) | ❌ | Taslaklar yalnızca DORA ve NIS2, İngilizce (`core/compliance/regulatory_drafts.py:39-52`). **U-27** |
| 32 | UY, vakayı "kişisel veri ihlali" olarak işaretler: etkilenen kişi sayısı, veri kategorileri | ❌ | `grep -rni "personal_data\|kişisel veri" core/cases core/storage/models` → yok. **U-28** |
| 33 | Saatler vaka yan panelinde görünür | ✅ | `clients/web/src/screens/cases/RegulatoryClocks.tsx` (W3.8) |
| 34 | Saat gecikince uyarı gider | ❌ | W3.8 non-goal (`docs/wp/w3.8.md` Non-goals). Süre yapılandırmasının ekranı da yok. **U-29** |

### A7. İlgili kişi hakları (DPO) — KVKK md. 11 ve 13 (30 gün)

| # | Adım | Durum | Kanıt / bulgu |
|---|---|---|---|
| 35 | DPO, bir kişinin (kullanıcı adı, e-posta, IP) tüm verisini alarm, vaka, sohbet, LLM kaydı, epizodik bellek, ders, defter ve yedeklerde bulur | ❌ | `grep -rni "data.subject\|dsar\|erasure\|ilgili kişi"` → yok. Epizodik bellek varlık anahtarlıdır (`infra/database/init/26_episodic_memory.sql:24`). Yalnızca `recall_entity` aracı var. **U-30** |
| 36 | DPO, kişinin verisini dışa aktarır (erişim hakkı) | ❌ | aynı. **U-30** |
| 37 | DPO, kişinin verisini siler ya da anonimleştirir (yasal saklama dışında) | ❌ | Saklama yalnızca yaşa göre çalışır (`core/compliance/retention.py:161, 1042-1049`). Kişiye göre silme yok. **U-30** |
| 38 | DPO, silme ile değişmez denetim kaydını uzlaştırır | ❌ | `audit_chain.payload` satırın tam JSON kopyasını tutar (`infra/database/init/51_audit_chain.sql:234-246`, `to_jsonb(OLD/NEW)`). `case_audit_logs` anonimleştirilse bile kişisel veri zincirde kalır ve imha kodu zincire dokunmaz (`retention.py:23, 73`). **U-31** |
| 39 | DPO, otomatik karara itiraz hakkını (md. 11/1-g) uygular: AI kaynaklı hesap kapatma | ◐ | Varsayılan Approve, kimlik eylemlerinde dört göz onayı (`kapsam.md` W3.1, W2.4). Belgede eşleme yok. **U-45** |

### A8. Veri minimizasyonu ve LLM veri akışı (DPO, UY)

| # | Adım | Durum | Kanıt / bulgu |
|---|---|---|---|
| 40 | DPO, istemden önce kişisel verinin maskelenmesini ister | ❌ | `grep -rni "redact\|mask\|pii\|pseudonym" services/daemon core/llm core/federation` → yalnızca açıklamalar (`core/llm/system_prompt.py:35`). Alarm içeriği olduğu gibi gider (R15). **U-32** |
| 41 | UY, "bulut LLM yasak" politikası ister: uygulama içinde zorlanan, değiştirilmesi denetlenen | ❌ | `AIRGAP_EGRESS_ALLOWLIST` yalnızca testlerde okunur (`tests/airgap/guard/sitecustomize.py:44`). Admin, konsoldan bulut sağlayıcı ekleyebilir (`llm_providers.py:167-206`, residency yalnızca etiket). **U-20, U-21** |
| 42 | UY, egress olmadığını kanıtlar | ✅ / ◐ | K1 testleri var. Yalnızca Python süreçleri çalışma zamanında izleniyor (W3.4 non-goal: Bifrost, Node, web statik). R16 ve R23 kayıtlı. |
| 43 | DPO, istem ve yanıt kayıtlarının nerede, ne kadar tutulduğunu bilir | ◐ | `llm_interaction_logs` tam istem, yanıt ve thinking tutar (`core/storage/models/ai.py:117-124`). `llm_logs` sınıfı var ama varsayılan politika yok, yani sonsuz saklama. Bifrost `logs.db` kapsam dışı (R7, "Düşük" etiketli; KVKK açısından düşük değil). **U-33** |

### A9. Saklama ve imha (DPO, İD)

| # | Adım | Durum | Kanıt / bulgu |
|---|---|---|---|
| 44 | DPO, veri sınıfı başına süre tanımlar | ◐ | 9 sınıf var (`retention.py:161`). Kapsamda olmayanlar: epizodik bellek (`episodic_*`), `lessons`, `approval_actions`, `approval_decisions`, `workflow_runs`, `agent_events` (yalnızca arşiv), `audit_chain`, Redis, Bifrost `logs.db`, auth spool, `exports/` dizini. Epizodik bellekte yalnızca read log temizleniyor (`core/memory/recall.py:189, 509`). **U-34** |
| 45 | DPO, politikayı konsoldan yönetir | ❌ (bilinen R8) | Yalnızca API. `DataUploadsSection.tsx:10-12` "NotMeasured". |
| 46 | İD, imha tutanağı alır | ✅ / ◐ | `GET /api/compliance/retention/reports` Türkçe Markdown üretir (`retention.py:1452-1457`). İmzasız ve zincirsiz. Plan "her silmenin zincirli denetim kaydı" diyordu (`docs/wp/NORTHSTAR_PLAN.md:270`). **U-35** |
| 47 | DPO, yedeklerin de saklama süresine uyduğunu gösterir | ❌ | restic `--keep-last 14` (`core/backup/schedule.py:46, 316-320`), yaşa dayalı değil. Uzak depo bucket kuralına bırakılmış (`:303`). Geri yükleme, imha edilmiş veriyi geri getirir ve imhayı yeniden uygulamaz (`grep -i "retention\|purge" core/backup/restore.py` → yok). **U-36** |

### A10. Erişim kontrolü kanıtı (İD)

| # | Adım | Durum | Kanıt / bulgu |
|---|---|---|---|
| 48 | İD, periyodik erişim gözden geçirme dışa aktarımı ister: kullanıcı, rol, MFA, son giriş (CSV) | ◐ | `GET /api/users/` yalnızca JSON (`users.py:224`). CSV, imza ve onay akışı yok. **U-37** |
| 49 | İD, ayrıcalıklı erişim kaydını ister: kim kime Admin verdi | ❌ | U-15 ile aynı (spool'a bağlı). R13: DB'deki rol izin değişimi kaydedilmez. |
| 50 | İD, görevler ayrılığı raporunu alır | ✅ | `GET /api/response/segregation/export?format=csv` (W3.2) |
| 51 | İD, ayrıcalıklı hesaplarda MFA'nın zorunlu olduğunu görür | ❌ (R9) | MFA bir rol için zorunlu kılınamaz. **U-38** |

### A11. Değişiklik yönetimi kanıtı (İD)

| # | Adım | Durum | Kanıt / bulgu |
|---|---|---|---|
| 52 | Ayar, AI model ataması, otonomi ve SoD değişikliklerinin eski ve yeni değeri | ✅ | `core/storage/config_service.py:340-343`, `services/api/routers/ai_config.py:139-142`, `core/autonomy/store.py`, `core/response/segregation_router.py` |
| 53 | Prompt değişikliği | ◐ | Özel ajan prompt değişiklikleri kaydediliyor (`core/agents/custom_agent_service.py`). Yerleşik prompt'lar koda gömülü, her kararda `prompt_version` var (W1.2). Beceri (skill), iş akışı ve tespit kuralı değişiklikleri kaydedilmiyor (U-16). |
| 54 | Sürüm ve yükseltme kaydı: kim, ne zaman, hangi sürümden hangisine | ◐ | Sürüm notları ve `docs/release/dogrulama.md` var. Pre-upgrade yedek manifesti sürümü taşıyor (`core/backup/preupgrade.py:1-7`). Ürün içinde yükseltme geçmişi tablosu ya da denetim kaydı yok (`grep -rni "upgrade_history\|version_history"` → yok). **U-39** |

### A12. Şifreleme (UY, DD)

| # | Adım | Durum | Kanıt / bulgu |
|---|---|---|---|
| 55 | DB'nin durağan halde şifrelenmesi | ◐ | Ürün sağlamıyor, platforma bırakıyor. Belgede açıkça yazmıyor (`guvenlik-teknik-belgesi.md` §8'de "durağan DB" satırı yok). Helm CronJob dökümü şifresiz (R17). |
| 56 | Servisler arası TLS | ❌ | `postgres_ssl_mode = "prefer"` (`core/config.py:167`), yani sertifika doğrulaması yok. Redis, Bifrost ve agent düz `http://`/`redis://` (`infra/airgap/airgap.env` "Internal services"). **U-43** |
| 57 | HSM / PKCS#11 ile imza ve anahtar yönetimi | ❌ | `grep -rni "pkcs11\|hsm"` → yalnızca `kurulum-internetsiz.md:64` (paket imzalama makinesi önerisi). Kontrol noktası ve kanıt anahtarları Fernet deposunda, `master.key` yanında (R18). **U-44** |
| 58 | FIPS modu | ◐ (bilinen) | `docs/fips.md`. Ed25519 boşluğu (R31). |

### A13. AI yönetişimi (UY, HK, DÜZ)

| # | Adım | Durum | Kanıt / bulgu |
|---|---|---|---|
| 59 | UY, model davranış belgesi ister: model kartı, sınırlar, insan gözetimi | ◐ | QA karnesi, kanaryalar ve otonomi katmanları var (K12, K17). Model kartı ya da AI sistem belgesi yok (`grep -rli "model card\|ai act"` → yalnızca NORTHSTAR). **U-45** |
| 60 | HK, EU AI Act, KVKK Yapay Zekâ Tavsiyeleri (2021) ve Ulusal YZ Stratejisi eşlemesini ister | ❌ | aynı. **U-45** |
| 61 | DD, insan gözetiminin kanıtını ister | ✅ | `approval_decisions`, SoD raporu, otonomi audit; model onay veremez (W1.7b) |
| 62 | DD, prompt-injection dayanıklılığının kanıtını ister | ◐ (bilinen W1.4) | 21/240 taban, kapı değil (R1) |

### A14. Yenileme ve sözleşme bitişi (HK, DPO)

| # | Adım | Durum | Kanıt / bulgu |
|---|---|---|---|
| 63 | HK, tüm verinin taşınabilir biçimde dışa aktarılmasını ister | ❌ | Toplu dışa aktarım yalnızca bulgular için (`findings.py:239`). Vakalar ve denetim kayıtları için tam export yok. **U-50** |
| 64 | DPO, kaldırma sonrası imha tutanağı ister: PVC, yedek, sır deposu, Bifrost, Ollama, spool | ❌ | prosedür yok. **U-50** |
| 65 | HK, tedarikçide kopya kalmadığının beyanını ister: destek paketleri | ❌ | U-42, U-50 |

---

## B. Mevzuat eşlemesi: kapsam ve doğruluk denetimi

| Düzenleme / konu | Eşlemede var mı | Ürün kontrolü gerçekte | Not |
|---|---|---|---|
| KVKK md. 4 ve 7, İmha Yönetmeliği | Var, "Karşılanıyor/Kısmi" | 9 sınıf; epizodik bellek, ders, onay, `audit_chain`, Bifrost ve yedek kapsam dışı | md. 4 satırı "Karşılanıyor" (`:75`) fazla iyimser → U-06 |
| KVKK md. 9 (2024 değişikliği: standart sözleşme, 5 iş günü bildirim, arızi aktarım) | Eski metin | Bulut sağlayıcı kilidi yok, maskeleme yok | U-04, U-20, U-32 |
| KVKK md. 10 aydınlatma | Yok | — | U-12 |
| KVKK md. 11 ve 13 ilgili kişi hakları | Yok | Yok | U-30 |
| KVKK md. 12/5 ve Kurul 2019/10 (72 saat ihlal bildirimi) | Yok | Saat yok | U-26 |
| VERBİS ve envanter | Yok | — | U-10 |
| Kişisel veriye erişim kaydı (Kurul Teknik ve İdari Tedbirler Rehberi) | "Kısmi" | Okuma kaydı yok; giriş kaydı spool'a bağlı | U-15, U-18 |
| BDDK BS Yönetmeliği: yurt içi, iz kaydı, değişiklik yönetimi, olay bildirimi | Kısmi; madde no yok | Olay bildirim saati yok; iz kaydında boşluklar var | U-04, U-15, U-16, U-26 |
| BDDK Destek Hizmetleri Yönetmeliği; Bankacılık Kanunu md. 73 (sır) | "Dış hizmet: Karşılanıyor (air-gap)" | Bulut LLM ve tedarikçi desteği değerlendirilmemiş | U-11, U-20, U-42 |
| SPK VII-128.9 | Var, madde no yok | — | U-04 |
| CBDDO Bilgi ve İletişim Güvenliği Rehberi (kamu için zorunlu) | **Yok** | — | U-01 |
| 7545 s. Siber Güvenlik Kanunu (2025): bildirim, yerli depolama, ürün belgelendirme | **Yok** | — | U-02 |
| USOM / SOME bildirimi | Yok | — | U-26 |
| EPDK / BTK sektörel siber güvenlik düzenlemeleri | Yok | — | U-03 |
| ISO 27001 Ek A | Var (21 kontrol) | A.5.21 "SBOM Planlı" eskimiş; A.8.32 eksik kapsamı yazmıyor; A.8.10 "Karşılanıyor" fazla iyimser; A.5.34 için DSAR anılmıyor | U-07, U-08, U-06 |
| EU AI Act | Yok | — | U-45 |
| DORA / NIS2 | Var | Saatler ve taslaklar var (İngilizce) | AB'de faaliyet gösteren banka için yeterli |

---

## C. Bulgular

| ID | Persona | Flow adımı | Eksik (ne yok / ne yanlış) | Kanıt | Önem | Sahip | Tahmini efor |
|---|---|---|---|---|---|---|---|
| U-01 | UY, DÜZ (kamu) | A1.1 mevzuat eşlemesi | CBDDO Bilgi ve İletişim Güvenliği Rehberi eşlemesi yok. Rehber kamu kurumları ve kritik altyapı için zorunlu; kurum uyum denetiminde ürünün tedbir eşlemesini ister. | `grep -rni "rehber\|ddo\|dijital dönüşüm" docs/guide` → yok | SATIŞ-ENGELİ (kamu) | Uyum | M |
| U-02 | HK, DÜZ | A1.1 | 7545 s. Siber Güvenlik Kanunu (Mart 2025) hiç anılmıyor: olay bildirimi, verinin yurt içinde tutulması ve kamu ile kritik altyapıda siber güvenlik ürünlerinin belgelendirme/yetkilendirme şartı. İkincil düzenleme yürürlükteyse belgesiz ürün kamuya ve kritik altyapıya satılamaz (hukukça teyit). | `grep -rn 7545 docs` → yok | SATIŞ-ENGELİ (kamu/KA, teyide bağlı) | Hukuk | M (analiz) / L (belgelendirme) |
| U-03 | UY | A1.1 | EPDK ve BTK sektörel siber güvenlik düzenlemeleri eşlenmemiş: enerji ve telekom müşterileri | `grep -rni "epdk\|btk" docs` → yok | YÜKSEK | Uyum | M |
| U-04 | HK | A1.2 | BDDK ve SPK satırlarında madde numarası yok. KVKK md. 9 satırı 2024 değişikliğini anmıyor: standart sözleşme, 5 iş günü içinde Kurul'a bildirim, arızi aktarım şartları. Bulut LLM seçen müşteri için yanıltıcı. | `mevzuat-eslemesi.md:57-69, 74, 108-117` | GA-ENGELİ | Hukuk | S |
| U-05 | İD | A1.3 | "Yetkili kullanıcı işlemlerinin kayıt altına alınması — **Karşılanıyor**" yanlış. Rol değişikliği, kullanıcı oluşturma/silme ve giriş olayları yalnızca SIEM aktarım spool'u açıksa kaydediliyor. | `mevzuat-eslemesi.md:63`; `users.py:546, 570, 595` | GA-ENGELİ (belge düzeltmesi S; asıl düzeltme U-15) | Uyum | S |
| U-06 | DPO | A1.3 | KVKK md. 4 ve ISO A.8.10 "Karşılanıyor" fazla iyimser. Epizodik bellek, ders, onay, `audit_chain`, Bifrost `logs.db` ve yedekler imha kapsamında değil. | `mevzuat-eslemesi.md:75, 131`; `retention.py:161`; `RETENTION.md:141` | YÜKSEK | Uyum | S |
| U-07 | UY, DD | A1.7 | SBOM ve imzalı imajlar W4.7 ile birleşti, ama eşleme (A.5.21, NIS2 tedarik zinciri), kapsam, güvenlik belgesi §9 ve R21 hâlâ "Planlı — bu sürümde yok" diyor. Belge tabanı `b8795def`'te kalmış. | `kapsam.md:31, 139`; `guvenlik-teknik-belgesi.md:487`; `tehdit-modeli.md:188`; `release.yml:12-20`; `STATUS.md` W4.7 PASS | GA-ENGELİ | Uyum | S |
| U-08 | İD | A1.3 | A.8.32 Değişiklik yönetimi yalnızca "rol izinleri" boşluğunu yazıyor. LLM sağlayıcı, beceri, iş akışı, tespit kuralı, bütçe ve özel entegrasyon değişikliklerinin kaydedilmediğini yazmıyor. | `mevzuat-eslemesi.md:138`; U-16 kanıtı | YÜKSEK | Uyum | S |
| U-09 | UY | A1.3 | K6 "`config_audit_log` tablosu" denetçiyi DB erişimine yönlendiriyor; API ya da ekran yok | `mevzuat-eslemesi.md:37`; U-19 | ORTA | Uyum | S |
| U-10 | DPO | A1.4 | Kişisel veri envanteri yok: tablo × veri kategorisi × ilgili kişi grubu (çalışan, müşteri) × amaç × alıcı (LLM sağlayıcı, SIEM) × varsayılan saklama. VERBİS ve kurum envanteri bu olmadan doldurulamaz. | `grep -rni verbis` → yalnızca `RETENTION.md:5` | SATIŞ-ENGELİ (banka KVKK onboarding) | Uyum | M |
| U-11 | HK | A1.5 | Veri işleyen sözleşmesi ve BDDK destek hizmeti sözleşme ekleri yok: denetim hakkı, sır saklama, alt işleyen listesi (LLM sağlayıcı), yurt içi kalma. Lisans yalnızca Apache-2.0. | `LICENSE:1-3`; `grep -rli "eula\|veri işleyen"` → yok | SATIŞ-ENGELİ | Hukuk | M |
| U-12 | DPO, HK | A2.9 | İzlenen çalışanlar için aydınlatma metni şablonu yok: SOC'de AI ile işleme, yurt dışı aktarım seçeneği | `grep -rni aydınlatma` → yok | ORTA | Hukuk | S |
| U-13 | UY, DD | A3.12 | Kurulumda denetim kontrol noktası ve kanıt paketi imza anahtarı üretilmiyor ve istenmiyor. Helm ve airgap değerlerinde alan yok. Varsayılan kurulumda kontrol noktası yazılmıyor, paketler geçici anahtarla imzalanıyor, dolayısıyla "imzalı denetim izi" kurulum günü yok. | `grep -rn "CHECKPOINT\|EVIDENCE_PACK" infra/helm infra/airgap` → yalnızca SQL; `evidence_bundle.py:22-25`; `kapsam.md` W1.10 satırı | GA-ENGELİ | Mühendislik | M |
| U-14 | UY | A3.13 | İlk açılış sihirbazında uyum adımı yok: saklama politikası şablonu (ör. bankacılık önerisi), SIEM aktarımı, "yalnız yerel model" seçimi. Ürün kutudan "politikasız ve sonsuz saklama" ile çıkıyor. | `setupSteps.ts`; `mevzuat-eslemesi.md:75` | YÜKSEK | Ürün | M |
| U-15 | İD, DÜZ | A4.15, A10.49 | Kimlik doğrulama ve kullanıcı yönetimi olayları (giriş, başarısız giriş, kilitleme, rol değişikliği, kullanıcı oluşturma/silme, MFA kapatma) kalıcı ve DB'de bir denetim kaydına yazılmıyor. Yalnızca W3.6 aktarımı açıkken dosya spool'una yazılıyor. BDDK ve SPK iz kaydı ile ISO A.8.15 için temel kontrol. | `users.py:72-76, 546, 570, 595`; `AUDIT_EXPORT.md:8, 17` | SATIŞ-ENGELİ (banka denetimi: ayrıcalıklı işlem kaydı) | Mühendislik | M |
| U-16 | İD | A4.16, A11.53 | LLM sağlayıcı ekleme/değiştirme (yurt dışı aktarımı başlatan işlem), Bifrost ayarı, beceri, iş akışı, tespit kuralı, bütçe ve özel entegrasyon değişiklikleri `config_audit_log`'a yazılmıyor | `llm_providers.py:167-206`; `grep -c audit` = 0 (llm_providers, bifrost_config, skills, detection_rules, budgets, custom_integrations); `core/workflows` ConfigAuditLog yok | GA-ENGELİ | Mühendislik | M |
| U-17 | İD, DPO | A4.17 | `POST /api/findings/export`: tüm bulgular, Viewer dahil her rol, aktör kaydı yok. Toplu kişisel veri sızdırma yolu, KVKK md. 12. | `findings.py:239-258`; `route_role_matrix.json:2663-2669`; `auth_only_write_routes.txt:32` | YÜKSEK | Mühendislik | S |
| U-18 | DPO, İD | A4.18 | Kişisel veri içeren kayıtlara (vaka, bulgu, sohbet, LLM kaydı) okuma erişimi kaydedilmiyor | `mevzuat-eslemesi.md:77` | YÜKSEK | Mühendislik | M |
| U-19 | İD | A4.19 | Konsolda genel denetim kaydı görüntüleyici ve arama yok. `config_audit_log` için okuma API'si yok. | `grep -rn '@router.get(".*audit'` → yalnızca autonomy; `clients/web/src/screens` | YÜKSEK | Mühendislik | M |
| U-20 | UY, DÜZ (BDDK) | A1.6, A8.41 | Uygulama içinde "bulut LLM yasak / veri yurt içinde" kilidi yok. Admin konsoldan yurt dışı sağlayıcı ekleyebilir. Air-gap profili yalnızca kurulum yapılandırması, NetworkPolicy yalnızca uygun CNI'da etkili (R16). Bankacılık Kanunu md. 73 ve BDDK yurt içi şartı açısından kilit kurumca gösterilebilir olmalı. | `tests/airgap/guard/sitecustomize.py:44` (allowlist yalnız test); `llm_providers.py:167` | YÜKSEK | Mühendislik | M |
| U-21 | UY | A8.41 | Bulut sağlayıcı seçiminin denetim kaydı yok (U-16'nın KVKK md. 9 boyutu): yurt dışı aktarımın başladığı anı kanıtlayan kayıt yok | U-16 kanıtı | GA-ENGELİ (U-16 ile birlikte kapanır) | Mühendislik | S |
| U-22 | DD | A4.20 | Tüm denetim zincirinin çevrimdışı doğrulanması için dışa aktarma + doğrulama yok. `core.audit.verify` canlı DB ve ürün Python ortamı ister. Denetçiye DB erişimi verilmesi gerekir. | `core/audit/verify.py:41-44` | YÜKSEK | Mühendislik | M |
| U-23 | UY | A4.23 | `audit_chain` için arşivle-sonra-kes ve saklama süresi yok, sınırsız büyür. `agent_events` kesimi elle SQL ile yapılıyor. Auth spool boyutla sınırlı. | `RETENTION.md` §5; `retention.py:73`; `audit_export.py:268` | ORTA | Mühendislik | M |
| U-24 | DD, DÜZ | A5.26 | Kanıt paketinde Türkçe, insan okunur özet rapor (PDF/HTML) yok; README İngilizce | `evidence_bundle.py:108-130` | YÜKSEK | Ürün | M |
| U-25 | HK | A5.27 | Paket imzası 5070 s. Kanun anlamında güvenli e-imza değil; nitelikli zaman damgası yok. Delil değeri tartışmaya açık. ESHS TSA ile RFC 3161 damgası ya da kurum e-imzasıyla ikinci imza seçeneği yok. | `evidence_bundle.py:20`; `grep -i tsa evidence_bundle.py` → yok | YÜKSEK | Mühendislik | M |
| U-26 | UY, DÜZ | A6.29-30 | Türk düzenleyici saatleri yok: KVKK ihlali (72 saat, Kurul'a + ilgili kişiye), BDDK olay bildirimi, USOM/SOME (7545 sonrası Başkanlık), SPK. Yalnızca DORA ve NIS2 var. Türkiye'yi hedefleyen "düzenleyici saat" özelliği Türk müşteri için boş. | `clocks.py:39, 108-114` | GA-ENGELİ | Mühendislik + Hukuk (süreler) | M |
| U-27 | UY | A6.31 | Türkçe bildirim taslakları yok: KVKK Veri İhlali Bildirim Formu alanları, BDDK ve USOM formları. Taslak başlıkları ve "To complete" listesi İngilizce. | `regulatory_drafts.py:39-80` | GA-ENGELİ | Ürün | M |
| U-28 | DPO | A6.32 | Vakada "kişisel veri ihlali" işareti ve alanları yok: etkilenen kişi sayısı, veri kategorileri, özel nitelikli veri | `grep -rni "personal_data\|kişisel veri" core/cases core/storage/models` → yok | YÜKSEK | Mühendislik | M |
| U-29 | UY | A6.34 | Saat gecikme uyarısı (e-posta/webhook) ve süre yapılandırma ekranı yok | `docs/wp/w3.8.md` Non-goals | ORTA | Mühendislik | S |
| U-30 | DPO | A7.35-37 | İlgili kişi hakları aracı yok: bir kişinin verisini tüm depolarda bulma, dışa aktarma, silme/anonimleştirme. Depolar: bulgu, vaka, sohbet, LLM kaydı, epizodik bellek, ders, onay, defter. Yedekler için belgelenmiş bir yöntem de yok. 30 günlük yanıt süresi (md. 13) ürünle karşılanamaz. | `grep -rni "dsar\|data.subject\|erasure"` → yok; `retention.py:1042-1049` yalnızca yaşa göre | SATIŞ-ENGELİ (DPO veto) | Mühendislik + Uyum | L |
| U-31 | DPO, HK | A7.38 | Değişmez zincir ile silme hakkı uzlaştırılmamış. `audit_chain.payload` kaynak satırın tam JSON kopyasını tutar. Kaynak anonimleştirilince kişisel veri zincirde süresiz kalır. Hukuki dayanak (md. 5/2-ç) ve saklama süresi belgelenmemiş. Hash-yalnız zincir ya da kriptografik silme seçeneği yok. | `51_audit_chain.sql:234-246`; `retention.py:23, 73` | YÜKSEK | Mühendislik + Hukuk | L |
| U-32 | DPO | A8.40 | İstemden önce kişisel veri maskeleme ve takma adlandırma (pseudonymisation) yok; bulut sağlayıcıya alarm içeriği olduğu gibi gider (R15) | `grep -rni "redact\|mask\|pseudonym" services/daemon core/llm core/federation` → yok | YÜKSEK | Mühendislik | L |
| U-33 | DPO | A8.43 | İstem ve yanıt kayıtları tam metinle süresiz tutuluyor (politika yoksa). Bifrost `logs.db` saklama dışında (R7, KVKK için "Düşük" değil). Bulut sağlayıcı tarafındaki saklama (zero-retention seçenekleri) belgelenmemiş. | `core/storage/models/ai.py:117-124`; `tehdit-modeli.md:174` | YÜKSEK | Mühendislik + Uyum | M |
| U-34 | DPO | A9.44 | İmha kapsamında olmayan kişisel veri depoları: `episodic_sightings/verdicts/...`, `lessons`, `approval_actions`, `approval_decisions`, `workflow_runs`, `exports/` dosyaları, auth spool, Redis | `retention.py:161`; `26_episodic_memory.sql:24-167`; `recall.py:189` (yalnızca read log) | YÜKSEK | Mühendislik | M |
| U-35 | İD | A9.46 | İmha tutanağı ve imha kayıtları (`config_audit_log`, `config_type='retention'`) zincirsiz ve imzasız. Plan "her silmenin zincirli denetim kaydı" demişti. | `NORTHSTAR_PLAN.md:270`; R6 | YÜKSEK | Mühendislik | M |
| U-36 | DPO | A9.47 | Yedekler saklama süresine uymuyor: restic yaşa göre değil adede göre siliyor, uzak depolar bucket kuralına kalıyor. Geri yükleme sonrası imha yeniden uygulanmıyor, imha edilmiş veri geri gelir. Belgede yalnızca "ayrı süreç" deniyor. | `schedule.py:46, 303, 316-320`; `restore.py` (retention yok); `RETENTION.md:141` | YÜKSEK | Mühendislik | M |
| U-37 | İD | A10.48 | Erişim gözden geçirme raporu (CSV/PDF, dönem, onaylayan) yok; yalnızca JSON kullanıcı listesi var | `users.py:224` | ORTA | Mühendislik | S |
| U-38 | İD, DÜZ | A10.51 | Ayrıcalıklı roller için MFA zorunlu kılınamıyor (R9). BDDK ve DDO güçlü kimlik doğrulama bekler; yalnızca SSO ile IdP'de telafi ediliyor. | `tehdit-modeli.md:176` | YÜKSEK | Mühendislik | M |
| U-39 | İD | A11.54 | Ürün içinde yükseltme ve sürüm geçmişi kaydı (kim, ne zaman, hangi sürümden hangisine) yok | `grep -rni "upgrade_history\|version_history"` → yok; `preupgrade.py:1-7` | ORTA | Mühendislik | S |
| U-40 | UY, DD | A1.7 | SECURITY.md eski: "Vigil is pre-1.0", 0.5.x, `vigilsoc.org`, `Vigil-SOC/vigil` advisory adresi. AutoSecOps 2.0 için tedarikçi zafiyet bildirimi ve destek penceresi beyanı yanlış. | `SECURITY.md:3-25, 56` | GA-ENGELİ | Satış-Pazarlama + Mühendislik | S |
| U-41 | UY | A1.7 | İmaj imzası keyless (Fulcio/Rekor). İnternetsiz müşteri için çevrimdışı doğrulama (`--offline`, Sigstore bundle, güvenilir kök) belgelenmemiş. OS düzeyinde düzeltilmemiş HIGH zafiyetler var (backend 58, daemon 48, agent 53, zlib CRITICAL): VEX ya da istisna beyanı yok. | `SECURITY.md:29-41`; `STATUS.md` §4 W0.22/23 | YÜKSEK | Mühendislik | M |
| U-42 | HK, DPO | A2.8 | Destek paketi (`vigil-support`) sırları maskeliyor ama kişisel veriyi (IP, e-posta, kullanıcı adı) maskelemiyor. Tedarikçiye aktarım veri işleyen ilişkisi doğurur; paket adı da hâlâ "vigil". | `scripts/vigil-support/README.md:3`; `redact.awk` | ORTA | Mühendislik + Hukuk | S |
| U-43 | UY, DD | A12.56 | Servisler arası TLS yok ya da doğrulanmıyor: Postgres `sslmode=prefer`; Redis, Bifrost ve agent düz metin. BDDK ve DDO "iletimde şifreleme" sorusunda açık. | `core/config.py:167`; `infra/airgap/airgap.env` (Internal services); `values.yaml:299, 498` | YÜKSEK | Mühendislik | M |
| U-44 | UY | A12.57 | HSM/PKCS#11 desteği yok: imza anahtarları yazılımda, `master.key` sır deposuyla aynı yerde ve döndürme yok (R18). Durağan DB şifrelemesinin platforma ait olduğu belgede açıkça yazmıyor. | `guvenlik-teknik-belgesi.md:380-450` | YÜKSEK | Mühendislik | L |
| U-45 | UY, HK | A7.39, A13.59-60 | AI yönetişim paketi yok: model kartı ya da sistem belgesi (kullanılan modeller, sınırlar, prompt sürümleri, eval sonuçları), EU AI Act ve KVKK YZ Tavsiyeleri eşlemesi, otomatik karara itiraz (md. 11/1-g) eşlemesi. Kanıtın kendisi (karne, onay, otonomi audit) var. | `grep -rli "model card\|ai act"` → yok | YÜKSEK | Uyum + Ürün | M |
| U-46 | UY | A6.30 | Bilinen: kontrol noktası ve kanıt paketi imzası FIPS'te Ed25519 (R31). Listede sayıldı. | `checkpoint.py:44-47` | (bilinen) | Mühendislik | — |
| U-47 | İD | A4.15 | Bilinen: `config_audit_log` ve `approval_decisions` zincirsiz (R6); `approval_decisions` SIEM'e gitmiyor. Listede sayıldı. | `audit_chain.py:30-33` | (bilinen) | Mühendislik | — |
| U-48 | DPO | A9.45 | Bilinen: saklama konsol ekranı yok, imha işi varsayılan kapalı, elle silme tutanağa girmiyor (R8). | `DataUploadsSection.tsx:10-12` | (bilinen) | Mühendislik | — |
| U-49 | UY | A1.7 | Bilinen: dış pentest yok (W4.4). Tedarikçinin ISO 27001 ve SOC 2 sertifikası yok (`NORTHSTAR_PLAN.md:189`). Banka TPRM anketinde telafi beyanı hazırlanmalı. | `NORTHSTAR_PLAN.md:189` | YÜKSEK (sertifika beyanı) | Uyum | S |
| U-50 | HK, DPO | A14.63-65 | Sözleşme bitişi süreci yok: tüm veri için dışa aktarma (vaka, denetim zinciri, defter arşivi), kaldırma runbook'u (PVC, yedek, `secrets.enc`/`master.key`, Bifrost, Ollama, spool, `exports/`), imha tutanağı şablonu, tedarikçi kopya beyanı. Bankanın destek hizmeti bitiş maddesi için gerekli. | `grep -rli "uninstall\|decommission"` → yalnızca `rpo-rto.md` | YÜKSEK | Mühendislik + Hukuk | M |
| U-51 | UY | A1.1 | Kılavuzlar ve konsol İngilizce: konsol metinleri, kanıt README, taslaklar. Kamu ve banka denetim çıktıları Türkçe bekler. Mevzuat belgeleri Türkçe. | `providerResidency.ts:5-7`; `regulatory_drafts.py:44` | YÜKSEK | Ürün | L |
| U-52 | UY | A4.22 | SIEM aktarımı varsayılan kapalı ve serbest metin maskelemesi en iyi çaba (R32, bilinen). U-15 nedeniyle bu "isteğe bağlı" özellik fiilen zorunlu hale geliyor; kurulum kılavuzunda banka için "açık olmalı" denmeli. | `AUDIT_EXPORT.md:8` | ORTA | Uyum | S |

---

## D. Var ve çalışıyor görünüyor

- **Hash zinciri ve imzalı kontrol noktası** (W1.10): `approval_actions` ve `case_audit_logs` üzerinde tetikleyiciyle doldurulan tek zincir; TRUNCATE, UPDATE ve DELETE engeli; Ed25519 kontrol noktaları, dosya kopyası ve isteğe bağlı RFC 3161 TSA; `python -m core.audit.verify --require-signature` (`core/audit/*`, `51_audit_chain.sql`).
- **Ajan defteri**: koşu başına zincir, `vigil_app` rolüne UPDATE/DELETE yok, zinciri doğrulanan arşiv dışa aktarımı (`RETENTION.md` §5).
- **Vaka kanıt paketi** (W3.7): imzalı manifest, bağımlılıksız çevrimdışı doğrulayıcı, katı ZIP okuma, indirme kaydı, geçici anahtar uyarısı (`evidence_bundle.py`, `verify_bundle.py`, `EvidencePackButton.tsx:53`).
- **DORA ve NIS2 saatleri** (W3.8): DST ve ay aritmetiği, zincirli an kaydı, gerekçe zorunluluğu, atıf doğrulamalı taslak, vaka yan paneli.
- **Saklama ve imha** (W3.5): 9 sınıf, delete/anonymise, vaka ve sınıf düzeyinde yasal saklama, advisory lock, cascade denetimi, kuru çalıştırma varsayılanı, Türkçe Markdown imha tutanağı.
- **SIEM aktarımı** (W3.6): syslog TLS, HTTPS JSON ve CEF; en az bir kez teslim, kalıcı imleç, imzalı kontrol noktalarının SIEM'e gitmesi, egress koruması.
- **Görevler ayrılığı raporu** (CSV), dört göz onayı, model onay veremez (W1.7b), otonomi katmanları varsayılan Approve ve audit.
- **Ayar değişikliği kaydı** (eski ve yeni değer, gerekçe): genel config, AI model ataması, otonomi, SoD, saklama, SSO, düzenleyici saat yapılandırması, özel ajan.
- **Sıfır egress kanıtı** (statik envanter ratchet + çalışma zamanı guard, CI `airgap.yml`), imzalı internetsiz paket, Helm NetworkPolicy (airgap değerlerinde açık).
- **Kurulumda veri yerleşimi etiketi**: "Local / Your cloud / Hosted: data leaves your site".
- **FIPS 140-3 modu**: sağlayıcı yoksa süreç başlamaz; PBKDF2 parola özeti (bilinen Ed25519 boşluğu dışında).
- **Tedarik zinciri**: CycloneDX SBOM, cosign keyless imza ve SLSA provenance (release.yml); Trivy (secret kapısı dahil), Bandit, Dependabot; rol × rota matrisi, SSRF matrisi, kırmızı takım regresyonu.
- **QA karnesi, kanaryalar, kararda `prompt_version` ve model**: AI kontrol kanıtı olarak kullanılabilir.
