# 1 — Satıcının (SingularityRD) ticari ve hukuki akışları: eksik analizi

Kapsam: ilk satış temasından yenileme ve sözleşme bitişine kadar, **satıcı tarafı** persona'ları.
Kod tabanı: `/root/wt/gap` @ `87b1438e` (salt-okunur). Bütün kanıtlar bu ağaca göre verildi.
Repo dışında olması beklenen hukuki ve ticari belgeler "repoda yok, büyük olasılıkla gerekli" diye işaretlendi ve önemleri, bir Türk bankasının satın alma ve tedarikçi risk sürecinin ne isteyeceğine göre verildi.

**Zaten bilinen, burada yeniden keşfedilmeyen ama sayılan maddeler:** rc.1 etiketi atıldı (imajlar yayımlanıyor) · Kapı C (temiz VM'de <30 dk) yapılmadı · dış pentest · W1.4 kararı · yüksek riskli WP'lerin ürün onayları · tag ruleset'leri · katalog yer tutucuları · otomatik kapatma ve çok kiracılık Kasım'a ertelendi.

---

## A. Persona'lar ve uçtan uca user story'ler (adım adım doğrulama)

### A1. Satış / ön satış mühendisi (keşif → değerlendirme)
1. *Hedef bankayı ilk kez arar; elinde bir tanıtım sunumu, tek sayfalık özet ve rakip karşılaştırması vardır.* → Repoda hiçbiri yok (S-01, S-02). Tezin kaynağı yalnızca iç plan: `docs/wp/NORTHSTAR_PLAN.md:7-46` (dört ayak tablosu, `:44-51`).
2. *Fiyat ve paket sorulur (çekirdek, düzenlenmiş sektör paketi, MSSP; varlık, alarm hacmi ya da analist sayısına göre).* → Fiyatlandırma modeli yok. Lisans modeli açık bir karar olarak bekliyor: `NORTHSTAR_PLAN.md:434` (S-03).
3. *Demo yapar: kanaryalarla ölçülen FN, kanıt öncelikli soruşturma ve "Geri al" düğmesi gösterilir.* → İki demo yolu var: (a) kurulum sihirbazındaki "Try demo data" (`clients/web/src/screens/setup/FileAndDemoSources.tsx:82-114`). Bu, upstream'den gelen ve bellekte tutulan 25 bulgu ile 5 vakadır (`core/platform/demo_data_service.py:1,196`). Karne, onay ya da eylem verisi üretmez. (b) staging'deki `infra/staging/seed-demo.sh`, korpustan bulgu yükler, ama yanıt eylemleri kapalıdır (`infra/staging/values-staging.yaml:15,104`). Sahte veya sandbox bir executor yok (`core/response/executors/` içinde yalnızca `base.py` ve `wiring.py`). Sonuç: "geri alınabilir eylem" ancak gerçek bir Defender ya da Entra kiracısıyla gösterilebiliyor (S-04, S-05).
4. *Müşteri "Türkçe arayüz var mı?" diye sorar.* → Konsolda i18n yok (aranan: `i18next|react-intl|useTranslation` → bulunamadı). Bu bir açık karar: `NORTHSTAR_PLAN.md:437` (S-06).
5. *Teknik değerlendirme için müşteriye belge seti verilir.* → `docs/guide/` var. Ancak kökteki `README.md` baştan sona upstream Vigil'in metni (S-20).

### A2. POC / pilot sahibi (değerlendirme → satın alma kararı)
1. *POC ortamı hazırlanır (internetsiz VM).* → Air-gap paketi ve kurulum kılavuzu var (`docs/guide/kurulum-internetsiz.md`). Kapı C (kurulumun gerçekten <30 dk sürdüğü) ölçülmedi (bilinen).
2. *POC süresi, başarı ölçütleri ve çıkış koşulları yazılı olarak üzerinde anlaşılır.* → POC şablonu, başarı kriteri belgesi ya da POC sözleşmesi yok (S-07).
3. *Başarı müşterinin kendi verisinde ölçülür (eval düzeneği ve Karne).* → `evalkit` yalnızca depodaki korpusu ölçüyor: `--suite` yalnız `train,dev,test,test_unseen,injection` alıyor (`evalkit/cli.py:190-195`). Müşteri tarafından etiketlenmiş bir korpusu içeri alma yolu yok. Canlı Karne'nin FN üst sınırı için kategori başına ≥299 inceleme gerekiyor (`NORTHSTAR_PLAN.md:30`); 2-4 haftalık bir POC'ta bu sayıya istatistik olarak ulaşılmaz (S-08).
4. *POC sonunda müşteriye bir "POC raporu" verilir.* → Rapor üretecinin bileşenleri mevcut (eval `report.md`, kanıt paketi). POC raporu şablonu yok (S-07).

### A3. Lisans ve sözleşme yöneticisi (satın alma)
1. *Sözleşmeyle birlikte bir lisans anahtarı ya da hak (entitlement) dosyası verilir; ürün kurulumda bunu doğrular.* → Lisans, entitlement, aktivasyon, son kullanma tarihi, koltuk ya da varlık sayımı, ek süre (grace) ya da katman kapısı yok. Aranan: `license_key|entitlement|activation|seat_count|subscription_tier|grace_period` → yalnızca maskeleme listesindeki adlar çıkıyor (`core/compliance/audit_export.py:1510-1511`). `tier` geçen tek yer otonomi katmanları (`core/autonomy/controller.py`) (S-09).
2. *Lisansı olmayan kopyaları ne durdurur?* → Hiçbir şey. Üstelik imajlar `org.opencontainers.image.licenses=Apache-2.0` etiketiyle yayımlanıyor (`.github/workflows/release.yml:164`). Bu, alıcıya yeniden dağıtım hakkı verildiği anlamına gelir. Durumun bilinçli mi olduğu belirsiz: lisans modeli kararı açık (`NORTHSTAR_PLAN.md:434`) (S-03, S-09).
3. *Müşteri EULA veya müşteri koşullarını, KVKK veri işleyen sözleşmesini, SLA ve destek koşullarını imzalar.* → Repoda hiçbiri yok (S-10, S-11, S-12).

### A4. Hukuk / açık kaynak uyum sorumlusu
1. *Fork'un ticari olarak satılabilirliği doğrulanır.* → Upstream'in lisansı Apache-2.0 (`LICENSE`, `FORK.md:3-6`). Kapalı ya da ticari bir türev yasal: Apache-2.0 copyleft değil. Yükümlülükler: §4(a) lisansın bir kopyası verilmeli, §4(b) değiştirilen dosyalarda "değiştirildi" bildirimi olmalı, §4(c) mevcut bildirimler korunmalı, §4(d) NOTICE dosyası (upstream'de yok). §6 marka hakkı vermez. Durum: §4(b) bildirimi yok (aranan: `Modified by|SingularityRD` kaynak başlıklarında → yalnız testler). LICENSE imajlara ve air-gap paketine girmiyor (aranan: Dockerfile'larda, `build-bundle.sh`'de ve `build-support-tarball.sh`'de `LICENSE` → yok). SingularityRD için bir telif satırı da yok (`LICENSE` sonundaki `Copyright [yyyy] [name of copyright owner]` şablonu doldurulmamış) (S-13).
2. *Üçüncü taraf lisans envanteri ve atıf (NOTICE / THIRD_PARTY) dosyası hazırlanır.* → Yok (aranan: `NOTICE*`, `THIRD*PARTY*`, `*attribution*` → bulunamadı). Lockfile'dan üretilen Python SBOM'u lisans alanı taşımıyor; lisansı yalnızca npm bileşenleri yazıyor (`scripts/release/release_tool.py:718-720`) (S-14).
3. *Dağıtımı engelleyebilecek copyleft veya kaynağı görünür lisanslar taranır.* → Python'da GPL, AGPL ya da SSPL yok. LGPL var: `psycopg2-binary`, `paramiko`. MPL var: `certifi`. npm'de çalışma zamanı paketlerinin hepsi MIT, ISC, BSD veya Apache; lisansı bilinmeyen paketler: `react-router`, `react-router-dom`, `@remix-run/router` (lockfile'da alan yok, gerçekte MIT) ve `pipenet` (`infra/docker/mcp-packages/package-lock.json`). **Asıl riskler pakete giren bileşenlerde:**
   - `redis:7-alpine` kayan etiketi (`infra/helm/vigil/values.yaml:339-340`). Redis 7.4 ve sonrası RSALv2/SSPLv1 lisanslı; kurulumda gerçekte hangi sürümün çekileceği belli değil.
   - Varsayılan yerel model `llama3.1:8b` pakete giriyor (`infra/airgap/build-bundle.sh:60`). Llama 3.1 Community License lisans metninin verilmesini, "Built with Llama" ibaresini ve AUP'yi (kabul edilebilir kullanım politikası) şart koşuyor; pakette bunlar yok.
   - Aday modeller arasında `gemma2:9b` var (Gemma kullanım koşulları; `eval/suites/local_lane/candidates.json`).
   - Elastic `detection-rules` (ELv2) ve Sigma kuralları (DRL 1.1) yeniden dağıtılıyor (`scripts/setup_detection_repos.sh:44-47`, `build-bundle.sh:275-281`).
   - Debian/Node temel imajlarındaki GPL ikilileri için kaynak sunma yükümlülüğü var (S-15, S-16).
4. *Marka: "Vigil" kullanıcıya görünen yerlerden çıkarılır.* → Konsol ve API başlığı temiz (`services/api/main.py:158` "AutoSecOps API"). Kalan yerler şunlar:
   - Helm grafiği: `name: vigil`, "Vigil SOC — open-source…", `home: vigilsoc.org`, `maintainers: Vigil-SOC` (`infra/helm/vigil/Chart.yaml:2-12`).
   - Masaüstü: `appId: ai.deeptempo.vigil` (`clients/desktop/electron-builder.yml:1`), `name: vigil-desktop`.
   - Destek aracı: adı `vigil-support-<V>.tar.gz` (`release.yml` update-release adımı). Çıktıları "no Vigil install found", "More than one Vigil install…" diyor (`scripts/vigil-support/vigil-support.sh:554,564`).
   - Compose: 25 adet `container_name: deeptempo-*`, `image: vigil-backend:local`.
   - Gizli bilgi dosyasının başlığı "# Vigil SOC Secrets" (`core/secrets_manager.py:166,187`).
   - API hata metni `vigilsoc.org/docs/bifrost` adresine yönlendiriyor (`services/api/routers/analytics.py:310`).
   - Logo bileşeni `VigilLogo.tsx` ve `vigil-logo.svg` (karar açık: `NORTHSTAR_PLAN.md:431`).
   - Kök `README.md`, `SECURITY.md` ve `VERSIONING.md:3-5` hâlâ "Vigil", `vigilsoc.org` ve `deeptempo.ai` diyor.
   - Air-gap paketinin `docs/` tarball'ına bu kök README de giriyor (`build-bundle.sh:293`) (S-17, S-18, S-20).
5. *DCO ve katkı modeli.* → `DCO` standart DCO 1.1 metni. Katkı rehberi upstream'e yönlendiriyor (`README.md:337,349`). Eklenen kodun ileride ticari lisansa geçirilmesi gerekirse, dış katkıcılar için DCO yeterli değil, CLA gerekir (S-19).

### A5. Uyum / tedarikçi güvence sorumlusu (bankanın satın alma süreci ve TPRM, yani üçüncü taraf risk yönetimi)
1. *Güvenlik teknik belgesi istenir.* → `docs/guide/guvenlik-teknik-belgesi.md` (488 satır) var ve iyi durumda. Eksikleri: `main` @ `b8795def` tabanında ve **güncel değil**. Örneğin "SBOM, imzalı imajlar… Planlı — bu sürümde yok" diyor (`:487`), oysa W4.7 birleşti. Veri akışı çizimi yok (yalnız metin, `:46-52`). Satıcının kendi kurumsal güvenlik önlemleri (personel, erişim, uzaktan destek) yok (S-21).
2. *Güvenlik açığı bildirim politikası istenir.* → `SECURITY.md` upstream'in metni. Bildirimler **Vigil-SOC GitHub'ına ve `security@deeptempo.ai` adresine** gidiyor (`SECURITY.md:56,64,139,295`). Ayrıca `security.txt` `vigilsoc.org` üzerinde (`:10,299`), "0.5.x destekli" yazıyor (`:21`), ABD'nin CFAA yasasına atıf var (`:152`), PGP anahtarı yok (S-22).
3. *SOC 2 veya ISO 27001 beyanı, pentest raporu, BCP/DR beyanı istenir.* → SOC 2 hazırlığı Kasım'da planlı (`NORTHSTAR_PLAN.md` "GA sonrası", son madde). ISO yok. Ürünün RPO/RTO'su `docs/operations/rpo-rto.md`'de var; satıcının iş sürekliliği beyanı yok (S-23). Pentest bilinen bir madde.
4. *Alt işleyen listesi (LLM sağlayıcıları), veri akışı ve yurt dışı aktarım.* → `mevzuat-eslemesi.md:74` "bulut sağlayıcı seçilirse aktarım kurumun değerlendirmesine tabi" diyor. README ise varsayılan sağlayıcıyı Anthropic olarak gösteriyor (`README.md:144`). Alt işleyen listesi yok (S-24).
5. *BDDK destek hizmeti mevzuatı, kamu için Bilgi ve İletişim Güvenliği Rehberi eşlemesi.* → `mevzuat-eslemesi.md`'de BDDK BS Yönetmeliği, KVKK, DORA, NIS2, SPK ve ISO var. "Bankaların Destek Hizmeti Almalarına İlişkin Yönetmelik" ve kamu için "Bilgi ve İletişim Güvenliği Rehberi" yok (aranan: `destek hizmet|Rehber|DDO` → bulunamadı) (S-25).
6. *Yazılım emaneti (escrow), standart güvenlik anketi cevap seti (CAIQ / SIG-lite / BDDK tedarikçi formu).* → Yok (S-26, S-27).

### A6. Sürüm ve dağıtım mühendisi (teslimat)
1. *Müşteri imajları çeker.* → İmajlar `ghcr.io/singularityrd/autosecops-*` adresinde. Repo özel (`FORK.md` §6 "private repository"; `VERSIONING.md` rulesets "on a private repository"). Özel bir repodan yayımlanan GHCR paketleri varsayılan olarak özeldir; çekmek için kimlik doğrulama gerekir. Helm'de `imagePullSecrets: []` (`infra/helm/vigil/values.yaml:16`) ve hiçbir belge pull secret ya da GHCR erişimi anlatmıyor (aranan: `imagePullSecret|read:packages` docs'ta → yok) (S-28).
2. *Air-gap müşterisine paket teslim edilir.* → Paketi sürüm mühendisi üretiyor ve imzalıyor (`kurulum-internetsiz.md:21-30`). Aktarım "müşteri sürecine bağlı". Açık anahtarın "müşteri portalı, imzalı e-posta" ile verileceği yazıyor (`infra/airgap/README.md` §1), ama portal yok. Fiziksel medya, teslim tutanağı ve ilk Ed25519 anahtarının üretim töreni kayıt altında değil (S-29).
3. *Sürüm notları yayımlanır.* → `release.yml` taslak bir GitHub Release oluşturuyor. Özel repoda müşteri bunu göremez. Notlar Türkçe ve "TASLAK" (`docs/release/2.0.0.md:4`) (S-30).
4. *Helm grafiği dağıtılır.* → Grafik bir OCI kayıt defterine itilmiyor (aranan: `helm push|oci://|chart-releaser` → yok). Grafik yalnız air-gap paketinin içinde ya da repo kopyasıyla geliyor (S-28).

### A7. Destek ve müşteri başarısı (günlük kullanım → olay → yenileme)
1. *Müşteri destek talebi açar (kanal, bilet sistemi, önem dereceleri, yanıt süreleri).* → Hiçbiri yok. Üründe satıcıya ait bir iletişim bilgisi de yok (aranan: `support@|mailto:|singularityrd.(com|ai)` → yok; alan adı kararı açık: `NORTHSTAR_PLAN.md:432`) (S-12, S-31).
2. *Destek paketi toplanır.* → Var: `scripts/vigil-support/vigil-support.sh`. Tarball'ı maskeliyor, hiçbir şey yüklemiyor (`README.md:255`) ve sürümle yayımlanıyor (`release.yml`). Ancak adında ve çıktısında Vigil geçiyor (S-17).
3. *Telefonla eve dönüş (phone-home) olmadan uzaktan teşhis.* → Medic var (varsayılan kapalı). Egress envanterine göre satıcıya giden hiçbir bağlantı yok: Sentry ve OTEL kapalı (`tests/airgap/egress_inventory.json`; `core/config.py:296`). Bu, düzenlenmiş sektör için doğru tercih. Lisans için kullanım ölçümü yok; isteğe bağlı (opt-in) ve çevrimdışı bir kullanım raporu da yok (S-32).
4. *EOL / LTS politikası.* → `VERSIONING.md` sürüm mekaniğini anlatıyor ama destek süresi, LTS ya da geriye düzeltme taşıma (backport) taahhüdü yok. `SECURITY.md:21-22` "eski sürümlere backport yok" diyor. Ayrıca ajan imajı `node:20-slim` (`infra/docker/Dockerfile.agent:28,44`) ve Node 20'nin desteği 30 Nisan 2026'da bitti, yani GA'da EOL bir çalışma zamanı ile çıkılıyor (S-33, S-34).
5. *Müşteri sağlık kontrolü ve çeyreklik iş değerlendirmesi (QBR).* → Ürün içinde Karne, analitik ve Medic var. Bunlardan rapor üretecek bir müşteri başarısı oyun kitabı yok (S-35).

### A8. Profesyonel hizmetler (kurulum → ilk değer)
1. *Kurulum mühendisimiz sahada kurar.* → Rol ve süre tablosu var (`kurulum-internetsiz.md:21-30`), ilk 15 dakikanın adımları var (`:221-250`). Saha kontrol listesi yok: ön keşif anketi, değişiklik onayı, kabul tutanağı (S-36).
2. *Müşteri analistleri eğitilir.* → Eğitim müfredatı veya sertifikası yok. Belgeler yalnız yöneticiye yönelik; analist kılavuzu yok (S-37).
3. *İlk değer: ilk entegrasyon, ilk triyaj ve ilk onaylı eylem.* → Sihirbaz var (`clients/web/src/screens/setup/*`). Varsayılan yerel model "eval ile seçilir" deniyor (sürüm notları, W2.3), ama depoda bir seçim sonucu yok (aranan: `selection.json`, `ranking.json` → yok). Paket varsayılanı `llama3.1:8b` gerekçesiz seçilmiş (S-38).

### A9. Pazarlama
1. *Katalog artifact'ı ve web sitesi.* → Katalog yer tutucuları bilinen bir madde. Web sitesi, alan adı ve vaka çalışması yok (S-39).
2. *"Kanıtlanabilir AI SOC" iddiası ölçümle destekleniyor mu?* → Hedefler `NORTHSTAR_PLAN.md:29-38`'de. Ölçülen değerler yalnız **stub** model ile, **sentetik** korpus üzerinde (`evalkit/README.md:194-203`; korpus sentetik: `eval/corpus/v1/DATASHEET.md:235-238`):
   - FN ≤ %1 → ölçülmedi (otomatik kapatma Kasım'da; ≥299 inceleme gerekiyor).
   - Recall ≥ %95 → `test` 0,972 ama `test_unseen` **0,833** (hedefin altında), ikisi de stub.
   - Injection ≤ %5 → **0,0875 (21/240)**, stub. Belge seti bu kapıyı "Planlı" diyor (`docs/guide/README.md:15`, `guvenlik-teknik-belgesi.md:478-479` "≤ %5 hedefi değildir").
   - Maliyet −%60 → ölçüm yok (aranan: wp belgelerinde `%60|-60` → yalnız plan satırları).
   - Gerçek bir modelle (live) koşu sonucu ve yayımlanmış bir Karne yok, oysa GA kapısında "karne yayımlandı" maddesi var (`NORTHSTAR_PLAN.md:294`) (S-40).

### A10. Sözleşme sonu (veri iadesi ve kaldırma)
1. *Müşteri verisi iade edilir.* → Kısmi yollar var: `POST /api/findings/export`, vaka kanıt paketi, denetim dışa aktarımı ve SIEM aktarımı (`yonetici-kilavuzu.md:116,609-730`). Tam bir veri iadesi prosedürü ve biçimi yok.
2. *Kaldırma ve imha sertifikası verilir.* → KVKK periyodik imha tutanağı var (`yonetici-kilavuzu.md:581`). Tam kaldırma prosedürü yok: helm uninstall, PVC'ler, yedek deposu, `master.key`, imza anahtarları. `rpo-rto.md:185` yedek PVC'sinin uninstall sonrasında da kaldığını söylüyor. İmha veya kaldırma sertifikası şablonu yok (S-41).

---

## B. Bulgu tablosu

| ID | Persona | Flow adımı | Eksik (ne yok / ne yanlış) | Kanıt | Önem | Sahip | Tahmini efor |
|---|---|---|---|---|---|---|---|
| S-01 | Satış | İlk temas | Satış sunumu, tek sayfalık özet ve demo senaryosu yok; tez yalnız iç planda | aranan: `docs/**` içinde deck/pitch/demo script → yok; tez `NORTHSTAR_PLAN.md:7,44-51` | YÜKSEK | Satış-Pazarlama | M |
| S-02 | Satış | Rakip sorusu | Rakip karşılaştırması (Dropzone, Prophet, Torq, 7AI, yerli SOAR) yok | aranan: `dropzone|prophet|torq|7ai|competitor|rakip` → yok | ORTA | Satış-Pazarlama | M |
| S-03 | Satış/Hukuk | Fiyat ve lisans | Fiyatlandırma ve paketleme yok; eklenen kodun lisans modeli (Apache mi ticari mi) kararı açık. EULA, fiyat ve korumaların hepsi buna bağlı | `NORTHSTAR_PLAN.md:434` | SATIŞ-ENGELİ | Ürün + Hukuk | M |
| S-04 | Satış | Demo: tez | Demo modu upstream'in rastgele 25 bulgusu; Karne, kanarya, verdict, onay ve geri alma göstermiyor | `core/platform/demo_data_service.py:1,196-206`; `setup/demoMode.ts` | YÜKSEK | Mühendislik + Ürün | M |
| S-05 | Satış | Demo: geri alma | Sahte veya sandbox executor yok; staging'de yanıt kapalı. "Geri alınabilir eylem" gerçek kiracı olmadan gösterilemiyor | `core/response/executors/` (base, wiring); `infra/staging/values-staging.yaml:15,104` | YÜKSEK | Mühendislik | M |
| S-06 | Satış | Türkçe arayüz | Konsolda i18n yok; kamu ve banka için açık karar | aranan: `i18next|react-intl|useTranslation` → yok; `NORTHSTAR_PLAN.md:437` | YÜKSEK (kamu için SATIŞ-ENGELİ olabilir) | Ürün | L |
| S-07 | POC | POC planı | POC şablonu (süre, başarı ölçütü, çıkış, veri iadesi), POC sözleşmesi ve POC raporu şablonu yok | repoda yok | YÜKSEK | Satış + Hukuk | S |
| S-08 | POC | Müşteri verisinde ölçüm | evalkit müşteri tarafından etiketlenmiş korpusu alamıyor (yalnız sabit suite'ler); canlı FN sınırı için ≥299 inceleme gerekiyor, POC süresinde ulaşılmaz | `evalkit/cli.py:190-195`; `NORTHSTAR_PLAN.md:30` | YÜKSEK | Mühendislik + Ürün | M |
| S-09 | Lisans | Aktivasyon ve koruma | Lisans anahtarı, entitlement, son kullanma tarihi, koltuk ya da varlık sayımı, çevrimdışı lisans, ek süre ve katman kapısı yok; imaj etiketi Apache-2.0 diyor, yani yeniden dağıtım serbest | aranan: `license_key|entitlement|activation|seat|subscription_tier|grace` → yok; `release.yml:164` | GA-ENGELİ (karar), uygulaması YÜKSEK | Ürün + Mühendislik | L |
| S-10 | Hukuk | Sözleşme | EULA, müşteri koşulları ve abonelik sözleşmesi yok | repoda yok, büyük olasılıkla gerekli | SATIŞ-ENGELİ | Hukuk | M |
| S-11 | Hukuk/Uyum | KVKK | Veri işleyen sözleşmesi (DPA) yok. Destek paketi ve uzaktan destek satıcıya veri aktarabilir | repoda yok; `scripts/vigil-support/` | SATIŞ-ENGELİ | Hukuk | M |
| S-12 | Destek | SLA | SLA, destek koşulları, önem tanımları (P1-P4), yanıt ve çözüm süreleri yok | repoda yok (`SECURITY.md` yalnız güvenlik açığı hedeflerini veriyor) | SATIŞ-ENGELİ | Destek-Operasyon + Hukuk | S |
| S-13 | Hukuk | Apache §4 | LICENSE imajda, air-gap paketinde ve destek tarball'ında yok (§4a); değiştirilen dosyalarda bildirim yok (§4b); SingularityRD telif satırı yok; NOTICE yok | Dockerfile'larda, `build-bundle.sh`'de ve `build-support-tarball.sh`'de `LICENSE` yok; `LICENSE` sonunda şablon satır | GA-ENGELİ | Hukuk + Mühendislik | S |
| S-14 | Hukuk | 3. taraf envanteri | NOTICE, THIRD_PARTY_LICENSES ve konsolda "açık kaynak lisansları" sayfası yok; Python SBOM'u lisans taşımıyor | aranan: `NOTICE*`, `THIRD*PARTY*` → yok; `release_tool.py:718-720` (yalnız npm) | YÜKSEK | Hukuk + Mühendislik | M |
| S-15 | Hukuk | Paketlenen bileşenler | `redis:7-alpine` kayan etiketi (7.4+ RSALv2/SSPL); Llama 3.1 lisans metni, "Built with Llama" ibaresi ve AUP pakette yok; Gemma koşulları; Elastic ELv2 ve Sigma DRL kuralları yeniden dağıtılıyor | `values.yaml:339-340`; `build-bundle.sh:60,275-281`; `setup_detection_repos.sh:44-47`; `local_lane/candidates.json` | YÜKSEK | Hukuk + Mühendislik | M |
| S-16 | Hukuk | Konteyner GPL | Debian ve Node temel imajlarındaki GPL/LGPL ikilileri ile psycopg2 ve paramiko (LGPL) için kaynak sunma veya yazılı teklif yok | `Dockerfile.*` FROM `python:3.12-slim`, `node:20/22-slim` | ORTA | Hukuk | S |
| S-17 | Hukuk/Marka | Kullanıcıya görünen Vigil | Helm grafiğinin adı, açıklaması, home ve maintainers alanları; masaüstü `appId ai.deeptempo.vigil`; `vigil-support` tarball adı ve çıktıları; `deeptempo-*` konteyner adları; gizli bilgi dosyası başlığı; API hata metnindeki `vigilsoc.org` linki; logo | `Chart.yaml:2-12`; `electron-builder.yml:1`; `vigil-support.sh:554,564`; compose (25×); `secrets_manager.py:166`; `analytics.py:310`; `VigilLogo.tsx` | YÜKSEK | Mühendislik + Ürün | M |
| S-18 | Hukuk/Marka | Marka tescili | "AutoSecOps" için TÜRKPATENT marka araştırması ve tescil kaydı yok (çakışma riski) | repoda yok, büyük olasılıkla gerekli | YÜKSEK | Hukuk | M |
| S-19 | Hukuk | Katkı | DCO var, CLA yok; ileride ticari lisansa geçiş için dış katkılar engel olur | `DCO`; `README.md:337,349` | DÜŞÜK | Hukuk | S |
| S-20 | Satış/Marka | Belge seti | Kök `README.md` tümüyle upstream'in (Vigil, Discord, vigilsoc, `git clone Vigil-SOC`) ve air-gap paketinin docs tarball'ına giriyor | `README.md:1-11,114`; `build-bundle.sh:293` | GA-ENGELİ | Ürün | S |
| S-21 | Uyum | Güvenlik belgesi | Belge `b8795def` tabanında ve güncel değil (SBOM/imza "Planlı" yazıyor); veri akışı diyagramı yok; satıcının kurumsal güvenliği ve uzaktan erişim modeli yok | `guvenlik-teknik-belgesi.md:3,487`; `docs/guide/README.md:4` | YÜKSEK | Uyum + Mühendislik | S |
| S-22 | Uyum | Açık bildirimi | SECURITY.md bildirimleri DeepTempo'ya ve Vigil-SOC'a yönlendiriyor; security.txt vigilsoc.org'da; "0.5.x" yazıyor; CFAA atfı var; PGP yok. Ürünümüzün açıkları üçüncü tarafa gidiyor | `SECURITY.md:10,21,56,64,139,152,295` | GA-ENGELİ | Uyum + Mühendislik | S |
| S-23 | Uyum | Sertifikalar ve BCP | SOC 2 / ISO 27001 beyanı (ya da yol haritası mektubu) yok; satıcının BCP/DR beyanı yok (ürün RPO/RTO'su var) | `NORTHSTAR_PLAN.md` Kasım: "SOC 2 hazırlığı"; `docs/operations/rpo-rto.md` | YÜKSEK | Uyum | L |
| S-24 | Uyum | Alt işleyenler | Alt işleyen listesi (Anthropic, OpenAI, Vertex; destek araçları) ve yurt dışı aktarım bildirimi yok | `mevzuat-eslemesi.md:74,129`; `README.md:144` | YÜKSEK | Hukuk + Uyum | S |
| S-25 | Uyum | Mevzuat | BDDK Destek Hizmeti Yönetmeliği (satıcı = destek hizmeti kuruluşu olabilir) ve kamu için Bilgi ve İletişim Güvenliği Rehberi eşlemesi yok | aranan: `destek hizmet|Rehber|DDO` → yok | YÜKSEK | Uyum + Hukuk | M |
| S-26 | Uyum | Emanet | Yazılım emaneti (escrow) sözleşmesi ve süreci yok (bankalar kapalı kaynakta ister) | repoda yok | ORTA | Hukuk | M |
| S-27 | Uyum | Anket | CAIQ / SIG-lite / banka TPRM formu için hazır cevap seti yok | repoda yok | YÜKSEK | Uyum | M |
| S-28 | Sürüm | İmaj ve grafik erişimi | GHCR paketleri özel repodan geliyor (muhtemelen özel); pull secret ve müşteri erişim modeli belgesiz (`imagePullSecrets: []`); Helm grafiği OCI'ye itilmiyor | `values.yaml:16`; `FORK.md` §6; aranan: `helm push|oci://` → yok | YÜKSEK (çevrimiçi müşteride SATIŞ-ENGELİ) | Mühendislik + Destek-Operasyon | S |
| S-29 | Sürüm | Air-gap teslimi | Teslim kanalı (medya, portal, teslim tutanağı) ve Ed25519 paket anahtarının üretim töreni ile saklama kaydı yok; bahsedilen "müşteri portalı" yok | `infra/airgap/README.md` §1; `kurulum-internetsiz.md:25-27` | YÜKSEK | Destek-Operasyon | M |
| S-30 | Sürüm | Sürüm notları | Taslak GitHub Release'i müşteri göremez; notlar "TASLAK"; müşteriye dönük yayın kanalı yok | `docs/release/2.0.0.md:4`; `release.yml` update-release `draft: true` | ORTA | Ürün | S |
| S-31 | Destek | Kanal | Destek kanalı, bilet sistemi ve üründe satıcı iletişim bilgisi yok; alan adı kararı açık | aranan: `support@|mailto:` → yok; `NORTHSTAR_PLAN.md:432` | SATIŞ-ENGELİ | Destek-Operasyon | M |
| S-32 | Destek/Lisans | Kullanım ölçümü | Lisans uyumu için çevrimdışı, isteğe bağlı kullanım raporu yok (phone-home olmaması doğru) | `egress_inventory.json` (vendor host yok) | ORTA | Ürün | M |
| S-33 | Destek | EOL/LTS | Destek süresi, LTS ve backport politikası yok; SECURITY.md "backport yok" diyor | `VERSIONING.md`; `SECURITY.md:17-22` | YÜKSEK | Ürün | S |
| S-34 | Destek | EOL bileşen | Ajan imajı `node:20-slim` ve Node 20'nin desteği 30 Nisan 2026'da bitti; banka tarayıcıları bunu EOL diye işaretler | `Dockerfile.agent:28,44`; `Dockerfile.backend:19` | YÜKSEK | Mühendislik | S |
| S-35 | Müşteri başarısı | Sağlık ve yenileme | Müşteri sağlık kontrolü, QBR oyun kitabı ve yenileme takvimi yok | repoda yok | DÜŞÜK | Destek-Operasyon | S |
| S-36 | PS | Saha kurulumu | Ön keşif anketi (EDR, IdP, firewall, kapasite), saha kontrol listesi ve kabul tutanağı yok | `kurulum-internetsiz.md:21-30` yalnız teknik adımlar | YÜKSEK | Destek-Operasyon | S |
| S-37 | PS | Eğitim | Analist ve yönetici eğitim müfredatı, sertifikası ve analist kullanım kılavuzu yok | `docs/guide/` (yalnız yönetici kılavuzu) | ORTA | Ürün + Destek-Operasyon | M |
| S-38 | PS | İlk değer | Varsayılan yerel modelin eval seçimi depoda yok (selection veya ranking dosyası yok); paket varsayılanı `llama3.1:8b` gerekçesiz | aranan: `selection.json|ranking.json` → yok; `build-bundle.sh:60` | YÜKSEK | Mühendislik | M |
| S-39 | Pazarlama | Web ve vaka çalışması | Web sitesi, alan adı ve referans vaka çalışması yok (katalog yer tutucuları bilinen) | repoda yok | ORTA | Satış-Pazarlama | M |
| S-40 | Pazarlama | Ölçülmüş iddialar | FN ≤%1 ölçülmedi; recall test_unseen 0,833 (<0,95); injection 0,0875 (>0,05); maliyet −%60 için veri yok; hepsi stub ve sentetik; yayımlanmış Karne yok. "Kanıtlanabilir" iddiası şu an kanıtsız | `evalkit/README.md:194-203`; `DATASHEET.md:235-238`; `NORTHSTAR_PLAN.md:29-38,294`; `docs/guide/README.md:15` | GA-ENGELİ (pazarlamada sayı kullanılırsa) | Ürün + Mühendislik | L |
| S-41 | Sözleşme sonu | Veri iadesi ve imha | Tam veri iadesi prosedürü, kaldırma runbook'u (PVC, yedek deposu, anahtarlar) ve imha/kaldırma sertifikası şablonu yok; yedek PVC'si uninstall sonrası kalıyor | `yonetici-kilavuzu.md:581`; `docs/operations/rpo-rto.md:185`; aranan: `uninstall` docs/guide → yok | YÜKSEK | Destek-Operasyon + Hukuk | M |
| S-42 | Sürüm | Paket belgeleri | Air-gap docs tarball'ına iç tasarım belgeleri de giriyor (`docs/design/console/PRD-phase1.md`; yalnız `docs/wp` hariç tutuluyor) | `build-bundle.sh:293-295` | DÜŞÜK | Mühendislik | S |
| S-43 | Hukuk | Sorumluluk ve sigorta | AI kararlarından doğan sorumluluk sınırı, siber sorumluluk sigortası ve hizmet kusurunda tazmin maddeleri yok (EULA ile birlikte) | repoda yok | YÜKSEK | Hukuk | M |

Bilinen ve yalnızca sayılan maddeler (yeniden keşfedilmedi): rc.1, Kapı C, pentest (S-23'ü etkiler), W1.4 (S-40'ı etkiler), ürün onayları, tag ruleset'leri, katalog yer tutucuları (S-39), otomatik kapatma ve çok kiracılık Kasım'da (S-08 ve S-40'ı etkiler).

---

## C. Var ve çalışıyor görünüyor

- **Apache-2.0 tabanı ticari satışa izin veriyor** (copyleft değil, NOTICE yükümlülüğü yok). Python'da GPL, AGPL ya da SSPL bağımlılık yok. npm çalışma zamanı paketlerinin hepsi MIT, ISC, BSD veya Apache.
- **İmzalı sürüm hattı:** cosign anahtarsız imza, SLSA provenance, CycloneDX SBOM'lar, `SHA256SUMS`, `verify-release.sh` ve çevrimdışı doğrulama belgesi (`docs/release/dogrulama.md`).
- **Air-gap paketi:** `infra/airgap/` (imzalı, sahte paketi reddediyor). Türkçe kurulum kılavuzu. Sıfır egress testi (`tests/airgap/`, `airgap.yml`). Satıcıya giden hiçbir bağlantı yok.
- **Destek paketi aracı:** maskeliyor, yüklemiyor ve sürümle birlikte `.sha256` ile yayımlanıyor.
- **Müşteriye dönük Türkçe belge seti:** kapsam, kurulum, yönetici kılavuzu, güvenlik teknik belgesi, tehdit modeli, mevzuat eşlemesi (BDDK, KVKK, DORA, NIS2, SPK, ISO). Ayrıca RPO/RTO ve 0.7'den 2.0'a yükseltme belgeleri.
- **Ölçüm düzeneği:** evalkit (stub/cassette/live, bütçe tavanlı). Korpus v1 sentetik ve Apache. Injection ASR gerileme kapısı CI'da.
- **KVKK:** saklama ve imha, yasal saklama ve periyodik imha tutanağı (`core/compliance/RETENTION.md`).
- **Ürün içi kanıt araçları:** vaka kanıt paketi (imzalı ZIP, `scripts/autosecops verify-bundle`), denetim zinciri, SIEM aktarımı.
- **Kurulum sihirbazı:** sistem kontrolleri, sağlayıcı, kaynaklar, limitler, özet.
- **Konsol ve API başlığı** AutoSecOps diyor. İmaj adları `ghcr.io/singularityrd/autosecops-*` ve OCI etiketinde `vendor=SingularityRD`.
- **Staging:** gecelik kurulum, demo verisi ve replay (`infra/staging/`).
