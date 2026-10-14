# 7 — Kurulum, ilk açılış sihirbazı ve müşteri yaşam döngüsü (time-to-value)

Kod: `/root/wt/gap` @ 87b1438e (salt okunur). Upstream dalları: `/root/vigil` (remote `target` = SingularityRD/autosecops2).
Yöntem: her persona için akış adım adım yazıldı, her adım kod ve belgeyle doğrulandı. Uygulama başlatılmadı.

## 0. Özet hüküm

- **Sihirbaz var ve iyi yapılmış**: 5 numaralı adım ve bir "hazır" sayfası (`SetupScreen.tsx:31`). Adımlar: sistem kontrolleri → veri kaynağı → AI sağlayıcısı → ajanlar/iş akışları ve Assist/Act → limitler ve Slack → "AutoSecOps is ready". Bağlantı testi, ilk poll testi, anahtar doğrulama, demo, dosya yükleme ve "sonra bitir" de var.
- **Upstream `factory/18xx-setup-*` dallarında AutoSecOps'ta eksik bir adım yok.** 1810 (iki dal), 1812 ve 1813'ün `target/main..dal` farkı **0 commit**. Dördü de AutoSecOps main'in atası. AutoSecOps bu dalların da ilerisinde: `useSystemChecks.ts`, rail'de "!" uyarısı, alan adıyla kimlik bilgisi reddi. 1642 (integrations setup drawer) için de fark 0 commit. Kanıt: `git -C /root/vigil log --oneline target/main..target/factory/<dal> | wc -l` → 0. Dosya bazında diff yalnızca marka metnini ("Vigil" → "AutoSecOps") ve AutoSecOps'un kendi iyileştirmelerini gösteriyor.
- **Asıl boşluk düzenlenmiş sektör adımları.** Sihirbazda şunlar yok: kurum adı, saat dilimi ve dil; SSO; kullanıcı davet etme; KVKK veri yerleşimi onayı; müdahale yürütücüsü; korunan varlıklar; saklama; SIEM'e denetim aktarımı; yedek; SLA; e-posta ve Teams bildirimi. Bunların çoğu yalnızca API ile yapılabiliyor; belge de bunu açıkça yazıyor (`yonetici-kilavuzu.md:343-345`, `:603-604`, `:690-691`).
- **Kurulumcu tarafı**: Air-gap paket doğrulaması çok iyi. Kümeye yönelik bir ön kontrol (preflight) ise yok. Helm NOTES hâlâ "Vigil SOC" diyor. İlk yönetici hesabını, ağdan ilk gelen kim olursa alabiliyor; kurulum token'ı yok.
- **Yaşam döngüsünün geri kalanı neredeyse görünmez**: yedek hatası, disk dolması, lisans, sertifika, aylık bütçe tavanı, kimlik bilgisi süresi. Yapılandırmayı dışa ya da içe aktarma yok. Kaldırma, sözleşme sonu veri iadesi ve güvenli imha belgesi yok.

## 1. Zaten bilinen ve listelenmiş olanlar (yeniden keşfedilmedi, sayıldı)

- rc.1 etiketi atıldı, imajlar yayımlanıyor.
- **Kapı C** (temiz VM'de 30 dakikanın altında internetsiz kurulum) yapılmadı (`docs/wp/STATUS.md:42`).
- `reset-setup.sh` CSRF sorunu takip listesinde (`STATUS.md:60`). Aşağıda **doğrulandı** (KS-25).
- Pentest, W1.4 kararı, yüksek riskli WP ürün onayları, tag ruleset'leri, katalog yer tutucuları. Otomatik kapatma ve çok kiracılık Kasım'a ertelendi.
- Lisans modeli açık karar (`NORTHSTAR_PLAN.md:434`).

## 2. Personalar ve uçtan uca akışlar

### P1 — Kurulumcu (müşteri BT/platform mühendisi; Helm, air-gap, Compose, masaüstü)

| Adım | Kullanıcının gördüğü | Ne ters gidebilir / ne eksik |
|---|---|---|
| 1. Ön koşulları okur | `infra/airgap/README.md:19-33` ve `docs/guide/kurulum-internetsiz.md` §2: K8s ≥1.25, CNI, kayıt defteri, varsayılan StorageClass, "tercihen GPU" | Bunları denetleyen bir betik yok (KS-01) |
| 2. `install.sh verify` | İmza, SHA256, fazladan dosya, manifest ve arşiv üyesi denetimi; `REFUSED: …` iletileri (`install.sh:52`, `:116-310`) | İyi. Sorun giderme tablosu var (`README.md:290-301`) |
| 3. `install.sh install` | İmaj yükleme → llm-stack → model tar → `helm upgrade --install --wait` → `done: release …` (`install.sh:283-336`) | Küme, StorageClass, GPU, kayıt defterine erişim ve disk ön kontrolü yok. GPU isteği yok (`k8s/llm-stack.yaml` içinde `nvidia.com/gpu` yok). Son satırda URL ya da sonraki adım yok; yalnızca Helm NOTES basılıyor |
| 4. Helm NOTES | "Vigil SOC has been installed…" (`NOTES.txt:1`). Pod/job izleme, port-forward ya da ingress URL'i, `helm test`, ilk yönetici için bootstrap açıklaması (`:40-42`) | Marka hatalı (KS-03). `anthropicApiKey` boşsa air-gap/Ollama kurulumunda da "AI özellikleri hata verir" uyarısı çıkıyor (`NOTES.txt:66-74`; `values-airgap.yaml` anahtar vermiyor) (KS-04). Ingress varsayılan olarak kapalı (`values.yaml:541`), TLS boş (`:553`) |
| 5. Sağlık doğrulama | `helm test` yalnızca `/api/health/ready` ve daemon `/health` denetliyor (`templates/tests/test-connection.yaml:22-26`) | Bifrost, Ollama ve modelin yüklü olduğu denetlenmiyor. README'de elle `ollama list` var (`README.md:252`) |
| 6. Tekrar çalıştırma | `helm upgrade --install`, `kubectl apply`, `docker push` idempotent | Var |
| 7. Tek sunucu (Compose/host) | `set -a; . airgap.env; ./start.sh` (`kurulum-internetsiz.md:197`). Compose için "her servise `env_file` ekleyin, adresleri değiştirin" (`:201`) | `start.sh` geliştirme çalıştırıcısı: `uvicorn --reload` (`start.sh:339`) ve Vite geliştirme sunucusu (`:299`). Compose backend'i `6987:6987` ile tüm arayüzlere ve düz HTTP olarak açıyor (`docker-compose.yml:214-215`). Hazır bir tek sunucu üretim profili yok (KS-05) |
| 8. Masaüstü (değerlendirme) | Docker yoksa diyalog açılıyor (`clients/desktop/src/main.ts:282-294`). Auth açık, JWT'yi uygulama üretiyor (`standalone/docker-compose.yml:109-111`) | İmajları ghcr'den çekiyor; air-gap için değil. `appId: ai.deeptempo.vigil` (`electron-builder.yml:1`). Docker Desktop kurumsal ortamda lisans gerektirebilir (KS-06) |

### P2 — İlk yönetici (SOC yöneticisi; çoğu zaman geliştirici değil, düzenlenmiş kurum)

| Adım | Ne var | Eksik |
|---|---|---|
| 1. İlk tarayıcı ziyareti | Kullanıcı tablosu boşsa `GET /api/auth/bootstrap` ile giriş ekranı "ilk hesabı oluştur" formuna dönüyor (`LoginScreen.tsx:64-92`). Advisory lock ile yarış önleniyor; dakikada 5 deneme; ilk kullanıcı oluşunca kalıcı kapanıyor (`auth.py:226-308`) | **Kurulum token'ı yok.** `BootstrapRequest` yalnızca username, email, password, full_name alıyor (`auth.py:94-100`). Ağa ilk ulaşan herkes Admin olur (KS-02). İlk girişte MFA ya da kurtarma kodu adımı yok (KS-07) |
| 2. Auth ve DEV_MODE | Helm `DEV_MODE: "false"` (`values.yaml:734`), NOTES DEV_MODE uyarısı veriyor (`NOTES.txt:30-35`), konsolda `DevModeWarning.tsx` var | Var |
| 3. TLS | TLS ingress'te sonlanıyor (belgede). Helm `VIGIL_COOKIE_SECURE: "true"` (`values.yaml:789`) | HTTP üzerinden (localhost dışı bir IP veya NodePort) açılırsa Secure çerez yazılmaz ve giriş sessizce döngüye girer. UI'da güvensiz bağlam uyarısı yok (aranan: `isSecureContext\|location.protocol` → yok) (KS-08) |
| 4. Sihirbaza yönlendirme | `SetupGate` tarayıcı başına `localStorage` `vigil.setupDismissed` okuyor (`SetupGate.tsx:13-16`, `setupDismissed.ts:3-18`) | İlerleme sunucuda değil tarayıcıda tutuluyor (`setupDismissed.ts:24-52`). İkinci yönetici ya da başka tarayıcı 1. adımdan başlıyor; yetkisi olmayan analist de her yeni tarayıcıda bir kez /setup'a düşüyor (`SetupScreen.tsx:187-213`) (KS-09) |
| 5. Sihirbaz adımları | §3'teki tablo | §3 |
| 6. "Finish setup" | `SummaryStep.tsx:143-144`: "Setup complete / AutoSecOps is ready" | "Continue" hiçbir adımda doğrulama yapmıyor (`SetupScreen.tsx:144-151`). Veri yok ("Nothing connected yet", `:60`) ve sağlayıcı yok ("No provider", `:77`) olsa bile "hazır" diyor (KS-10) |
| 7. İlk değer (TTV) | Özet "Triage starts on new alerts…" diyor. Home'da "Get more from AutoSecOps" listesi ve "Explore with demo data" var (`HomeScreen.tsx:402-513`). Tur var (`ConsoleTour.tsx`) | "İlk alarm geldi, triyaj edildi, kanıt burada" diye yönlendiren rehberli ilk alarm yok. Kaynak testi yalnızca "Last success …" gösteriyor, kaç alarm alındığını göstermiyor (`SourceCollection.tsx:99-108`) (KS-11). Air-gap'te `DEMO_MODE=false` ortamdan geldiği için demo kapalı (`values-airgap.yaml:117`, `demoMode.ts:9`): hedef pazarın değerlendirme yolu kapalı. Home'daki demo düğmesi ortam kontrolü yapmadan "açıldı" diyor (`HomeScreen.tsx:284-290`) (KS-12) |
| 8. Kalan işler listesi | Üst çubukta "Finish setup · N left" çipi (`SocConsole.tsx:555-564`), menüde "Setup guide" (`UserMenu.tsx:128-131`) | Sayaç sihirbazın adımlarını değil Home'un 4-5 adımını sayıyor (`config.py:632-721`). `notify` yalnızca Slack veya PagerDuty ile bitiyor (`:652`); ikisi de air-gap'te kapalı (`values-airgap.yaml:106-107`). `per_agent` en az 2 farklı model istiyor (`:699`), tek yerel modelli air-gap kurulumunda hiç bitmiyor. Sonuç: çip kalıcı olarak "N left" gösteriyor (KS-13) |

### P3 — Analist (ilk giriş)
Yönetici kullanıcıyı açar ve parolayı kendisi yazar (`UsersSection.tsx:291-295`). Davet e-postası yok, ilk girişte parola değiştirme zorunluluğu yok (aranan: `must_change_password|force_password_change` → yok) (KS-14). Analist her yeni tarayıcıda bir kez "Administrator access needed" ekranını görür (KS-09). Arayüz yalnızca İngilizce ve UTC (KS-15).

### P4 — Uyum/KVKK sorumlusu
Model seçiminde veri yerleşimi yalnızca kart altbilgisi olarak gösteriliyor ("Hosted: data leaves your site", `providerResidency.ts:7`). Onay kaydı, KVKK md.9 yurt dışı aktarım uyarısı ve sağlayıcı sözleşmesi onayı yok (KS-16). Saklama politikası kurulumda yok ve yalnızca API ile ayarlanıyor (`yonetici-kilavuzu.md:567-568`, `:603-604`) (KS-21). İmha tutanağı da API ile alınıyor. SIEM'e denetim aktarımı da yalnızca API ile (`:690-691`) (KS-22).

### P5 — Destek/Operasyon (SingularityRD ve müşteri ops)
Yeniden yapılandırma, DR, staging'den prod'a geçiş ve sıfırlama: §5. Yaşam döngüsü olayları: §6.

### P6 — Satın alma/Hukuk (sözleşme sonu)
Veri iadesi, tam dışa aktarım, imha sertifikası ve kaldırma: §7.

## 3. Sihirbaz adımları — beklenen ve var olan

UI'daki gerçek sıra: `checks` (`SystemChecksStep.tsx`, `useSystemChecks.ts`) → `data` (`DataSourceDialog.tsx`, `ConnectSource.tsx`, `SourceCollection.tsx`, `FileAndDemoSources.tsx`) → `ai` (`SetupProviderStep.tsx`, `ProviderKeyCard.tsx`, `ModelPlan.tsx`) → `workflows` (`WorkflowsStep.tsx`) → `limits` (`LimitsStep.tsx`, `MonthlyCeiling.tsx`, `SlackRoute.tsx`) → `done` (`SummaryStep.tsx`). Hepsi `clients/web/src/screens/setup/` altında.

| Beklenen adım | Durum | Kanıt |
|---|---|---|
| Sistem kontrolleri | VAR | 6 kontrol: DB, model gateway, storage, API health, alarm toplama, MCP (`useSystemChecks.ts:149-156`). GPU, disk, saat/NTP, TLS ve sertifika kontrolü yok |
| Kurum adı, saat dilimi (Europe/Istanbul), dil | EKSİK | aranan: `org_name\|organization_name\|timezone` (UI) → yok. Zaman UTC'ye sabit (`shared/utc.ts:1-2`). i18n kütüphanesi yok (`package.json` içinde `i18n` → yok) |
| Lisans aktivasyonu | EKSİK (ürün kararı açık) | aranan: `license_key\|license_expir` → yok; `NORTHSTAR_PLAN.md:434` |
| SSO (ya da sonra) | KISMİ: Ayarlar'da var, sihirbazda yok | `settings/SsoSection.tsx`; sihirbaz adım listesinde yok (`SetupScreen.tsx:31`) |
| Kullanıcı davet ve rol atama | KISMİ: Ayarlar'da elle oluşturma var | `UsersSection.tsx`; davet/e-posta yok |
| Dağıtım modu (yerel/bulut) ve sağlayıcı anahtar testi | VAR | 4 kart, anahtar kaydet ve `checkKey` ile yönlendirilebilirlik testi (`SetupProviderStep.tsx:34-67`, `:121-133`) |
| KVKK veri yerleşimi seçimi | KISMİ | Yalnızca etiket (`providerResidency.ts:5-17`); onay kaydı yok |
| Yerel model indirme/doğrulama ve GPU kontrolü | EKSİK | Ollama kartı yalnızca URL alıyor (`SetupProviderStep.tsx:140-151`); `pull` ya da `gpu` kodu yok. Kart "48 GB GPU" diyor (`:63`), paketin varsayılan modeli ise `llama3.1:8b` (`build-bundle.sh:60`) |
| Model atama | KISMİ | `ModelPlan` salt okunur; "Settings › AI models'ta değiştirin" diyor (`ModelPlan.tsx:59`) |
| Veri kaynağı: bağlantı testi | VAR | `ConnectSource.tsx:71-93`, MCP `connected` sonucu |
| Veri kaynağı: ilk poll ve alım doğrulama | VAR (kısmi) | `SourceCollection.tsx:61-110` `last_poll_at` değişimini bekliyor; alınan alarm sayısı ya da örnek alarm gösterilmiyor |
| Örnek alarm / demo | VAR (air-gap'te kapalı) | `FileAndDemoSources.tsx`, `demoMode.ts` |
| Müdahale yürütücüleri: bağla, test et, dry-run | EKSİK | Sihirbazda yok. Yürütücü kaydı yalnızca açılışta kuruluyor (`services/api/main.py:460`, `services/daemon/main.py:152`): Ayarlar'da açılan Defender/Entra/Palo Alto yeniden başlatmaya kadar çalışmaz ve UI bunu söylemez. Yürütücü testi yok (`core/response/executors/` içinde test/probe yok). Dry run yalnızca Ayarlar'da (`AutoInvestigateSection.tsx:321-326`) |
| Müdahale politikası (korunan varlık, dört göz) | KISMİ | Dört göz için farklı rol ekranı var (`SegregationSection.tsx`). `protected_targets` ve `asset_tags` yalnızca API ile (`yonetici-kilavuzu.md:343-345`). Varsayılan `asset_tags` boş (`policy.py:458`, `:487-498`): taze kurulumda yapılandırmayla korunan bir varlık yok |
| Otonomi katmanı (varsayılan "onayla") | KISMİ ve YANLIŞ YÖNLENDİRİYOR | Assist/Act kartı var, fakat **Act "Recommended" rozetli** (`WorkflowsStep.tsx:195-197`). Helm `DAEMON_FORCE_APPROVAL: "false"` (`values.yaml:844`). Belge düzenlenmiş sektör için `true` öneriyor (`yonetici-kilavuzu.md:440`). Kilit satırı "isolating a host gibi geri alınamayan eylemler her zaman kişi ister" diyor (`WorkflowsStep.tsx:204`), oysa `isolate_host` `AUTONOMOUS_ELIGIBLE` içinde (`core/autonomy/tiers.py:79-81`) |
| Bildirim: SMTP testi, Teams, Slack, webhook | KISMİ: yalnızca Slack | `SlackRoute.tsx:29`. SMTP yalnızca ortam değişkeniyle (`core/platform/email_service.py:1-15`), UI'da test yok. Teams entegrasyonu var (`core/integrations/microsoft_teams/`) ama sihirbazda yok |
| SLA politikaları | KISMİ: Ayarlar'da | `SlaPoliciesSection.tsx`; sihirbazda yok |
| Saklama (KVKK) | EKSİK (yalnızca API) | `yonetici-kilavuzu.md:603-604` "konsol ekranı yoktur" |
| SIEM'e denetim aktarımı | EKSİK (yalnızca API) | `yonetici-kilavuzu.md:690-691` |
| Yedek hedefi | EKSİK (Helm değeri ya da `backups.json`) | `yonetici-kilavuzu.md:770-773`, `:790-791`; UI'da `backup` → yok |
| Bütçe limitleri | VAR | Profil + aylık tavan (`LimitsStep.tsx`, `MonthlyCeiling.tsx`). Eşik uyarısı (örn. %80) yok |
| "Hazırsınız" özeti | VAR (koşulsuz) | `SummaryStep.tsx:143-189` |
| Rehberli ilk alarm | EKSİK | Yalnızca tur ve "Watch a hunt run" bağlantısı (`SummaryStep.tsx:24-28`) |
| Sihirbaza geri dönme | VAR | Menüde "Setup guide" ve üst çubuk çipi; ilerleme tarayıcıya bağlı |

## 4. Bulgu tablosu

| ID | Persona | Flow adımı | Eksik (ne yok / ne yanlış) | Kanıt | Önem | Sahip | Tahmini efor |
|---|---|---|---|---|---|---|---|
| KS-01 | Kurulumcu | install.sh install / helm install | Küme ön kontrolü yok: kubectl bağlamı, K8s sürümü, varsayılan StorageClass, kayıt defterine düğümlerden erişim, NetworkPolicy uygulayan CNI, GPU düğümü/allocatable, PVC için disk, ingress/DNS/sertifika. Hata ancak `--wait --timeout 15m` dolunca ya da ImagePullBackOff'ta görülüyor | `infra/airgap/install.sh:283-336` (ön kontrol yok); `Chart.yaml` yalnızca `kubeVersion: '>=1.25.0-0'`; aranan: `preflight` → yalnızca `upgrade_database.py` | YÜKSEK | Mühendislik | M |
| KS-02 | İlk yönetici | İlk tarayıcı ziyareti | Bootstrap'ta kurulum token'ı yok: ingress açıkken ya da Compose'un 0.0.0.0:6987 yayınında ilk ulaşan kişi Admin olur. Banka pentest'i bunu "taze kurulumda kimliksiz yönetici ele geçirme" olarak işaretler | `services/api/routers/auth.py:94-100`, `:240-308`; `docker-compose.yml:214-215`; `NOTES.txt:40-42` | GA-ENGELİ | Mühendislik | S-M |
| KS-03 | Kurulumcu | Helm NOTES | Kurulumcunun gördüğü ilk metin "Vigil SOC has been installed". Chart açıklaması, `home: vigilsoc.org`, `icon`, maintainer ve `vigil.local` host da upstream'e ait (NORTHSTAR'ın "Vigil adı görünen yerlerden çıkarıldı" iddiasıyla çelişiyor) | `infra/helm/vigil/templates/NOTES.txt:1`; `Chart.yaml:3-15`; `values.yaml:547`; `NORTHSTAR_PLAN.md:90` | ORTA | Mühendislik / Satış-Pazarlama | S |
| KS-04 | Kurulumcu (air-gap) | Helm NOTES | Air-gap/Ollama kurulumunda da "anthropicApiKey boş, AI özellikleri hata verir" uyarısı basılıyor: yanlış alarm ve destek çağrısı nedeni. NOTES'ta "konsol URL'i + ilk yönetici + sihirbaz" sırası yerine "Access the backend API" var | `NOTES.txt:13-23`, `:66-74`; `values-airgap.yaml` (anahtar yok) | DÜŞÜK | Mühendislik | S |
| KS-05 | Kurulumcu | Tek sunucu üretim | Compose ve host kurulumu için hazır üretim profili yok. Belgedeki yol `./start.sh` (uvicorn `--reload` ve Vite geliştirme sunucusu). Compose için elle `env_file` ve adres düzenlemesi gerekiyor; backend düz HTTP ve 0.0.0.0'da; TLS önerisi yok | `start.sh:299`, `:339`; `kurulum-internetsiz.md:197-202`; `docker-compose.yml:214-215` | YÜKSEK | Mühendislik / Destek-Operasyon | M |
| KS-06 | Değerlendirici | Masaüstü uygulaması | Masaüstü uygulaması internet (ghcr) ve Docker Desktop gerektiriyor, kimliği upstream'e ait (`ai.deeptempo.vigil`). Hangi senaryonun (değerlendirme mi, demo mu) desteklendiği belgede yok | `clients/desktop/electron-builder.yml:1`; `standalone/docker-compose.yml:98`; `src/main.ts:14`, `:282-294` | DÜŞÜK | Ürün | S |
| KS-07 | İlk yönetici | Bootstrap sonrası | İlk Admin için MFA ve kurtarma kodu adımı yok (belge "hemen açın" diyor, ürün yönlendirmiyor). Break-glass önerisi yalnızca belgede | `yonetici-kilavuzu.md:143-149`; sihirbaz adımları `SetupScreen.tsx:31` | ORTA | Mühendislik | S |
| KS-08 | İlk yönetici | TLS / ilk giriş | Güvensiz bağlam (HTTP, localhost dışı) algılanmıyor. `VIGIL_COOKIE_SECURE=true` ile giriş sessizce başarısız olur. Sertifika uyarısı ya da açıklaması yok | `values.yaml:789`; aranan: `isSecureContext\|location.protocol` → yok | ORTA | Mühendislik | S |
| KS-09 | Yönetici / Analist | Sihirbaz ilerlemesi | "Kurulum bitti" ve ilerleme tarayıcı `localStorage`'ında. İkinci yönetici baştan başlıyor, her analist her yeni tarayıcıda /setup'a düşüyor. Sunucu tarafında "kurulum tamamlandı, kim, ne zaman" kaydı yok (denetim izi yok) | `routing/SetupGate.tsx:13-16`; `setup/setupDismissed.ts:3-52`; `SetupScreen.tsx:187-213` | ORTA | Mühendislik | M |
| KS-10 | İlk yönetici | Finish setup | "Continue" doğrulama yapmıyor; veri ve sağlayıcı olmadan "AutoSecOps is ready" deniyor. Zorunlu asgari koşullar (≥1 kaynak ya da demo, ≥1 yönlendirilebilir model, bildirim) ve "eksik" uyarısı yok | `SetupScreen.tsx:144-151`, `:251-258`; `SummaryStep.tsx:60`, `:77`, `:143-144` | YÜKSEK | Ürün / Mühendislik | S |
| KS-11 | İlk yönetici | Time-to-value | Rehberli ilk alarm yok ("ilk alarm alındı → triyaj → kanıt → karar"). Kaynak testi alınan alarm sayısı ya da örnek göstermiyor. Health ekranı yapılandırılmış/eksik kontrol listesi değil; LLM harcaması, onaylar, koşular ve probe gösteriyor | `SourceCollection.tsx:99-108`; `SummaryStep.tsx:24-28`; `screens/health/HealthScreen.tsx:75-137` | YÜKSEK | Ürün | M |
| KS-12 | Değerlendirici (air-gap) | Demo ile keşif | Air-gap profili `DEMO_MODE=false`'u ortamdan verdiği için sihirbazın demo seçeneği "Demo mode is set by the server's environment" hatasına düşüyor. Home'daki "Explore with demo data" ortam kontrolü yapmadan UI'da "açık" gösteriyor | `infra/airgap/values-airgap.yaml:117`; `setup/demoMode.ts:7-12`; `services/api/routers/config.py:174-178`; `home/HomeScreen.tsx:284-290` | ORTA | Ürün / Mühendislik | S |
| KS-13 | Yönetici | "Finish setup · N left" | Kalan iş sayacı sihirbazla uyumsuz. Air-gap'te bitirilemeyen adımlar sayılıyor (Slack/PagerDuty kapalı; "≥2 farklı model"). Çip kalıcı olarak "eksik" gösteriyor. E-posta ve Teams bildirimi "notify" sayılmıyor | `services/api/routers/config.py:652`, `:699`; `values-airgap.yaml:106-107`; `shell/SocConsole.tsx:555-564` | ORTA | Ürün / Mühendislik | S |
| KS-14 | Yönetici / Analist | Kullanıcı ekleme | Davet akışı yok; yönetici parolayı kendisi yazıp paylaşıyor. İlk girişte değiştirme zorunluluğu yok; UI "en az 8 karakter" diyor (sunucu politikası farklı olabilir) | `settings/UsersSection.tsx:109`, `:291-295`; aranan: `must_change_password` → yok | ORTA | Mühendislik | M |
| KS-15 | Tümü | Kurum, saat dilimi, dil | Kurum adı, saat dilimi (Europe/Istanbul) ve Türkçe arayüz yok; zaman UTC'ye sabit; tüm sihirbaz metinleri İngilizce. Düzenlenmiş Türk müşteride, teknik olmayan yönetici için engel | `shared/utc.ts:1-2`; `clients/web/package.json` (i18n yok); `SetupScreen.tsx:41-78` | YÜKSEK | Ürün | L |
| KS-16 | Uyum | AI sağlayıcısı seçimi | KVKK yurt dışı aktarım için bilinçli seçim, onay kaydı ve uyarı yok; yalnızca kart altbilgisi var. Bulut sağlayıcıya "data leaves your site" seçimi denetim kaydına "kim, ne zaman, hangi gerekçeyle" olarak yazılmıyor | `setup/providerResidency.ts:5-17`; `SetupProviderStep.tsx:36-53` | YÜKSEK | Uyum / Ürün | M |
| KS-17 | Yönetici (air-gap) | Yerel model | Sihirbaz yerel model için indirme, sürüm, bütünlük ve GPU denetimi yapmıyor. Kart "48 GB GPU" diyor, paketteki varsayılan model `llama3.1:8b`, llm-stack'te GPU isteği yok. Yanlış beklenti ya da CPU'da çok yavaş triyaj | `SetupProviderStep.tsx:63`; `build-bundle.sh:60`; `k8s/llm-stack.yaml:64-78` | YÜKSEK | Mühendislik / Ürün | M |
| KS-18 | Yönetici | Müdahale yürütücüleri | Sihirbazda yürütücü bağlama, test ve dry-run adımı yok. Yürütücü kaydı yalnızca açılışta kuruluyor; UI'dan açılan yürütücü yeniden başlatmadan çalışmıyor ve UI bunu söylemiyor. Yürütücü bağlantı testi yok | `services/api/main.py:460`; `services/daemon/main.py:152`; `core/response/executors/wiring.py:103`; `AutoInvestigateSection.tsx:321-326` | YÜKSEK | Mühendislik | M |
| KS-19 | Yönetici / Uyum | Müdahale politikası | Korunan varlıklar (`protected_targets`, `asset_tags`) için konsol yok; varsayılan boş. Taze kurulumda yapılandırmayla korunan hiçbir DC veya break-glass hesabı yok (koruma yalnızca eylemin kendi beyan ettiği etiketle). Sihirbazda adım yok | `core/response/policy.py:456-498`, `:561-569`, `:648-655`; `yonetici-kilavuzu.md:343-354` | YÜKSEK | Ürün / Mühendislik | M |
| KS-20 | Yönetici / Uyum | Otonomi seçimi | Sihirbaz **Act'i "Recommended"** gösteriyor ve Helm varsayılanı `DAEMON_FORCE_APPROVAL=false`. Plan "GA varsayılanı onayla" diyor, kılavuz düzenlenmiş sektöre `true` öneriyor. Kilit metni yanlış: `isolate_host` otonom uygun sınıfta, ama metin "her zaman kişi ister" diyor | `setup/WorkflowsStep.tsx:195-204`; `values.yaml:844`; `core/autonomy/tiers.py:79-81`; `yonetici-kilavuzu.md:440-446`; `NORTHSTAR_PLAN.md:174` | YÜKSEK | Ürün / Uyum | S |
| KS-21 | Uyum | Saklama ve imha | Saklama politikası, kuru çalıştırma ve imha tutanağı için konsol ekranı yok; kurulumda politika yok, yani hiçbir veri imha edilmiyor. Teknik olmayan yönetici KVKK periyodik imha yükümlülüğünü yalnızca API ile yerine getirebiliyor | `yonetici-kilavuzu.md:567-568`, `:603-604`; UI'da `retention` yalnızca açıklama metni (`DataUploadsSection.tsx:12`) | YÜKSEK | Ürün / Uyum | M |
| KS-22 | Uyum | SIEM'e denetim aktarımı | Kurulum ve izleme için konsol yok (yalnızca API; test ucu var). Son hata ve imleç durumu UI'da görünmüyor | `yonetici-kilavuzu.md:686-697`; UI'da aranan: `audit_export\|auditExport` → yok | ORTA | Mühendislik | M |
| KS-23 | Yönetici | Bildirim kanalları | Sihirbazda yalnızca Slack var. E-posta/SMTP yalnızca ortam değişkeniyle ve UI testi yok. Teams entegrasyonu sihirbazda yok. Air-gap'te Slack kapalı, e-posta `console` (loga yazılıyor): air-gap kurulumda **hiçbir bildirim kanalı kurulamıyor**. Bankalarda Teams ve e-posta yaygın | `setup/SlackRoute.tsx:29`; `core/platform/email_service.py:1-15`; `values-airgap.yaml:106-107`; `infra/airgap/README.md:280` | YÜKSEK | Mühendislik / Ürün | M |
| KS-24 | Yönetici | Diğer eksik sihirbaz adımları | SSO, kullanıcı daveti, SLA ve yedek hedefi sihirbazda yok (SSO, kullanıcı ve SLA Ayarlar'da; yedek yalnızca Helm değeri ya da `backups.json` ile) | `SetupScreen.tsx:31`; `settings/SettingsScreen.tsx:56-101`; `yonetici-kilavuzu.md:770-791` | ORTA | Ürün | M |
| KS-25 | Destek-Operasyon | Kurulumu sıfırlama | **Doğrulandı:** CSRF zorlanan kurulumda (Helm `VIGIL_CSRF_REPORT_ONLY: "false"`, `values.yaml:782`) `reset-setup.sh` X-CSRF-Token göndermiyor; muafiyet yalnızca webhook, ingest, mcp ve internal yollarında. İlk `POST /auth/login` ya da Bearer ile ilk `PUT`/`DELETE` 403 alıyor. Ayrıca sihirbaz kapısı artık `localStorage`'da: betik sunucu durumunu temizlese de kapı yeniden açılmıyor. Başlıktaki "setupSteps.ts gate" açıklaması eskimiş. Helm'de pod'a karşı çalıştırma yolu (repo, venv, `localhost:6987`) yok | `scripts/reset-setup.sh:2-6`, `:92-100`, `:154-159`; `middleware/csrf.py:71`, `:144-173`; `setup/setupSteps.ts:1-9`; `STATUS.md:60` (bilinen) | ORTA (bilinen) | Mühendislik | S |
| KS-26 | Destek-Operasyon | Yapılandırma dışa ve içe aktarma | Staging'den prod'a ve DR için tüm yapılandırmayı (entegrasyonlar sırsız, politika, otonomi katmanları, SLA, saklama, iş akışları, model atamaları) dışa ve içe aktarma yok. Yalnızca tam yedek ve geri yükleme var | aranan: `config/export\|import_config\|exportConfig` → yok; `core/backup` var | YÜKSEK | Mühendislik | L |
| KS-27 | Destek-Operasyon | Güncelleme (offline) | Ürün içinde "yeni sürüm var / şu sürümdesiniz / sürüm notları" yüzeyi yok. Yalnızca belgelenmiş "yeni paket → doğrula → install" yolu var. Sürüm yalnızca geri bildirim bağlantısında okunuyor | `infra/airgap/README.md:282-283`; `shell/UserMenu.tsx:61`; aranan: `update_available\|latest_version` → yok | ORTA | Ürün | M |
| KS-28 | Satış / Yönetici | Lisans süresi | Lisans ya da abonelik süresi kavramı yok: bitiş uyarısı, destek süresi ve yetki görünümü yok (lisans modeli açık karar) | aranan: `license_key\|license_expir` → yok; `NORTHSTAR_PLAN.md:434` | ORTA | Ürün / Hukuk | M |
| KS-29 | Destek-Operasyon | Sertifika süresi | Ingress TLS, entegrasyon uç noktası sertifikaları ve kanıt paketi/kontrol noktası imza anahtarları için bitiş izleme ve uyarı yok | aranan: `cert_expir\|not_after\|days_until_expiry` → yok | DÜŞÜK | Mühendislik | M |
| KS-30 | Yönetici | LLM bütçesi tükendi | Koşu ve bulgu düzeyinde ileti var, bütçe baskısında küçük modele düşülüyor. Fakat aylık tavana yaklaşma (%80) ya da dolma için genel banner, bildirim ve durum satırı yok; status line bütçeyi okumuyor | `screens/dashboard/FindingPopup.tsx:264`; `workflows/WorkflowsScreen.tsx:1006`; `core/lanes/alert_lanes.py:517-520`; `shell/statusLine.ts:28-34` | ORTA | Mühendislik | S-M |
| KS-31 | Yönetici | Entegrasyon kimlik bilgisi süresi | Entra/Defender client secret ve API token bitiş tarihi izlenmiyor. Sorun ancak poll hataya düşünce durum satırında "consecutive errors" olarak görünüyor | `shell/statusLine.ts:37-39`; aranan: `credential_expir\|secret_expir` → yok | ORTA | Mühendislik | M |
| KS-32 | Destek-Operasyon | Yedek başarısız | Helm CronJob yalnızca pg_dump alıyor ve durum dosyası yazmıyor; backend `backup_status.json` okuduğu için Helm'de yedek durumu her zaman "bilinmiyor". Compose'da durum yalnızca bir `recommendations` metninde ve Prometheus metriğinde; UI'da gösterilmiyor. Helm yedeği varsayılan olarak kapalı | `core/backup/status.py:1-37`; `services/api/routers/storage_status.py:97-107`; `infra/helm/vigil/templates/backup-cronjob.yaml:3`, `:96`; `core/platform/monitoring.py:185`; UI'da aranan: `backup` → yok; `yonetici-kilavuzu.md:790-791` | YÜKSEK | Mühendislik | M |
| KS-33 | Destek-Operasyon | Depolama doluyor | DB, PVC ve iş dizini doluluğu UI'da izlenmiyor (Medic'teki disk kodu dondurulmuş). Önce yazma hataları, sonra kesinti | `services/medic/api/status.py` (icebox, `NORTHSTAR_PLAN.md:74`); `shell/statusLine.ts` (disk yok) | ORTA | Mühendislik | M |
| KS-34 | Yönetici / Uyum | Kullanıcı ayrılıyor | Elle devre dışı bırakma ve silme var; OIDC JIT ve rol eşlemesi var. SCIM ve otomatik deprovision yok; IdP'de kapatılan hesabın yerel oturum ya da parolası için periyodik erişim gözden geçirme raporu yok | `UsersSection.tsx:149-160`; `core/auth/oidc.py:120-126`; aranan: `scim\|deprovision` → yok | ORTA | Mühendislik | L |
| KS-35 | Uyum | Model değiştirildi | Değişiklik `config_audit_log`'a yazılıyor (iyi). Fakat model değişince QA ve kanarya tabanının yeniden kurulması ya da otonomi katmanlarının "yeniden kanıtlanana kadar Approve'a dönmesi" için bir uyarı yok | `services/api/routers/ai_config.py:131-221`; `core/quality/canary_router.py` | ORTA | Ürün | M |
| KS-36 | Uyum | İmha çalıştı | İmha tutanağı yalnızca API'den (`/compliance/retention/reports`); yaklaşan ya da gerçekleşen imha için UI bildirimi ve kuru çalıştırma önizleme ekranı yok | `yonetici-kilavuzu.md:582-584`, `:603-604` | ORTA | Ürün | M |
| KS-37 | Hukuk / Satın alma | Sözleşme sonu: veri iadesi | "Her şeyi dışa aktar" (vakalar, kanıt paketleri, denetim zinciri, defter arşivi, yapılandırma) için tek bir prosedür ya da komut yok. Parçalar API'lerde dağınık. Sözleşmedeki veri iadesi maddesi karşılanamıyor | aranan: `decommission\|veri iadesi\|sözleşme sonu` → yok; parçalar `yonetici-kilavuzu.md:623-697` | YÜKSEK | Ürün / Hukuk | M |
| KS-38 | Hukuk / Uyum | Kaldırma ve güvenli imha | Belgelenmiş kaldırma yok: `helm uninstall` sonrası `resource-policy: keep` ile kalan PVC'ler, Postgres, Redis, Bifrost (`logs.db` dahil), Ollama PVC, `secrets.enc`/`master.key`, restic yedekleri, S3 nesneleri, kanıt imza anahtarları ve imaj/kayıt defteri temizliği. Kripto imha (anahtarı silerek) ve imha sertifikası yok. KVKK imha ve BDDK için gerekli | aranan: `uninstall\|decommission\|wipe\|güvenli silme` → yalnızca `docs/operations/rpo-rto.md:185` | YÜKSEK | Destek-Operasyon / Uyum | M |
| KS-39 | Yönetici | Kurulum sonrası belgeler | Kılavuzlar sihirbazdan hiç söz etmiyor ve ilk 15 dakikayı "Ayarlar → AI models" ve ortam değişkenleriyle anlatıyor. Sihirbaz, belge ve `reset-setup.sh` birbirinden kopuk; teknik olmayan yönetici için Türkçe "ilk gün" rehberi yok | `kurulum-internetsiz.md:221-251`; aranan (docs/guide): `sihirbaz\|/setup\|wizard` → yok | ORTA | Destek-Operasyon / Ürün | S |
| KS-40 | Kurulumcu / Yönetici | Kurulum sonrası sağlık | Tek yerden "neler yapılandırıldı, neler eksik" görünümü yok (yedek, saklama, denetim aktarımı, MFA, TLS, CSRF, DEV_MODE, otonomi modu, korunan varlık, bildirim). Health ekranı operasyon metrikleri gösteriyor | `screens/health/HealthScreen.tsx:75-137`; `shell/statusLine.ts:52-60` | YÜKSEK | Ürün / Mühendislik | M |

## 5. Yönetici devri ve yeniden yapılandırma (özet)

- **Yapılandırmayı dışa ve içe aktarma**: yok (KS-26).
- **DR**: `core.backup` restic yedeği ve geri yüklemesi var, `--test` ile dokunmadan sınama da var. Geri yükleme bekleyen onayları reddediyor ve JWT'yi döndürüyor (`yonetici-kilavuzu.md:745-786`). Bu iyi.
- **Sıfırlama**: KS-25 (bozuk ve eskimiş).

## 6. Sonradan karşılaşılan yaşam döngüsü olayları — UI'da nasıl görünüyor

| Olay | UI yüzeyi | Bulgu |
|---|---|---|
| Güncelleme var (offline) | Yok | KS-27 |
| Lisans süresi doluyor | Yok | KS-28 |
| Sertifika süresi doluyor | Yok | KS-29 |
| LLM bütçesi tükendi | Koşu/bulgu düzeyinde; AutoOps'ta "Intake paused: hourly limit reached" (`AutoOpsScreen.tsx:313`) | KS-30 |
| Entegrasyon kimlik bilgisi süresi doluyor | Hata olduktan sonra durum satırında | KS-31 |
| Model değiştirildi | Denetim kaydı var, UI uyarısı yok | KS-35 |
| Saklama/imha çalıştı | Yalnızca API tutanağı | KS-21, KS-36 |
| Yedek başarısız | Yok (Helm'de durum bile yok) | KS-32 |
| Depolama doluyor | Yok | KS-33 |
| Kullanıcı ayrılıyor | Elle devre dışı bırakma | KS-34 |
| Sözleşme sonu | Yok | KS-37, KS-38 |

## 7. Kaldırma ve hizmetten çıkarma
Belge ve betik yok (KS-38). Geri alma olarak yalnızca `helm rollback` belgelenmiş (`infra/airgap/README.md:303-304`).

## 8. Var ve çalışıyor görünüyor

- **Air-gap paket doğrulaması**: imza (minisign, Ed25519, cosign), SHA256, fazladan dosya/symlink/FIFO reddi, manifest tutarlılığı, arşiv üye güvenliği, özel hazırlık kopyası (TOCTOU'ya karşı), `--dry-run`, anlaşılır `REFUSED` iletileri ve sorun giderme tablosu (`install.sh:1-310`, `README.md:290-304`).
- **Idempotent kurulum**: `helm upgrade --install --wait`, `kubectl apply`, model tar'ı Ollama pod'una aktarma, kural korpusunu backend'e aktarma.
- **Varsayılan yönetici yok**: bootstrap yarışa karşı advisory lock ile korunuyor, hız sınırı var, ilk hesaptan sonra kalıcı kapanıyor, denetim olayı yazılıyor. Servis hesabı bootstrap'i kapatmıyor (`auth.py:208-308`).
- **DEV_MODE**: Helm'de kapalı; NOTES ve konsol uyarı veriyor. CSRF ve Secure çerez Helm'de zorlanıyor.
- **`start.sh`**: URL'leri ve "ilk çalıştırma: yönetici hesabını oluştur" iletisini basıyor (`start.sh:277-292`). `setup_dev.sh` ön koşul uyarıları veriyor.
- **Sihirbaz**:
  - Sistem kontrolleri, sırayla ve yeniden çalıştırılabilir.
  - Yalnızca canlı MCP sunucusu olan kaynakları gösteriyor.
  - Kimlik bilgisi reddini alan adıyla açıklıyor.
  - Bağlantı testi ve ilk poll testi var; sırlar yalnızca "set" olarak dönüyor.
  - Dosya yükleme ve ilerleme var; demo seçeneği var.
  - Dört sağlayıcı kartı ve yerleşim etiketi; anahtar doğrulama ve yönlendirilebilirlik.
  - İş akışı aç/kapa, otomatik soruşturma anahtarı.
  - Limit profilleri, limiti artırırken onay, aylık tavan.
  - Slack satır içi bağlama.
  - Her satırı kendi API'sinden okuyan özet; "Change" ile adıma dönme.
  - "Save and finish later", menüden ve çipten geri dönme, 1 dakikalık tur.
  - Yetkisiz kullanıcı için ayrı ekran.
- **Upstream setup dalları**: AutoSecOps'a tamamen alınmış ve ilerletilmiş (`useSystemChecks.ts`, rail uyarı işareti, `refusal()`).
- **Diğer**:
  - Model ataması değişikliği `config_audit_log`'a yazılıyor.
  - Restic yedeği, test ederek geri yükleme, yükseltme öncesi otomatik yedek (Compose).
  - Dört göz için farklı rol ekranı ve görevler ayrılığı raporu.
  - Saklama, denetim aktarımı ve kanıt paketi API'leri belgeli ve dürüst ("konsol ekranı yoktur").
