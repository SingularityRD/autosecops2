# Mevzuat eşlemesi

> **Bu belge hukuki görüş değildir.** Aşağıdaki tablolar, düzenlemelerin
> AutoSecOps'u kullanan kurumdan beklediği bazı kontrolleri ürünün bu sürümdeki
> (`main` @ `b8795def`) özelliklerine ve bu özelliklerin üretebildiği kanıta
> eşler. Yükümlülük kurumundur; bir aracın varlığı uyumu kendi başına sağlamaz.
> Eşleme, kurumun uyum ve hukuk ekibiyle doğrulanmalıdır. Madde numarası
> verilmeyen satırlarda ilgili hükmün eşlenmesi kurumun uyum ekibine bırakılmıştır.

> **English summary (not legal advice).** Maps selected expectations of the
> Turkish banking regulator's information-systems regulation (BDDK), the
> Turkish data-protection law (KVKK, Law 6698), the EU Digital Operational
> Resilience Act (DORA, Regulation 2022/2554), the NIS2 Directive (2022/2555),
> the Turkish Capital Markets Board's information-systems communiqué (SPK
> VII-128.9) and ISO/IEC 27001:2022 Annex A to AutoSecOps features in this
> release and the evidence each produces. Status is *Karşılanıyor* (supported),
> *Kısmi* (partly) or **Planlı** (planned, with the branch; not in this release).

Durum sütunu: **Karşılanıyor** — özellik bu sürümde var ve kanıt üretir;
**Kısmi** — özellik var ama beklentinin bir kısmı kurum süreciyle ya da planlı bir
paketle tamamlanır; **Planlı** — bu sürümde yok (dal adıyla). Özelliklerin
ayrıntısı: [yönetici kılavuzu](yonetici-kilavuzu.md), [güvenlik teknik
belgesi](guvenlik-teknik-belgesi.md); kalan riskler: [tehdit
modeli](tehdit-modeli.md#açık-riskler).

## Ortak kanıt kaynakları

Tablolarda kısaltılarak anılan kanıtlar:

| Kod | Kanıt | Nasıl üretilir |
|---|---|---|
| K1 | Sıfır egress test çıktısı | `pytest tests/airgap/test_egress_inventory.py --no-cov` ve `pytest tests/airgap/test_runtime_egress.py --no-cov`; CI'da `.github/workflows/airgap.yml` |
| K2 | Air-gap yapılandırması | Kurulumdaki `values-airgap.yaml` / `airgap.env` ve `kubectl get networkpolicy -n <ad alanı>` |
| K3 | Paket bütünlüğü | `./install.sh verify --pubkey ...` çıktısı, `SHA256SUMS`, imza dosyası |
| K4 | Rol ve izin matrisi | `GET /api/users/roles/list`; CI'da `tests/security/test_route_permissions.py` ve her rota × her rol için `tests/security/route_role_matrix.json` (`tests/security/test_route_role_matrix.py`) |
| K5 | Kullanıcı listesi ve MFA durumu | `GET /api/users/` (rol, `mfa_enabled`, son giriş) |
| K6 | Ayar değişikliği kaydı | `config_audit_log` tablosu (kim, ne zaman, eski/yeni değer, gerekçe; sırlar maskeli). LLM sağlayıcı (`llm_provider`), beceri (`skill`), özel iş akışı (`custom_workflow`), kural kaynağı (`detection_rules`), SLA politikası (`sla_policy`), bütçe ve sistem ayarları dahil |
| K7 | Müdahale eylemi ve onay kaydı | `approval_actions`; `GET /api/v1/approvals`; vaka Actions sekmesi (`GET /api/cases/{case_id}/actions/timeline`) |
| K8 | Defter ve denetim zinciri bütünlük doğrulaması | `python -m core.audit.verify --agent-events --require-signature --public-key <anahtar>` (ajan defteri, `audit_chain`, imzalı kontrol noktaları; temizse çıkış 0); `npm run ledger:verify` (ajan katmanında); `GET /api/workflows/runs/{run_id}/verify` |
| K9 | Vaka denetim kaydı | Vaka → Record sekmesi (`case_audit_logs`) |
| K10 | Düzenleyici bildirim sayaçları ve taslaklar | `GET /api/cases/{case_id}/regulatory/clocks`, `.../regulatory/events`, `.../regulatory/drafts` |
| K11 | Yedek ve geri yükleme testi | `./start.sh restore ... --test` çıktısı; konsolda depolama durumu "Last successful backup" |
| K12 | Doğruluk ölçümü | Karne (`GET /api/qa/scorecard`); kanarya sonuçları (`GET /api/quality/canaries`, yalnız Admin) |
| K13 | Soruşturma gözetim zinciri | `GET /api/orchestrator/investigations/{investigation_id}/chain-of-custody` |
| K14 | Saklama politikaları, yasal saklama listesi, periyodik imha tutanağı | `GET /api/compliance/retention/policies`, `GET /api/compliance/retention/legal-holds`, `GET /api/compliance/retention/reports` (JSON ya da Markdown) |
| K16 | Görevler ayrılığı raporu ve onay kararları | `GET /api/response/segregation/export?format=csv` (öneren, onaylayan, ikinci onaylayan, yürüten, rolleri, ihlaller); `approval_decisions` tablosu; Ayarlar → System → Segregation of duties |
| K18 | Vaka kanıt paketi | Vaka → Record → **Evidence pack** (`GET /api/cases/{case_id}/evidence-pack`); denetçi `scripts/autosecops verify-bundle <paket> --public-key <anahtar>` ile çevrimdışı doğrular |
| K19 | Denetim olaylarının SIEM'e aktarımı | `GET /api/compliance/audit-export/status` (hedef ve kaynak başına imleç, son teslim, son hata); SIEM'deki `autosecops.audit.v1` / CEF / RFC 5424 olayları; `autosecops_audit_export_*` metrikleri |
| K20 | Kimlik sağlayıcı (SSO) yapılandırması ve girişleri | `GET /api/auth/sso/admin/config` (sağlayıcılar, rol eşlemesi, giriş politikası, break-glass hesapları); `config_audit_log` içinde `sso_login` / `sso_failure`; K22'de `sso_login` |
| K22 | Kimlik ve kullanıcı yönetimi olay kaydı | `case_audit_logs` içinde `entity_type = 'auth'` satırları: giriş (başarılı, başarısız, kilitleme, MFA hatası), SSO girişi, çıkış, MFA ve parola değişiklikleri, parola sıfırlama, kullanıcı oluşturma/güncelleme/devre dışı bırakma/silme, rol değişikliği; kim, ne zaman, IP, sonuç. SIEM aktarımından bağımsız, `audit_chain`'de zincirli (K8 ile doğrulanır); toplu bulgu dışa aktarımı `entity_type = 'findings_export'` |
| K21 | FIPS modu | `FIPS_MODE=true` ile çalışan süreçlerin açılış kaydı (FIPS sağlayıcısı yoksa süreç başlamaz); [docs/fips.md](../fips.md) |
| K17 | Otonomi katmanları ve değişiklik kaydı | `GET /api/autonomy/tiers` (katman matrisi, kategori başına QA sınırı); `GET /api/autonomy/audit` (yükseltme, devre kesici düşürmesi, kanıt bağlantısı) |
| K15 | Kubernetes yedek ve sıcak yedek kanıtı | yedek CronJob iş geçmişi ve döküm `.sha256` dosyaları; daemon `/health` `role` alanı; [docs/operations/rpo-rto.md](../operations/rpo-rto.md) tatbikat kaydı |

## BDDK — Bankaların Bilgi Sistemleri ve Elektronik Bankacılık Hizmetleri Hakkında Yönetmelik

| Beklenti | AutoSecOps özelliği (bu sürüm) | Kanıt | Durum |
|---|---|---|---|
| Birincil ve ikincil sistemlerin yurt içinde bulundurulması; verinin kurum denetiminde kalması | Kendi altyapısında kurulum (Helm/Compose); internetsiz kurulum paketi; yerel model (Ollama); sıfır egress profili | K1, K2, K3 | Karşılanıyor (kurulum yeri kurumun kararı) |
| İz kayıtlarının tutulması, bütünlüğünün korunması | Ajan defterinde koşu başına hash zinciri ve salt ekleme; onay ve vaka denetim kayıtları `audit_chain`'de zincirli; zincir başları Ed25519 imzalı kontrol noktasında; ayar kayıtları | K6, K7, K8, K9 | Kısmi — ayar kayıtları ve onay kararları zincirsiz; kontrol noktası imza anahtarı verilmeden yazılmaz (R6) |
| İz kayıtlarının merkezi izleme sistemine aktarılması | Denetim akışının syslog (TLS) ya da HTTPS ile SIEM'e aktarımı: ajan defteri, onaylar, kimlik doğrulama olayları, ayar ve vaka kayıtları, imzalı kontrol noktaları; en az bir kez teslim | K19 | Kısmi — aktarım varsayılan kapalı, kurum açmalı; serbest metinde kişisel veri maskelemesi en iyi çabadır (yapısal alanlar güvenilir); `approval_decisions` aktarılmaz |
| Görevler ayrılığı | Rol matrisi; onay yetkisi (`ai_decisions.approve`) yalnız Senior Analyst ve üstünde; kimlik eylemlerinde dört göz onayı; sınıf başına farklı rol koşulu; karar başına rol kaydı ve görevler ayrılığı raporu; atayan kişi yalnızca kendi izinlerini aşmayan rolü atayabilir; model onay veremez | K4, K5, K7, K16 | Kısmi — farklı rol koşulu varsayılan kapalı (R3); onaylanmış MCP araçları tek onayla çalışır (R2) |
| Erişim yönetimi, kimlik doğrulama | Yerel hesaplar, parola politikası, kilitleme, TOTP MFA, oturum iptali; OIDC SSO, grup → rol eşlemesi, yerel girişi break-glass hesaplarına sınırlama | K4, K5, K20 | Kısmi — MFA AutoSecOps'ta zorunlu kılınamaz (SSO kullanılıyorsa IdP'de zorunlu kılınabilir) |
| Yetkili kullanıcı işlemlerinin kayıt altına alınması | Giriş ve başarısız giriş, kullanıcı oluşturma/silme, rol değişikliği, MFA ve parola olayları (zincirli, SIEM aktarımından bağımsız); onaylayan ve onay zamanı; ayar değiştiren kullanıcı ve eski/yeni değer; toplu bulgu dışa aktarımı | K22, K6, K7, K8 | Karşılanıyor (ayar kaydı zincirsizdir, R6; veritabanında doğrudan yapılan rol izni değişikliği kaydedilmez, R13) |
| Bilgi güvenliği olay yönetimi | Alarm alımı, triage, vaka yönetimi, SLA izleyicisi, vaka bildirimleri | K9, K7 | Karşılanıyor (süreç kurumun) |
| Yedekleme ve iş sürekliliği | Şifreli ve doğrulanan restic yedeği, test geri yükleme, yükseltme öncesi otomatik yedek (Compose/host); Helm yedek CronJob'u; daemon sıcak yedeği; RPO/RTO belgesi | K11, K15 | Kısmi — CronJob varsayılan kapalı ve dökümü şifrelemez; RTO kurumun tatbikatıyla ölçülmeli (R17) |
| Dış hizmet (model sağlayıcı) riskinin yönetimi | Yerel model ile dış sağlayıcıya bağımlılığın kaldırılması | K1, K2 | Karşılanıyor (air-gap profiliyle) |
| Kriptografik anahtar yönetimi | Bant dışı imza anahtarı; şifreli sır deposu; Secret/ExternalSecrets; isteğe bağlı FIPS 140-3 modu | K3, K21 | Kısmi — `master.key` için yerleşik döndürme yok; FIPS modunda kontrol noktası ve kanıt paketi imzaları Ed25519 kalır |

## KVKK — 6698 sayılı Kişisel Verilerin Korunması Kanunu

| Beklenti | AutoSecOps özelliği (bu sürüm) | Kanıt | Durum |
|---|---|---|---|
| Md. 12 — veri güvenliği için teknik tedbirler (erişim yetkisi, şifreleme, kayıt) | Rol matrisi; sırların şifreli saklanması; şifreli yedek; denetim kayıtları; SIEM aktarımında kişisel veri maskelemesi | K4, K6, K8, K11, K19 | Kısmi — açık riskler tehdit modelinde (ör. R2, R6); idari tedbirler kurumun |
| Md. 9 — yurt dışına aktarım kısıtları | Yerel model, internetsiz kurulum, bulut sağlayıcı anahtarları boş; egress kanıtı | K1, K2 | Karşılanıyor (air-gap profiliyle); bulut sağlayıcı seçilirse aktarım kurumun değerlendirmesine tabidir |
| Md. 4 — işlendikleri amaç için gerekli süre kadar muhafaza | Veri sınıfı başına saklama süresi ve yöntemi (silme / anonimleştirme); yasal saklama | K14 | Karşılanıyor (sürelerin belirlenmesi kurumun; kurulumda politika yoktur) |
| Md. 7 ve Silme, Yok Etme veya Anonim Hale Getirme Yönetmeliği — periyodik imha, imha kaydı | Zamanlanmış ya da elle başlatılan imha işi (kuru çalıştırma varsayılan); vaka bazında yasal saklama; periyodik imha tutanağı | K14 | Kısmi — tutanak kayıtları zincirsiz (R6); elle silme uçları tutanağa girmez (R8) |
| Kişisel verilere erişimin kaydı | Ayar ve vaka değişiklik kayıtları; ajan defteri; giriş kayıtları; toplu bulgu dışa aktarımının kaydı (kim, seçim, satır sayısı) | K6, K8, K9, K22 | Kısmi — salt okuma erişimleri kaydedilmez |

## DORA — (AB) 2022/2554

| Beklenti | AutoSecOps özelliği (bu sürüm) | Kanıt | Durum |
|---|---|---|---|
| Md. 10 — anormal faaliyetin tespiti | Alarm toplama (federation), AI triage, kanarya ile tespit oranı ölçümü, QA karnesi | K12 | Karşılanıyor |
| Md. 11 — müdahale ve kurtarma | Onaylı müdahale eylemleri (Cloudflare, Defender, Entra ID, PAN-OS); müdahale politikası; kategori başına otonomi katmanları ve devre kesici; süre dolunca ve elle geri alma; eylem zaman çizelgesi | K7, K17 | Kısmi — onaylanmış MCP araçları politikasız çalışır (R2) |
| Md. 12 — yedekleme politikaları, geri yükleme | Şifreli, doğrulanan yedek; test geri yükleme; geri yüklemede bekleyen onayların reddi ve oturum anahtarı döndürme; Helm yedek CronJob'u; daemon sıcak yedeği; RPO/RTO hedefleri | K11, K15 | Kısmi — RTO kurum ortamında ölçülmeli; oturum anahtarı kurulum dışında tanımlıysa (ör. Kubernetes Secret) elle döndürülmeli (R17, R29) |
| Md. 17 — BİT olay yönetim süreci, kayıt | Vaka yönetimi, zincirli vaka denetim kaydı, gözetim zinciri dışa aktarımı, vaka kanıt paketi | K9, K13, K18 | Karşılanıyor |
| Md. 18 — olay sınıflandırması | Vakada "büyük olay" sınıflandırma anı (`classification_at`) kaydı | K10 | Kısmi — sınıflandırma kriterlerinin uygulanması kurumun |
| Md. 19 — büyük olayların süreli bildirimi (ilk bildirim, ara rapor, nihai rapor) | DORA sayaçları: ilk bildirim `min(sınıflandırma + 4 saat, farkına varma + 24 saat)`, ara rapor bildirim + 72 saat, nihai rapor son ara rapor + 1 ay; süreler kiracı başına ayarlanabilir; an kayıtları zincirli; rapor taslakları vakanın kanıtından | K10 | Karşılanıyor (resmî bildirimin gönderimi kurumun) |
| Kayıtların bütünlüğü | Defter zinciri, onay ve vaka denetim zinciri, imzalı kontrol noktaları, düzenleyici an zinciri ve zincir başı çapası | K8, K10 | Kısmi — ayar kayıtları ve onay kararları zincirsiz; tablo sahibi düzenleyici zinciri yeniden yazabilir (tehdit modeli R6, R27) |
| Md. 28–30 — üçüncü taraf BİT riski | Yerel model; dış entegrasyonların varsayılan kapalı olması; egress envanteri | K1 | Kısmi |
| Kanıt paketi | Vaka başına imzalı, kendi doğrulayıcısını taşıyan ZIP: kayıtlar, eylemler, defter olayları, AI karar kökeni, düzenleyici anlar | K18 | Karşılanıyor (`EVIDENCE_PACK_SIGNING_KEY` verilmelidir; yoksa paket geçici anahtarla imzalanır) |

## NIS2 — (AB) 2022/2555

| Beklenti | AutoSecOps özelliği (bu sürüm) | Kanıt | Durum |
|---|---|---|---|
| Md. 23 — 24 saat erken uyarı | NIS2 erken uyarı sayacı: farkına varma + 24 saat | K10 | Karşılanıyor |
| Md. 23 — 72 saat olay bildirimi | Farkına varma + 72 saat sayacı | K10 | Karşılanıyor |
| Md. 23 — 1 ay nihai rapor | Bildirim + 1 ay sayacı; rapor taslağı | K10 | Karşılanıyor |
| Md. 21 — olay ele alma | Vaka yönetimi, onaylı müdahale | K7, K9 | Karşılanıyor |
| Md. 21 — iş sürekliliği, yedek yönetimi | Şifreli yedek ve test geri yükleme; Helm yedek CronJob'u; daemon sıcak yedeği | K11, K15 | Kısmi — CronJob varsayılan kapalı, döküm şifresiz (R17) |
| Md. 21 — tedarik zinciri güvenliği | İmzalı kurulum paketi; CI'da imaj taraması | K3 | Kısmi — SBOM ve imzalı imajlar Planlı — `wp/w4.7-release`, bu sürümde yok |
| Md. 21 — kriptografi politikaları | Kriptografi envanteri (güvenlik teknik belgesi §8); FIPS 140-3 modu | K21 | Kısmi — FIPS modu FIPS etkin ayrı imaj ister; FIPS modunda kontrol noktası ve kanıt paketi imzaları Ed25519 kalır, `ssh_tunnel` desteklenmez |
| Md. 21 — erişim denetimi, çok faktörlü kimlik doğrulama | Rol matrisi, TOTP MFA, OIDC SSO | K4, K5, K20 | Kısmi — MFA AutoSecOps'ta zorunlu kılınamaz (SSO ile IdP'de zorunlu kılınabilir) |

## SPK — Bilgi Sistemleri Yönetimi Tebliği (VII-128.9)

| Beklenti | AutoSecOps özelliği (bu sürüm) | Kanıt | Durum |
|---|---|---|---|
| Bilgi güvenliği yönetimi, olay yönetimi | Alarm triage, vaka yönetimi, SLA izleme | K9 | Karşılanıyor (süreç kurumun) |
| İz kayıtları ve bütünlüğü | Defter zinciri; zincirli onay/vaka kayıtları ve imzalı kontrol noktaları; ayar kayıtları; SIEM aktarımı | K6–K9, K19 | Kısmi — ayar kayıtları zincirsiz (R6); SIEM aktarımı varsayılan kapalı |
| Kimlik doğrulama ve erişim yönetimi | Rol matrisi, MFA, kilitleme, oturum iptali, OIDC SSO | K4, K5, K20 | Kısmi (MFA AutoSecOps'ta zorunlu kılınamaz) |
| Görevler ayrılığı | Onay yetkisinin rolle sınırlanması; kimlik eylemlerinde dört göz onayı; sınıf başına farklı rol koşulu; görevler ayrılığı raporu | K4, K7, K16 | Kısmi — farklı rol koşulu varsayılan kapalı (R3); R2 |
| Yedekleme ve iş sürekliliği | Şifreli yedek, test geri yükleme, Helm yedek CronJob'u, daemon sıcak yedeği | K11, K15 | Kısmi (R17) |
| Dış hizmet alımı | Yerel model, egress kanıtı | K1, K2 | Karşılanıyor (air-gap profiliyle) |

## ISO/IEC 27001:2022 — Ek A kontrolleri

| Kontrol | AutoSecOps özelliği (bu sürüm) | Kanıt | Durum |
|---|---|---|---|
| A.5.3 Görevler ayrılığı | Onay yetkisi rolle sınırlı; kimlik eylemlerinde dört göz onayı; sınıf başına farklı rol koşulu; görevler ayrılığı raporu | K4, K7, K16 | Kısmi — farklı rol koşulu varsayılan kapalı (R3); R2 |
| A.5.15 Erişim denetimi / A.5.18 Erişim hakları | Rol matrisi, rota başına izin, rol atama kısıtı | K4, K5 | Karşılanıyor |
| A.5.16 Kimlik yönetimi | Yerel hesap yaşam döngüsü, hizmet hesabı Viewer'a kilitli; OIDC SSO ile ilk girişte hesap oluşturma ve grup → rol eşlemesi | K5, K20 | Kısmi — SCIM yok: IdP'de kapatılan hesabın açık oturumu için AutoSecOps'ta da devre dışı bırakma gerekir |
| A.5.17 Kimlik doğrulama bilgisi / A.8.5 Güvenli kimlik doğrulama | Parola politikası, bcrypt ya da PBKDF2-HMAC-SHA256, TOTP, kilitleme, OIDC SSO | K5, K20 | Kısmi (MFA AutoSecOps'ta zorunlu değil) |
| A.5.21 BİT tedarik zinciri | İmzalı paket, Trivy, Dependabot | K3 | Kısmi — SBOM Planlı — `wp/w4.7-release`, bu sürümde yok |
| A.5.24–A.5.26 Olay yönetimi planlama, değerlendirme, müdahale | Triage, vaka, onaylı müdahale, eylem zaman çizelgesi | K7, K9 | Karşılanıyor |
| A.5.28 Kanıt toplama | Gözetim zinciri dışa aktarımı, defter ve denetim zinciri, vaka başına imzalı kanıt paketi | K8, K13, K18 | Karşılanıyor (imza anahtarı kurumun) |
| A.5.33 Kayıtların korunması | Defter ve `audit_chain` salt ekleme + hash zinciri; imzalı kontrol noktaları; `python -m core.audit.verify` | K8 | Kısmi — ayar kayıtları ve onay kararları zincirsiz (R6) |
| A.5.34 Kişisel verilerin gizliliği | Yerel işleme, egress kanıtı, saklama ve imha | K1, K14 | Kısmi — bulut sağlayıcı seçilirse yurt dışı aktarım (R15) |
| A.8.2 Ayrıcalıklı erişim hakları | Admin/Manager izinleri, `DEV_MODE` uyarısı | K4 | Karşılanıyor |
| A.8.10 Bilgi silme | Saklama politikası, imha işi, yasal saklama, imha tutanağı | K14 | Karşılanıyor (politikalar kurumun) |
| A.8.13 Bilgi yedekleme | Şifreli, doğrulanan yedek; test geri yükleme; Helm yedek CronJob'u | K11, K15 | Karşılanıyor (Compose/host); Kısmi (Kubernetes: CronJob açılmalı, döküm şifresiz) |
| A.8.15 Kayıt tutma | Kimlik, ayar, vaka, onay, defter kayıtları; SIEM aktarımı | K6–K9, K19, K22 | Kısmi — kayıtlar veritabanında tutulur, kurum dışı kopya (SIEM aktarımı) varsayılan kapalı; ayar kaydı zincirsiz (R6); serbest metin maskelemesi en iyi çabadır |
| A.8.16 İzleme faaliyetleri | Ürünün kendisi (alarm triage); kanarya ve QA ile ölçüm | K12 | Karşılanıyor |
| A.8.20 Ağ güvenliği / A.8.22 Ağların ayrılması | NetworkPolicy, küme içi egress, daemon webhook CIDR kısıtı | K2 | Karşılanıyor (air-gap profiliyle) |
| A.8.24 Kriptografi kullanımı | Kriptografi envanteri; FIPS 140-3 modu | K21 | Kısmi — FIPS modunda kontrol noktası ve kanıt paketi imzaları Ed25519 kalır; `ssh_tunnel` desteklenmez |
| A.8.25–A.8.29 Güvenli geliştirme ve test | Bağımsız doğrulayıcı, CI eşik testleri (ratchet), güvenlik testleri, otomatik kırmızı takım regresyon paketi (rol × rota matrisi, SSRF matrisi, injection eşiği) | CI kayıtları | Kısmi — dış pentest Planlı — dal yok, W4.4, bu sürümde yok |
| A.8.32 Değişiklik yönetimi | Ayar değişikliği kaydı: sistem ayarları, otonomi, LLM sağlayıcı, AI bileşen ataması, bütçe, beceri, özel iş akışı, kural kaynağı, SLA politikası | K6 | Kısmi — rol izinlerinin veritabanında değişimi, Bifrost yönetim vekili (`/api/bifrost/...`) ve özel entegrasyon kodu değişiklikleri kaydedilmez; ayar kaydı zincirsizdir (R6) |

## Denetçiye sunum için öneri paketi (bu sürüm)

1. [Sürüm kapsamı](kapsam.md) ve bu eşleme.
2. K1 ve K3 çıktıları (kurulum günü).
3. K4 ve K5 (rol matrisi, kullanıcı/MFA listesi).
4. Seçilmiş bir vaka için K18 (kanıt paketi ve çevrimdışı doğrulama çıktısı), K7, K9,
   K10, K13 ve K8 (`python -m core.audit.verify --agent-events --require-signature` çıktısı).
5. K16 (dönemin görevler ayrılığı raporu) ve K17 (otonomi katmanları ve değişiklikleri).
   K22 (dönemin giriş ve kullanıcı yönetimi kayıtları). SIEM aktarımı açıksa K19;
   SSO kullanılıyorsa K20; FIPS modu açıksa K21.
6. Son K11 test geri yükleme çıktısı ve (Kubernetes'te) K15.
7. K14: saklama politikaları ve son periyodik imha tutanağı.
8. [Tehdit modeli — açık riskler](tehdit-modeli.md#açık-riskler) ve her biri için kurumun telafi edici kontrolü.
   R2 (onaylanmış MCP araçları) ve R6 (zincirsiz ayar kayıtları) için önlemi ayrıca gösterin.
