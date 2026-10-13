# Mevzuat eşlemesi

> **Bu belge hukuki görüş değildir.** Aşağıdaki tablolar, düzenlemelerin
> AutoSecOps'u kullanan kurumdan beklediği bazı kontrolleri ürünün bu sürümdeki
> (`main` @ `b38f6fdb`) özelliklerine ve bu özelliklerin üretebildiği kanıta
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
| K4 | Rol ve izin matrisi | `GET /api/users/roles/list`; CI'da `tests/security/test_route_permissions.py` |
| K5 | Kullanıcı listesi ve MFA durumu | `GET /api/users/` (rol, `mfa_enabled`, son giriş) |
| K6 | Ayar değişikliği kaydı | `config_audit_log` tablosu (kim, ne zaman, eski/yeni değer, gerekçe) |
| K7 | Müdahale eylemi ve onay kaydı | `approval_actions`; `GET /api/v1/approvals`; vaka Actions sekmesi (`GET /api/cases/{case_id}/actions/timeline`) |
| K8 | Ajan defteri ve bütünlük doğrulaması | `npm run ledger:verify` (ajan katmanında); `GET /api/workflows/runs/{run_id}/verify` |
| K9 | Vaka denetim kaydı | Vaka → Record sekmesi (`case_audit_logs`) |
| K10 | Düzenleyici bildirim sayaçları ve taslaklar | `GET /api/cases/{case_id}/regulatory/clocks`, `.../regulatory/events`, `.../regulatory/drafts` |
| K11 | Yedek ve geri yükleme testi | `./start.sh restore ... --test` çıktısı; konsolda depolama durumu "Last successful backup" |
| K12 | Doğruluk ölçümü | Karne (`GET /api/qa/scorecard`); kanarya sonuçları (`GET /api/quality/canaries`, yalnız Admin) |
| K13 | Soruşturma gözetim zinciri | `GET /api/orchestrator/investigations/{investigation_id}/chain-of-custody` |

## BDDK — Bankaların Bilgi Sistemleri ve Elektronik Bankacılık Hizmetleri Hakkında Yönetmelik

| Beklenti | AutoSecOps özelliği (bu sürüm) | Kanıt | Durum |
|---|---|---|---|
| Birincil ve ikincil sistemlerin yurt içinde bulundurulması; verinin kurum denetiminde kalması | Kendi altyapısında kurulum (Helm/Compose); internetsiz kurulum paketi; yerel model (Ollama); sıfır egress profili | K1, K2, K3 | Karşılanıyor (kurulum yeri kurumun kararı) |
| İz kayıtlarının tutulması, bütünlüğünün korunması | Ajan defterinde koşu başına hash zinciri ve salt ekleme; ayar, vaka ve onay kayıtları | K6, K7, K8, K9 | Kısmi — onay/vaka kayıtlarının zincire alınması ve imzalı kontrol noktası Planlı — `wp/w1.10-audit-chain`, bu sürümde yok |
| İz kayıtlarının merkezi izleme sistemine aktarılması | — | — | Planlı — `wp/w3.6-audit-export`, bu sürümde yok (geçici: tabloların salt okuma rolüyle periyodik aktarımı) |
| Görevler ayrılığı | Rol matrisi; onay yetkisi (`ai_decisions.approve`) yalnız Senior Analyst ve üstünde; atayan kişi yalnızca kendi izinlerini aşmayan rolü atayabilir | K4, K5 | Kısmi — dört göz ve farklı rol koşulu Planlı — `wp/w2.4-executors-policy`, `wp/w3.2-sod`, bu sürümde yok |
| Erişim yönetimi, kimlik doğrulama | Yerel hesaplar, parola politikası, kilitleme, TOTP MFA, oturum iptali | K4, K5 | Kısmi — MFA zorunlu kılınamaz; SSO Planlı — `wp/w1.9-oidc`, bu sürümde yok |
| Yetkili kullanıcı işlemlerinin kayıt altına alınması | Onaylayan ve onay zamanı, ayar değiştiren kullanıcı | K6, K7 | Karşılanıyor |
| Bilgi güvenliği olay yönetimi | Alarm alımı, triage, vaka yönetimi, SLA izleyicisi, vaka bildirimleri | K9, K7 | Karşılanıyor (süreç kurumun) |
| Yedekleme ve iş sürekliliği | Şifreli ve doğrulanan restic yedeği, test geri yükleme, yükseltme öncesi otomatik yedek (Compose/host) | K11 | Kısmi — Kubernetes yedek CronJob'u ve sıcak yedek Planlı — `wp/w3.9-daemon-standby`, bu sürümde yok |
| Dış hizmet (model sağlayıcı) riskinin yönetimi | Yerel model ile dış sağlayıcıya bağımlılığın kaldırılması | K1, K2 | Karşılanıyor (air-gap profiliyle) |
| Kriptografik anahtar yönetimi | Bant dışı imza anahtarı; şifreli sır deposu; Secret/ExternalSecrets | K3 | Kısmi — `master.key` için yerleşik döndürme yok |

## KVKK — 6698 sayılı Kişisel Verilerin Korunması Kanunu

| Beklenti | AutoSecOps özelliği (bu sürüm) | Kanıt | Durum |
|---|---|---|---|
| Md. 12 — veri güvenliği için teknik tedbirler (erişim yetkisi, şifreleme, kayıt) | Rol matrisi; sırların şifreli saklanması; şifreli yedek; denetim kayıtları | K4, K6, K8, K11 | Karşılanıyor (idari tedbirler kurumun) |
| Md. 9 — yurt dışına aktarım kısıtları | Yerel model, internetsiz kurulum, bulut sağlayıcı anahtarları boş; egress kanıtı | K1, K2 | Karşılanıyor (air-gap profiliyle); bulut sağlayıcı seçilirse aktarım kurumun değerlendirmesine tabidir |
| Md. 4 — işlendikleri amaç için gerekli süre kadar muhafaza | Onay isteklerinin süresinin dolması, okuma günlüğünün 90 günde silinmesi | — | Kısmi — veri sınıfı başına saklama süresi Planlı — `wp/w3.5-retention`, bu sürümde yok |
| Md. 7 ve Silme, Yok Etme veya Anonim Hale Getirme Yönetmeliği — periyodik imha, imha kaydı | Elle silme uçları (vaka, tüm bulgular, soruşturmalar) | — | Planlı — `wp/w3.5-retention`, bu sürümde yok (periyodik imha, yasal saklama, imha raporu) |
| Kişisel verilere erişimin kaydı | Ayar ve vaka değişiklik kayıtları; ajan defteri | K6, K8, K9 | Kısmi — salt okuma erişimleri kaydedilmez |

## DORA — (AB) 2022/2554

| Beklenti | AutoSecOps özelliği (bu sürüm) | Kanıt | Durum |
|---|---|---|---|
| Md. 10 — anormal faaliyetin tespiti | Alarm toplama (federation), AI triage, kanarya ile tespit oranı ölçümü, QA karnesi | K12 | Karşılanıyor |
| Md. 11 — müdahale ve kurtarma | Onaylı müdahale eylemleri, eylem zaman çizelgesi | K7 | Kısmi — EDR/IdP/güvenlik duvarı yürütücülerinin bağlanması Planlı — `wp/w2.4-executors-policy`, bu sürümde yok |
| Md. 12 — yedekleme politikaları, geri yükleme | Şifreli, doğrulanan yedek; test geri yükleme; geri yüklemede oturum anahtarı döndürme ve bekleyen onayların reddi | K11 | Kısmi — RPO/RTO ölçümü Planlı — `wp/w3.9-daemon-standby`, bu sürümde yok |
| Md. 17 — BİT olay yönetim süreci, kayıt | Vaka yönetimi, vaka denetim kaydı, gözetim zinciri dışa aktarımı | K9, K13 | Karşılanıyor |
| Md. 18 — olay sınıflandırması | Vakada "büyük olay" sınıflandırma anı (`classification_at`) kaydı | K10 | Kısmi — sınıflandırma kriterlerinin uygulanması kurumun |
| Md. 19 — büyük olayların süreli bildirimi (ilk bildirim, ara rapor, nihai rapor) | DORA sayaçları: ilk bildirim `min(sınıflandırma + 4 saat, farkına varma + 24 saat)`, ara rapor bildirim + 72 saat, nihai rapor son ara rapor + 1 ay; süreler kiracı başına ayarlanabilir; an kayıtları zincirli; rapor taslakları vakanın kanıtından | K10 | Karşılanıyor (resmî bildirimin gönderimi kurumun) |
| Kayıtların bütünlüğü | Defter zinciri, düzenleyici an zinciri | K8, K10 | Kısmi — zincir başı çapası yok (tehdit modeli R4, R6) |
| Md. 28–30 — üçüncü taraf BİT riski | Yerel model; dış entegrasyonların varsayılan kapalı olması; egress envanteri | K1 | Kısmi |
| Kanıt paketi | — | — | Planlı — `wp/w3.7-evidence-pack`, bu sürümde yok |

## NIS2 — (AB) 2022/2555

| Beklenti | AutoSecOps özelliği (bu sürüm) | Kanıt | Durum |
|---|---|---|---|
| Md. 23 — 24 saat erken uyarı | NIS2 erken uyarı sayacı: farkına varma + 24 saat | K10 | Karşılanıyor |
| Md. 23 — 72 saat olay bildirimi | Farkına varma + 72 saat sayacı | K10 | Karşılanıyor |
| Md. 23 — 1 ay nihai rapor | Bildirim + 1 ay sayacı; rapor taslağı | K10 | Karşılanıyor |
| Md. 21 — olay ele alma | Vaka yönetimi, onaylı müdahale | K7, K9 | Karşılanıyor |
| Md. 21 — iş sürekliliği, yedek yönetimi | Şifreli yedek ve test geri yükleme | K11 | Kısmi (Kubernetes'te zamanlanmış yedek Planlı — `wp/w3.9-daemon-standby`, bu sürümde yok) |
| Md. 21 — tedarik zinciri güvenliği | İmzalı kurulum paketi; CI'da imaj taraması | K3 | Kısmi — SBOM ve imzalı imajlar Planlı — dal yok, W4.7, bu sürümde yok |
| Md. 21 — kriptografi politikaları | Kriptografi envanteri (güvenlik teknik belgesi §8) | — | Kısmi — FIPS modu Planlı — `wp/w3.10-fips`, bu sürümde yok |
| Md. 21 — erişim denetimi, çok faktörlü kimlik doğrulama | Rol matrisi, TOTP MFA | K4, K5 | Kısmi — MFA zorunlu kılınamaz; SSO Planlı — `wp/w1.9-oidc`, bu sürümde yok |

## SPK — Bilgi Sistemleri Yönetimi Tebliği (VII-128.9)

| Beklenti | AutoSecOps özelliği (bu sürüm) | Kanıt | Durum |
|---|---|---|---|
| Bilgi güvenliği yönetimi, olay yönetimi | Alarm triage, vaka yönetimi, SLA izleme | K9 | Karşılanıyor (süreç kurumun) |
| İz kayıtları ve bütünlüğü | Defter zinciri; ayar/vaka/onay kayıtları | K6–K9 | Kısmi — Planlı — `wp/w1.10-audit-chain`, `wp/w3.6-audit-export`, bu sürümde yok |
| Kimlik doğrulama ve erişim yönetimi | Rol matrisi, MFA, kilitleme, oturum iptali | K4, K5 | Kısmi (MFA zorunlu kılınamaz) |
| Görevler ayrılığı | Onay yetkisinin rolle sınırlanması | K4, K7 | Kısmi — dört göz Planlı — `wp/w3.2-sod`, bu sürümde yok |
| Yedekleme ve iş sürekliliği | Şifreli yedek, test geri yükleme | K11 | Kısmi |
| Dış hizmet alımı | Yerel model, egress kanıtı | K1, K2 | Karşılanıyor (air-gap profiliyle) |

## ISO/IEC 27001:2022 — Ek A kontrolleri

| Kontrol | AutoSecOps özelliği (bu sürüm) | Kanıt | Durum |
|---|---|---|---|
| A.5.3 Görevler ayrılığı | Onay yetkisi rolle sınırlı | K4, K7 | Kısmi — Planlı — `wp/w3.2-sod`, bu sürümde yok |
| A.5.15 Erişim denetimi / A.5.18 Erişim hakları | Rol matrisi, rota başına izin, rol atama kısıtı | K4, K5 | Karşılanıyor |
| A.5.16 Kimlik yönetimi | Yerel hesap yaşam döngüsü, hizmet hesabı Viewer'a kilitli | K5 | Kısmi — SSO Planlı — `wp/w1.9-oidc`, bu sürümde yok |
| A.5.17 Kimlik doğrulama bilgisi / A.8.5 Güvenli kimlik doğrulama | Parola politikası, bcrypt, TOTP, kilitleme | K5 | Kısmi (MFA zorunlu değil) |
| A.5.21 BİT tedarik zinciri | İmzalı paket, Trivy, Dependabot | K3 | Kısmi — SBOM Planlı — dal yok, W4.7, bu sürümde yok |
| A.5.24–A.5.26 Olay yönetimi planlama, değerlendirme, müdahale | Triage, vaka, onaylı müdahale, eylem zaman çizelgesi | K7, K9 | Karşılanıyor |
| A.5.28 Kanıt toplama | Gözetim zinciri dışa aktarımı, defter zinciri | K8, K13 | Kısmi — kanıt paketi Planlı — `wp/w3.7-evidence-pack`, bu sürümde yok |
| A.5.33 Kayıtların korunması | Defter salt ekleme + hash zinciri | K8 | Kısmi — Planlı — `wp/w1.10-audit-chain`, bu sürümde yok |
| A.5.34 Kişisel verilerin gizliliği | Yerel işleme, egress kanıtı | K1 | Kısmi — saklama/imha Planlı — `wp/w3.5-retention`, bu sürümde yok |
| A.8.2 Ayrıcalıklı erişim hakları | Admin/Manager izinleri, `DEV_MODE` uyarısı | K4 | Karşılanıyor |
| A.8.10 Bilgi silme | Elle silme uçları | — | Planlı — `wp/w3.5-retention`, bu sürümde yok |
| A.8.13 Bilgi yedekleme | Şifreli, doğrulanan yedek; test geri yükleme | K11 | Karşılanıyor (Compose/host); Kubernetes Planlı — `wp/w3.9-daemon-standby`, bu sürümde yok |
| A.8.15 Kayıt tutma | Ayar, vaka, onay, defter kayıtları | K6–K9 | Kısmi — SIEM aktarımı Planlı — `wp/w3.6-audit-export`, bu sürümde yok |
| A.8.16 İzleme faaliyetleri | Ürünün kendisi (alarm triage); kanarya ve QA ile ölçüm | K12 | Karşılanıyor |
| A.8.20 Ağ güvenliği / A.8.22 Ağların ayrılması | NetworkPolicy, küme içi egress, daemon webhook CIDR kısıtı | K2 | Karşılanıyor (air-gap profiliyle) |
| A.8.24 Kriptografi kullanımı | Kriptografi envanteri | — | Kısmi — FIPS Planlı — `wp/w3.10-fips`, bu sürümde yok |
| A.8.25–A.8.29 Güvenli geliştirme ve test | Bağımsız doğrulayıcı, CI ratchet'leri, güvenlik testleri | CI kayıtları | Kısmi — dış pentest Planlı — dal yok, W4.4, bu sürümde yok |
| A.8.32 Değişiklik yönetimi | Ayar değişikliği kaydı | K6 | Kısmi (rol izinlerinin veritabanında değişimi kaydedilmez) |

## Denetçiye sunum için öneri paketi (bu sürüm)

1. [Sürüm kapsamı](kapsam.md) ve bu eşleme.
2. K1 ve K3 çıktıları (kurulum günü).
3. K4 ve K5 (rol matrisi, kullanıcı/MFA listesi).
4. Seçilmiş bir vaka için K7, K9, K10, K13 ve ilgili koşular için K8 doğrulaması.
5. Son K11 test geri yükleme çıktısı.
6. [Tehdit modeli — açık riskler](tehdit-modeli.md#açık-riskler) ve her biri için kurumun telafi edici kontrolü.
