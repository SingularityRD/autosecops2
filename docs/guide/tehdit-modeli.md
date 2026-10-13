# Tehdit modeli (STRIDE)

> **English summary.** STRIDE threat model per component of AutoSecOps at
> `main` @ `b38f6fdb`. For each threat it lists the mitigation that is actually
> implemented in this release and points to the open risk when there is one.
> The open-risk register at the end combines the non-blocking follow-ups the
> independent verifiers recorded for merged work packages
> (`docs/wp/FIXES.md`, `docs/wp/STATUS.md`) with the risks that remain because
> planned work packages are not merged (SSO, four-eyes, live provenance,
> retention, audit export, extended audit chain, FIPS). No internal red-team or
> external pentest has been run on this release yet.

Yöntem: her bileşen için Spoofing (kimlik sahteciliği), Tampering (kurcalama),
Repudiation (inkâr), Information disclosure (bilgi ifşası), Denial of service
(hizmet engelleme), Elevation of privilege (yetki yükseltme). "Önlem" sütunu
yalnızca bu sürümde kodda olanı yazar; kalan risk `R<n>` ile
[açık riskler](#açık-riskler) tablosuna bağlanır. Mimari ve güven sınırları için
[güvenlik teknik belgesi](guvenlik-teknik-belgesi.md).

Saldırgan profilleri: (A1) alarm verisini etkileyen dış saldırgan (e-posta,
dosya adı, user agent, komut satırı yazar); (A2) kimliği doğrulanmış ama yetkisi
sınırlı kötü niyetli içeriden kullanıcı; (A3) küme içinde bir pod'u ele geçirmiş
saldırgan; (A4) tedarik zincirini (paket aktarımı) kurcalayan taraf; (A5) model
sağlayıcısı ya da model çıktısını yönlendiren taraf.

## 1. Web konsolu ve API (kimlik doğrulama, yetkilendirme)

| STRIDE | Tehdit | Önlem (bu sürüm) | Kalan |
|---|---|---|---|
| S | Parola tahmini, kimlik bilgisi doldurma | bcrypt; 5 hatalı girişte 15 dk kilit; giriş dakikada 5 istek; parola politikası (12+ karakter, zxcvbn ≥ 3, geçmiş 5, yasaklı liste); TOTP MFA | MFA zorunlu kılınamaz (R9); SSO yok (R10) |
| S | Çalınan belirteçle oturum | Kısa erişim belirteci (30 dk); çıkışta JTI, parola/rol/e-posta değişiminde kullanıcı bazında iptal; Redis yokken kapalı başarısız; `Secure` + `SameSite=strict` çerez | — |
| T | CSRF ile durum değiştirme | Çift gönderim çerezi CSRF ara katmanı | Kodun varsayılanı yalnızca raporlama (R12) |
| R | Kullanıcının ayar değişikliğini inkârı | `config_audit_log` oturumdaki kullanıcıyı yazar | Zincirsiz (R6) |
| I | Yetkisiz okuma | Rota başına izin; Viewer salt okuma; kanarya verisi yalnızca Admin | — |
| D | Giriş uçlarına yük | Hız sınırları; ilk hesap ucu ilk kullanıcıdan sonra kapalı | Yük testi yapılmadı (R20) |
| E | Rol atamasıyla yetki yükseltme | Yalnızca sahip olunan tüm izinleri veren rol atanabilir; hizmet hesabı Viewer'a kilitli; rota × izin matrisi CI'da | Rol izinlerinin veritabanında değiştirilmesi denetlenmez (R13) |
| E | `DEV_MODE=true` ile tüm kimlik doğrulamanın kapanması | Varsayılan `false`; açılışta ve ağdan erişilebilir adreste yüksek sesli uyarı | Açılışı engellemez (R14) |

## 2. Alarm alımı ve AI triage

| STRIDE | Tehdit | Önlem (bu sürüm) | Kalan |
|---|---|---|---|
| S | Sahte kaynaktan alarm itme | Daemon webhook portu NetworkPolicy ile izinli CIDR'lere sınırlı; federation kaynakları yalnızca yönetici tanımlı | Webhook içeriği kaynağa kriptografik bağlı değil |
| T | Alarm alanına prompt injection yazarak "zararsız" kararı | Model çıktısı doğrudan eyleme dönüşmez; araç etki sınıfları; insan onayı olmadan eylem yok; QA örneklemesi ve kanaryalar kaçırmayı ölçer | Köken kuralı canlı yolda değil, injection oranı sürüm kapısı değil (R1) |
| T | Bayrak kapalıyken payload'daki `alert_lane` ile triage'ı atlatma | Bayrak kapalıyken kanca bulguya dokunmaz; açıkken gelen alan atılır, yalnızca bu çalıştırmanın kararı kullanılır; tenant payload'dan alınmaz; şiddeti bilinmeyen alarm bastırılmaz | — |
| R | Hangi kuralın/modelin karar verdiğinin bilinmemesi | Şerit kararı `alert_lane_decisions` tablosuna; onay satırına kararı veren kural | Model ve istem sürümünün her karara yazılması planlı (R1) |
| I | Alarm içeriğinin modele/dışarı gitmesi | Air-gap profili: yalnızca yerel model, bulut anahtarları boş, egress kapalı; kanarya alarmları dış zenginleştirmeye gitmez | Bulut sağlayıcı seçilirse alarm içeriği sağlayıcıya gider (R15) |
| D | Alarm seli, bütçe tükenmesi | Bütçe baskısında alarm düşürülmez, sıraya alınır; orkestratör bütçeleri | Yük/kaos testi yapılmadı (R20) |
| E | Alarmın otonom soruşturmayı tetikleyip yetkili araç çağırması | Gated araçlar onay checkpoint'i olmadan reddedilir; kanarya otonom soruşturmaya giremez | Onay araç argümanlarına bağlı değil (R5) |

## 3. Ajan katmanı ve araçlar (MCP)

| STRIDE | Tehdit | Önlem (bu sürüm) | Kalan |
|---|---|---|---|
| S | Küme içinden `/internal` uçlarını çağırma | `AGENT_INTERNAL_TOKEN` (sabit zamanlı karşılaştırma); NetworkPolicy (grafikte açılırsa) | Temel grafikte `networkPolicies.enabled=false` (R16) |
| T | Defter olaylarını değiştirme | `agent_events` hash zinciri; `vigil_app` rolünün UPDATE/DELETE yetkisi yok | Son olayların silinmesi ve sahip rolüyle yeniden yazım tespit edilmez (R6) |
| R | Ajanın yaptığını inkâr | Her koşunun olayları zincirli defterde; koşu başına doğrulama ucu | — |
| I | Araç çıktısıyla sır sızması | Kimlik bilgileri ajanlarda değil sır deposunda; log ve telemetri maskeleme | — |
| D | Sonsuz döngü/maliyet | Koşu ve saatlik bütçe tavanları, kill-switch (`POST /api/orchestrator/kill`) | — |
| E | Yıkıcı aracın onaysız çağrılması | Tek tablo (`core/llm/tool_effects.py`), bilinmeyen araç en kısıtlayıcı sınıfa; sohbet gated araç sunmaz; TS harness ve `/internal/tools/invoke` iki ayrı kapı; ratchet: kapısız yazma aracı = 0 | Ad sezgiseli bazı adları okuma sayabilir; onay argümana bağlı değil (R5) |

## 4. LLM ağ geçidi ve model

| STRIDE | Tehdit | Önlem (bu sürüm) | Kalan |
|---|---|---|---|
| S | Sahte model uç noktası | Sağlayıcı URL'leri için SSRF koruması; air-gap'te yalnız küme içi Bifrost/Ollama | — |
| T | Modelin önerilen eylemi değiştirmesi | Öneri insan onayından geçer; uygulanan tek yürütücü (Cloudflare) | Politika katmanı (parametre izin listesi) planlı (R2) |
| I | İstek günlüğünde hassas veri | Bifrost günlüğü kurulum içinde kalır | Bifrost istek günlüğünün saklama süresi AutoSecOps tarafından yönetilmez (R7) |
| D | Sağlayıcı kesintisi | — | Kural/yerel şeride otomatik iniş planlı (R20) |

## 5. Müdahale hattı (onaylar ve yürütücüler)

| STRIDE | Tehdit | Önlem (bu sürüm) | Kalan |
|---|---|---|---|
| S | Onaylayanın kimliğine bürünme | Onaylayan oturumdan alınır; `ai_decisions.approve` gerekir | — |
| T | Güven puanını şişirerek onaysız eylem | Kişi onaylamadıkça yanıtlayıcı uygulamaz; [0,1] dışı güven insan bekletir; geri alınamaz eylem her zaman bekler | Varsayılan ortam Act görünür (R11) |
| T | Korunan varlığa (DC, yönetim IP'si) eylem | Yürütücüler bağlı değil; Cloudflare dışında hiçbir eylem uygulanmaz | Politika ve korunan varlık listesi planlı (R2) |
| R | "Ben onaylamadım" | Onaylayan, zaman ve karar kuralı satırda; vaka zaman çizelgesinde | Onay kayıtları zincirsiz (R6) |
| E | Tek kişinin kritik eylemi tek başına onaylaması | `ai_decisions.approve` yalnız Senior Analyst ve üstünde | Dört göz yok (R3) |
| D | Onay kuyruğunun tıkanması | Yanıtlanmayan onaylar 7 günde süresi doluyor | — |

## 6. Veri depoları ve denetim kayıtları

| STRIDE | Tehdit | Önlem (bu sürüm) | Kalan |
|---|---|---|---|
| T | Defter/denetim kaydı kurcalama | Defter ve düzenleyici an zinciri; uygulama rolü defterde salt ekleme | Zincir başı imzasız; diğer denetim tabloları zincirsiz (R6) |
| R | Düzenleyici bildirim anlarının sonradan değiştirilmesi | `regulatory_clock_events` salt ekleme, güncelleme tetikleyiciyle reddedilir, değişiklik gerekçe ister | Son olayın silinmesi ve anların sırası denetlenmez (R4) |
| I | Veritabanı dökümüyle kişisel veri sızması | Uygulama sahip olmayan rolle bağlanır; yedekler şifreli | Saklama/imha politikası yok (R8) |
| D | Veri kaybı | Doğrulanan şifreli yedek, test geri yükleme | Kubernetes'te zamanlanmış yedek ve sıcak yedek yok (R17) |

## 7. Sırlar ve yapılandırma

| STRIDE | Tehdit | Önlem (bu sürüm) | Kalan |
|---|---|---|---|
| I | Entegrasyon kimlik bilgisinin sızması | Şifreli `secrets.enc`; veritabanına/JSON'a yazılmaz; API'de maskeli; Secret/ExternalSecrets | `master.key` aynı dizinde ve aynı yedekte; döndürme komutu yok (R18) |
| T | Air-gap profilinin sessizce gevşetilmesi | `values-airgap.yaml` ve `airgap.env` eşitliği testli; egress envanteri ratchet | — |
| E | Konsoldan yapılandırma ile yetki | `settings.write`/`integrations.write` izinleri; değişiklik `config_audit_log`'a | — |

## 8. Giden bildirimler (webhook, e-posta, Slack)

| STRIDE | Tehdit | Önlem (bu sürüm) | Kalan |
|---|---|---|---|
| S | Alıcının sahte bildirim alması | HMAC-SHA256 imza, zaman damgası, alıcı doğrulama belgesi | Belgede tekilleştirmenin imzalı gövde `id`'sine dayanması önerilmeli (R19) |
| I | SSRF ile iç servislere/metadata'ya istek | Çözümlenen adres denetimi, adres sabitleme, yönlendirme yok, vekil yok, metadata adresi her zaman reddedilir | CGNAT aralığı izinli (R19) |
| I | Kanarya varlığının dışarı sızması | Kanarya vakaları dış kanala gitmez | — |
| D | Alıcı çökünce kuyruk büyümesi | Üstel geri çekilme, `WEBHOOK_MAX_ATTEMPTS` sonra `dead` | — |

## 9. Kurulum paketi ve tedarik zinciri

| STRIDE | Tehdit | Önlem (bu sürüm) | Kalan |
|---|---|---|---|
| S | Sahte paket | Bant dışı açık anahtarla imza doğrulaması; paket içindeki anahtar kullanılmaz | — |
| T | Doğrulamadan sonra paketin değiştirilmesi | Paket özel hazırlık dizinine kopyalanır, kopya doğrulanır ve yalnızca kopyadan kurulur | — |
| T | Arşivde sembolik bağ / yol geçişi | Listelenmemiş dosya, bağ, FIFO, aygıt reddi; kural/model arşivlerinde üye denetimi | — |
| I | İmza anahtarının sızması | Anahtar yalnızca imzalama makinesinde; sızma prosedürü belgeli | — |
| E | Bağımlılık/imaj zinciri | CI'da Trivy imaj taraması (düzeltilebilir CRITICAL'da başarısız), Bandit, Dependabot | SBOM ve imzalı imajlar planlı (R21) |

## 10. Egress kanıtının sınırları

Çalışma zamanı koruması yalnızca Python soketlerini görür; Bifrost (Go), Node ajan
katmanı ve tarayıcı yalnızca statik taranır; uvloop'un yerel DNS'i koruma dışında
olduğu için test `--loop asyncio` kullanır. Ağ düzeyindeki önlem NetworkPolicy'dir
(R16). Ayrıntı: [tests/airgap/README.md](../../tests/airgap/README.md).

## Açık riskler

Kaynak: birleşmiş paketler için bağımsız doğrulayıcının "engelleyici değil" takip
maddeleri (`docs/wp/FIXES.md` son bölümü, `docs/wp/STATUS.md` §1) — bu commit'te
kodda hâlâ açık oldukları kontrol edildi —; diğerleri birleşmemiş paketlerin
yokluğundan doğan risklerdir. Önem: bu sürümde, düzenlenmiş sektör kurulumu için.

| # | Risk | Önem | Kaynak | Telafi edici önlem (bugün) |
|---|---|---|---|---|
| R1 | Köken (provenance) kuralı canlı triage yolunda uygulanmıyor; injection oranı sürüm kapısı değil; kararlara model/istem sürümü yazılmıyor | Yüksek | Planlı — `wp/w1.2-triage-provenance`, `wp/w1.4-injection-set` | İnsan onayı olmadan eylem yok; gated araçlar; QA/kanarya ile ölçüm; `evalkit` ile injection setini çevrimdışı ölçün |
| R2 | Tipli eylem politikası, korunan varlık listesi, parametre izin listesi, saatlik etki sınırı yok; Defender/Entra/PAN-OS yürütücüleri bağlı değil | Orta | Planlı — `wp/w2.4-executors-policy` | Bu sürümde yalnız Cloudflare eylemleri uygulanır ve her biri insan onaylıdır |
| R3 | Dört göz onayı ve görevler ayrılığı yok (tek onaylayıcı) | Yüksek | Planlı — `wp/w2.4-executors-policy`, `wp/w3.2-sod` | `ai_decisions.approve`'u az sayıda kişiye verin; onayları `approval_actions`'tan periyodik gözden geçirin |
| R4 | Düzenleyici an zincirinde zincir başı çapası yok (son olay silinmesi tespit edilmez); anların sıra kontrolü yok; DORA ilk bildirim başlamadan `met` gösterebilir; taslaktaki `[evidence:N]` referansları doğrulanmıyor | Orta | FIXES.md, W3.8 takip | Taslakları insan gözden geçirir; an kayıtları `case_audit_logs`'a da yazılır |
| R5 | Gated araç onayı araç argümanlarına bağlı değil; ad sezgiseli bazı adları (ör. get_blockIp gibi bir ad) okuma sayabilir; sohbette onay aracı açık | Orta | FIXES.md, W1.7 takip | Tablodaki tüm yerleşik araçlar açık sınıflı; bilinmeyen MCP araçları sohbetten düşer |
| R6 | Defter zincirinin başı imzalı kontrol noktasına bağlı değil; onay, vaka ve ayar denetim kayıtları zincirsiz; SIEM'e akış yok | Yüksek | Planlı — `wp/w1.10-audit-chain`, `wp/w3.6-audit-export` | `vigil_app` rolü defterde salt ekleme; denetim tablolarını salt okuma rolüyle düzenli olarak dışarı alın |
| R7 | Bifrost istek günlüğü (`logs.db`) AutoSecOps saklama kurallarının dışında | Düşük | Kod incelemesi | Bifrost veri dizinini kurum politikasıyla temizleyin |
| R8 | Veri sınıfı başına saklama, KVKK periyodik imha, yasal saklama ve imha raporu yok; bulgular/vakalar otomatik silinmez | Yüksek (KVKK) | Planlı — `wp/w3.5-retention` | Elle silme uçları (yönetici kılavuzu); imhayı kurum prosedürüyle kayıt altına alın |
| R9 | MFA bir rol için zorunlu kılınamaz | Orta | Kod incelemesi | Yönetici/onaylayıcı hesaplarında MFA'yı süreçle zorunlu tutun, `mfa_enabled` alanını denetleyin |
| R10 | SSO (OIDC) ve merkezi hesap yaşam döngüsü yok | Orta | Planlı — `wp/w1.9-oidc` | Yerel hesaplar; işten ayrılmada hesabı devre dışı bırakma prosedürü |
| R11 | Kodun varsayılanı `DAEMON_AUTO_RESPONSE=true`, `DAEMON_FORCE_APPROVAL=false` (Act görünümü) | Düşük | Kod incelemesi | Kişi onayı olmadan eylem yok; `DAEMON_FORCE_APPROVAL=true` önerilir |
| R12 | CSRF kodda varsayılan olarak yalnızca raporlama modunda | Düşük | `core/config.py` | `VIGIL_CSRF_REPORT_ONLY=false` (`env.example` böyle) |
| R13 | Rol izinleri veritabanında değiştirilirse denetim kaydı yok | Düşük | Kod incelemesi | Veritabanı erişimini sınırlayın; değişiklik yönetimi |
| R14 | `DEV_MODE=true` açılışı engellemez | Orta | `core/auth/dev_mode.py` (bilinçli tasarım) | Helm/`env.example` varsayılanı `false`; yapılandırma denetimi |
| R15 | Bulut model sağlayıcı seçilirse alarm içeriği sağlayıcıya gider (yurt dışı aktarım) | Yüksek (KVKK) | Mimari | Air-gap profili / yerel model; sağlayıcıyı müşteri seçer |
| R16 | Temel Helm grafiğinde `networkPolicies.enabled=false`; NetworkPolicy uygulamayan CNI'da egress kısıtı etkisiz | Orta | `infra/helm/vigil/values.yaml` | `values-airgap.yaml` açar; NetworkPolicy uygulayan CNI şart |
| R17 | Kubernetes'te zamanlanmış yedek CronJob'u, daemon sıcak yedeği, ölçülmüş RPO/RTO yok | Orta | Planlı — `wp/w3.9-daemon-standby` | Depolama düzeyinde anlık görüntü; Compose'da `core.backup` |
| R18 | `master.key` sır deposuyla aynı dizinde ve aynı yedekte; yerleşik döndürme yok | Orta | Kod incelemesi | Kubernetes'te sırları Secret/ExternalSecrets ile verin; restic parolasını ayrı saklayın |
| R19 | `url_safety` CGNAT 100.64.0.0/10'u (ör. 100.100.100.200 metadata) reddetmiyor; alıcı belgesi tekilleştirmeyi imzalı gövdedeki `id` yerine imzasız `X-AutoSecOps-Event-Id` başlığına dayandırıyor; SLA tekilleştirmesinde benzersizlik kısıtı yok | Orta | FIXES.md, W1.8 takip | `WEBHOOK_ALLOWED_CIDRS`'i boş bırakın; egress NetworkPolicy |
| R20 | Yük, kaos, sağlayıcı kesintisi testleri; iç kırmızı takım ve dış pentest yapılmadı | Yüksek | Planlı — dal yok, W4.1–W4.4 | — |
| R21 | SBOM ve imzalı imajlar yok | Orta | Planlı — dal yok, W4.7 | Air-gap paketi SHA-256 + imzalı |
| R22 | Entra ID yürütücüsünde yalnızca kimliği olan (adı/şablonu boş) rol kaydı korunan rol denetiminden geçiyor | Orta (bağlanınca) | FIXES.md, W2.6 takip | Yürütücü bu sürümde bağlı değil |
| R23 | Egress tarayıcısında kural boşlukları (ör. asyncio.open_connection, ftplib, grpc tanınmıyor), `scripts/` taranmıyor; CI eylemleri SHA'ya sabitli değil | Düşük | FIXES.md, W3.4 takip | Çalışma zamanı testi ve NetworkPolicy |
| R24 | QA örneklemede çağıranın verdiği `seed` üretimde de kabul ediliyor (örnek seçimi yönlendirilebilir) | Düşük | FIXES.md, W1.6 takip | `ai_decisions.approve` gerekir; örneklem satırları kayıtlı |
| R25 | Konsolda iki yerde eski "Vigil" metni; Revert 502 ayrıntısı gösterilmiyor | Düşük | FIXES.md, W0.9/W2.8 takip | — |
