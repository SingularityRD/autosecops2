# Tehdit modeli (STRIDE)

> **English summary.** STRIDE threat model per component of AutoSecOps at
> `main` @ `18d0bf09`. For each threat it lists the mitigation that is actually
> implemented in this release and points to the open risk when there is one.
> The open-risk register at the end combines the non-blocking follow-ups the
> independent verifiers recorded for merged work packages, findings of the
> internal reviews (the detection-rule source SSRF / argument injection, R26,
> has a planned hotfix that is not merged; chat can approve a pending action
> under the chatting user's identity, R30), and the risks that remain because
> planned work packages are not merged (SSO, audit export, extended audit
> chain, FIPS). Risks closed by W0.10 and by the autonomy and
> separation-of-duties packages stay listed as closed or narrowed. No external
> pentest has been run on this release yet.

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
| E | Rol atamasıyla yetki yükseltme | Yalnızca sahip olunan tüm izinleri veren rol atanabilir; hizmet hesabı Viewer'a kilitli; her rota × her rol matrisi CI'da, gerçek HTTP isteğiyle doğrulanır | Rol izinlerinin veritabanında değiştirilmesi denetlenmez (R13) |
| E | `DEV_MODE=true` ile tüm kimlik doğrulamanın kapanması | Varsayılan `false`; açılışta ve ağdan erişilebilir adreste yüksek sesli uyarı | Açılışı engellemez (R14) |
| E | Kural kaynağı ekleme ucuyla (`POST /api/detection-rules/sources`) SSRF, sunucudaki yerel depoların okunması, git argüman enjeksiyonu | Kabuk yok (`git` liste argümanıyla çağrılır); başka önlem yok: uç yalnızca oturum ister ve git adresini denetlemez | Yüksek (R26) |
| E | Viewer'ın yalnızca oturumla erişebildiği durum değiştiren uçlar | Her yazma rotası ya izin ister ya da gözden geçirilmiş listededir (CI) | Listede yanlış kalanlar var (R28) |

## 2. Alarm alımı ve AI triage

| STRIDE | Tehdit | Önlem (bu sürüm) | Kalan |
|---|---|---|---|
| S | Sahte kaynaktan alarm itme | Daemon webhook portu NetworkPolicy ile izinli CIDR'lere sınırlı; federation kaynakları yalnızca yönetici tanımlı | Webhook içeriği kaynağa kriptografik bağlı değil |
| T | Alarm alanına prompt injection yazarak "zararsız" kararı | JSON şemalı triage, katı ayrıştırma; köken kodla atanır; sensöre dayanmayan `benign` → `inconclusive`; model çıktısı doğrudan eyleme dönüşmez; insan onayı ve müdahale politikası; QA örneklemesi ve kanaryalar kaçırmayı ölçer; CI'da injection başarı oranı kayıtlı tabanı aşamaz | Yalnız saldırgan alanlarına dayanan `malicious` geçerli; `data_source` gönderenin seçimi; ≤ %5 hedefi kapı değil (R1) |
| T | Yüke analiz alanı (`triage_confidence`, `recommended_action`, `ai_triage`, `enrichment`, `category`, önceki karar) yazarak müdahaleyi ya da şeridi yönlendirme | Bu alanlar işlemeden önce atılır (`drop_payload_analysis`); otonomi kategorisi gönderenin yazdığı kategori alanından değil sensör alanlarından ve triage kararından | — |
| T | Bayrak kapalıyken yükteki `alert_lane` alanıyla triage'ı atlatma | Bayrak kapalıyken kanca bulguya dokunmaz; açıkken gelen alan atılır, yalnızca bu çalıştırmanın kararı kullanılır; kiracı yükten alınmaz; şiddeti bilinmeyen alarm bastırılmaz | — |
| R | Hangi kuralın/modelin karar verdiğinin bilinmemesi | Şerit kararı `alert_lane_decisions` tablosuna; triage kararında `model` ve `prompt_version`; onay satırına kararı veren kural | — |
| I | Alarm içeriğinin modele/dışarı gitmesi | Air-gap profili: yalnızca yerel model, bulut anahtarları boş, egress kapalı; kanarya alarmları dış zenginleştirmeye gitmez | Bulut sağlayıcı seçilirse alarm içeriği sağlayıcıya gider (R15) |
| D | Alarm seli, bütçe tükenmesi | Bütçe baskısında alarm düşürülmez, sıraya alınır; orkestratör bütçeleri; alım kuyruğu doluysa webhook 503 + `Retry-After` döner | Yük testi yapılmadı (R20) |
| D | Veritabanı kesintisinde ya da daemon çökünce kabul edilmiş alarmın kaybı | Webhook 200'ü bulgu diskteki kalıcı kuyruğa (`fsync`) yazıldıktan sonra döner; yazım başarısızsa bulgu yeniden denenir; açılışta kuyruk yeniden oynatılır, çift satır yok | Helm'de `daemon.persistence.enabled=false` ise kuyruk pod silinince kaybolur ([docs/operations/ingest-durability.md](../operations/ingest-durability.md)) |
| E | Alarmın otonom soruşturmayı tetikleyip yetkili araç çağırması | Onay gerektiren araçlar onay noktası olmadan reddedilir; kanarya otonom soruşturmaya giremez | Onaydan sonra politika yok (R2); onay argümana bağlı değil (R5) |

## 3. Ajan katmanı ve araçlar (MCP)

| STRIDE | Tehdit | Önlem (bu sürüm) | Kalan |
|---|---|---|---|
| S | Küme içinden `/internal` uçlarını çağırma | `AGENT_INTERNAL_TOKEN` (sabit zamanlı karşılaştırma); NetworkPolicy (grafikte açılırsa) | Temel grafikte `networkPolicies.enabled=false` (R16) |
| T | Defter olaylarını değiştirme | `agent_events` hash zinciri; `vigil_app` rolünün UPDATE/DELETE yetkisi yok | Son olayların silinmesi ve sahip rolüyle yeniden yazım tespit edilmez (R6) |
| R | Ajanın yaptığını inkâr | Her koşunun olayları zincirli defterde; koşu başına doğrulama ucu | — |
| I | Araç çıktısıyla sır sızması | Kimlik bilgileri ajanlarda değil sır deposunda; log ve telemetri maskeleme | — |
| D | Sonsuz döngü/maliyet | Koşu ve saatlik bütçe tavanları, acil durdurma (`POST /api/orchestrator/kill`) | — |
| E | Yıkıcı aracın onaysız çağrılması | Tek tablo (`core/llm/tool_effects.py`); tabloda olmayan ad, açıkça okuma fiiliyle başlamıyorsa en kısıtlayıcı sınıfa; sohbet onay gerektiren araç sunmaz (ama `approve_action`'ı sunar, R30); TS çalıştırıcısı ve `/internal/tools/invoke` iki ayrı kapı; onay sorunun başındaki araç adına bağlı; ratchet: onaysız yazma aracı = 0 | Onay argümana bağlı değil (R5) |
| E | Onaylanmış yıkıcı aracın korunan varlığa uygulanması | Bir kişinin onay noktasını onaylaması | Bu yolda müdahale politikası, korunan varlık listesi, saatlik sınır, süre dolumu ve dört göz onayı yok (R2) |

## 4. LLM ağ geçidi ve model

| STRIDE | Tehdit | Önlem (bu sürüm) | Kalan |
|---|---|---|---|
| S | Sahte model uç noktası | Sağlayıcı URL'leri için SSRF koruması; air-gap'te yalnız küme içi Bifrost/Ollama | — |
| T | Modelin önerilen eylemi değiştirmesi | Öneri insan onayından ve müdahale politikasından geçer; Cloudflare'de hedef otoriter, parametre izin listesi; `ttl_seconds` sınırlı | MCP araç yolu politikasız (R2) |
| I | İstek günlüğünde hassas veri | Bifrost günlüğü kurulum içinde kalır | Bifrost istek günlüğünün saklama süresi AutoSecOps tarafından yönetilmez (R7) |
| D | Sağlayıcı kesintisi | — | Yerel model şeridine otomatik iniş Planlı — `wp/w2.3-local-model-lane`; kesinti testi yapılmadı (R20) |

## 5. Müdahale hattı (onaylar ve yürütücüler)

| STRIDE | Tehdit | Önlem (bu sürüm) | Kalan |
|---|---|---|---|
| S | Onaylayanın kimliğine bürünme | Onaylayan oturumdan alınır; `ai_decisions.approve` gerekir | — |
| T | Güven puanını şişirerek onaysız eylem | Otonomi katmanının varsayılanı Approve: güven tek başına eylemi serbest bırakmaz; kişisiz yalnızca Autonomous katmanı (geri alınabilir sınıf, süre ≤ 7 gün, güven tabanı, kategorinin QA sınırı tutar) serbest bırakır ve yanıtlayıcı katmanı uygulamadan önce yeniden kararlaştırır; [0,1] dışı güven insan bekletir; geri alınamaz eylem her zaman bekler | Varsayılan ortam Act görünür (R11) |
| E | Otonomi katmanının yetkisiz ya da kanıtsız yükseltilmesi | `settings.write`; yalnızca kişi (hizmet hesabı 403, ajan/MCP yazamaz); `https://` kanıt bağlantısı zorunlu; `*` ve `other` kategorileri hiç Autonomous olamaz; her değişiklik `config_audit_log`'da; devre kesici QA sınırı bozulunca katmanı düşürür | Ayar kayıtları zincirsiz (R6) |
| E | Sohbete giren alarm metniyle modeli bekleyen eylemi onaylamaya yönlendirme | Araç yalnızca bağlı kişinin `ai_decisions.approve` izniyle çalışır; aynı kişi dört göz onayının ikinci onayını veremez | Sohbet `approve_action`'ı sunar; onay kişinin adıyla, istemeden verilebilir (R30) |
| T | Korunan varlığa (DC, yönetim IP'si) eylem | Müdahale politikası: korunan hedef ve etiketler, normalize eşleşme, geniş aralık reddi; öneride ve uygulamada iki kez; yürütücülerin kendi kuralları | MCP araç yolu politikasız (R2) |
| T | Eylemin kalıcı kalması | Geri alınabilir eylemde süre; süresi dolunca daemon geri alır ve doğrular; gerekçeli elle geri alma | — |
| R | "Ben onaylamadım" | Onaylayan(lar), zaman ve karar kuralı satırda; her geri alma ayrı satır; vaka zaman çizelgesinde | Onay kayıtları zincirsiz (R6) |
| E | Tek kişinin kritik eylemi tek başına onaylaması | `ai_decisions.approve` yalnız Senior Analyst ve üstünde; kimlik eylemlerinde dört göz onayı; sınıf başına açılabilen farklı rol koşulu; her karar rolüyle `approval_decisions`'ta; görevler ayrılığı raporu ihlalleri listeler | Varsayılanda diğer türler tek onaylı ve farklı rol koşulu kapalı (R3) |
| D | Onay kuyruğunun tıkanması; toplu eylem | Yanıtlanmayan onaylar 7 günde süresi doluyor; tür başına saatlik sınır; bir satırın hatası kuyruğu durdurmaz | — |

## 6. Veri depoları ve denetim kayıtları

| STRIDE | Tehdit | Önlem (bu sürüm) | Kalan |
|---|---|---|---|
| T | Defter/denetim kaydı kurcalama | Defter ve düzenleyici an zinciri; uygulama rolü defterde salt ekleme | Zincir başı imzasız; diğer denetim tabloları zincirsiz (R6) |
| R | Düzenleyici bildirim anlarının sonradan değiştirilmesi | `regulatory_clock_events` salt ekleme, güncelleme tetikleyiciyle reddedilir, değişiklik gerekçe ister; zincir başı çapası son olay silinmesini gösterir; anların sırası denetlenir | `TRUNCATE` reddedilmez; tablo sahibi iki tabloyu birlikte yeniden yazabilir (R27) |
| I | Veritabanı dökümüyle ya da süresi geçmiş veriyle kişisel veri sızması | Uygulama sahip olmayan rolle bağlanır; restic yedekleri şifreli; sınıf başına saklama, yasal saklama, kuru çalıştırmalı imha işi | İmha varsayılan kapalı ve politikasız; Helm dökümü şifresiz (R8, R17) |
| D | Veri kaybı, daemon kesintisi | Doğrulanan şifreli yedek, test geri yükleme; Helm yedek CronJob'u; daemon sıcak yedeği ve çitleme | CronJob varsayılan kapalı; gömülü Postgres tek kopya; RTO müşteri ortamında ölçülmedi (R17) |

## 7. Sırlar ve yapılandırma

| STRIDE | Tehdit | Önlem (bu sürüm) | Kalan |
|---|---|---|---|
| I | Entegrasyon kimlik bilgisinin sızması | Şifreli `secrets.enc`; veritabanına/JSON'a yazılmaz; API'de maskeli; Secret/ExternalSecrets | `master.key` aynı dizinde ve aynı yedekte; döndürme komutu yok (R18) |
| S | Geri yüklemeden sonra eski oturum belirteçlerinin geçerli kalması | Geri yükleme JWT anahtarını döndürür ve bekleyen onayları reddeder; anahtar yalnızca ortamdan geliyorsa yenisini `secrets.enc`'e yazar ve backend `secrets.enc`'i ortamdan önce okur, yeniden başlatmadan sonra eski oturumlar düşer | Anahtar kurulum dışındaysa (ör. Kubernetes Secret) operatör döndürmeli (R29) |
| T | Air-gap profilinin sessizce gevşetilmesi | `values-airgap.yaml` ve `airgap.env` eşitliği testli; egress envanteri ratchet | — |
| E | Konsoldan yapılandırma ile yetki | `settings.write`/`integrations.write` izinleri; değişiklik `config_audit_log`'a | — |

## 8. Giden bildirimler (webhook, e-posta, Slack)

| STRIDE | Tehdit | Önlem (bu sürüm) | Kalan |
|---|---|---|---|
| S | Alıcının sahte bildirim alması | HMAC-SHA256 imza, zaman damgası; alıcı belgesi tekrar oynatmaya karşı imzalı gövdenin `id`'siyle tekilleştirmeyi söyler | — |
| I | SSRF ile iç servislere/metadata'ya istek | Çözümlenen adres denetimi, adres sabitleme, yönlendirme yok, vekil yok, metadata adresi her zaman reddedilir | CGNAT aralığı izinli (R19) |
| I | Kanarya varlığının dışarı sızması | Kanarya vakaları dış kanala gitmez | — |
| D | Alıcı çökünce kuyruk büyümesi | Üstel geri çekilme, `WEBHOOK_MAX_ATTEMPTS` sonra `dead`; süresi dolmuş eski bir teslim talebinin geç sonucu yenisini ezmez | — |

## 9. Kurulum paketi ve tedarik zinciri

| STRIDE | Tehdit | Önlem (bu sürüm) | Kalan |
|---|---|---|---|
| S | Sahte paket | Bant dışı açık anahtarla imza doğrulaması; paket içindeki anahtar kullanılmaz | — |
| T | Doğrulamadan sonra paketin değiştirilmesi | Paket özel hazırlık dizinine kopyalanır, kopya doğrulanır ve yalnızca kopyadan kurulur | — |
| T | Arşivde sembolik bağ / yol geçişi | Listelenmemiş dosya, bağ, FIFO, aygıt reddi; kural/model arşivlerinde üye denetimi | — |
| I | İmza anahtarının sızması | Anahtar yalnızca imzalama makinesinde; sızma prosedürü belgeli | — |
| E | Bağımlılık/imaj zinciri | CI'da Trivy imaj taraması (düzeltilebilir CRITICAL'da başarısız), Bandit, Dependabot | SBOM ve imzalı imajlar Planlı — `wp/w4.7-release` (R21) |

## 10. Egress kanıtının sınırları

Çalışma zamanı koruması yalnızca Python soketlerini görür; Bifrost (Go), Node ajan
katmanı ve tarayıcı yalnızca statik taranır; uvloop'un yerel DNS'i koruma dışında
olduğu için test `--loop asyncio` kullanır. Ağ düzeyindeki önlem NetworkPolicy'dir
(R16). Ayrıntı: [tests/airgap/README.md](../../tests/airgap/README.md).

## Açık riskler

Kaynak: birleşmiş paketler için bağımsız doğrulayıcının "engelleyici değil" takip
maddeleri (`docs/wp/FIXES.md` son bölümü), iç incelemelerin bulguları ve birleşmemiş
paketlerin yokluğundan doğan riskler. Her madde bu commit'te kodda kontrol edildi.
W0.10 ile kapanan maddeler "Kapatıldı" olarak tabloda kalır. Önem: bu sürümde,
düzenlenmiş sektör kurulumu için.

| # | Risk | Önem | Kaynak | Telafi edici önlem (bugün) |
|---|---|---|---|---|
| R1 | Köken kuralı canlı triage'da uygulanır ama yalnız `benign` için: saldırganın yazdığı alanlara dayanan `malicious` geçerlidir ve bulguyu yükseltebilir; `data_source`'u gönderen seçer; injection oranı CI'da yalnızca kayıtlı tabana (21/240) karşı gerileme kapısıdır, ≤ %5 hedefi kapı değil | Orta | W1.2 bilinen sınırlar; Planlı — `wp/w1.4-injection-set` | İnsan onayı ve müdahale politikası; `DAEMON_FORCE_APPROVAL=true`; webhook/Kafka göndericilerinin kimlik doğrulaması; QA/kanarya; `evalkit` ile injection setini çevrimdışı ölçün |
| R2 | Onaylanmış MCP araçları (`mde_isolate`, `aad_disable_user`, `pan_block_ip`, `cb_quarantine`, `cf_*`) `/internal/tools/invoke` üzerinden müdahale politikası, korunan varlık listesi, saatlik sınır, yürütücü kuralları, süre dolumu, otonomi katmanı ve dört göz onayı olmadan çalışır | Yüksek | W4.6 doğrulayıcı incelemesi; dal yok | Bu satıcıların MCP sunucularını iş akışlarına açmayın (varsayılan kapalı); açıksa iş akışı onaylarını az sayıda kıdemli kişiye verin ve onay sorusundaki hedefi elle doğrulayın |
| R3 | Daraltıldı (W3.2): farklı rol koşulu ve görevler ayrılığı raporu var. Kalan: varsayılanda dört göz onayı yalnız kimlik eylemlerinde (`disable_user`, `revoke_sessions`) ve farklı rol koşulu hiçbir sınıfta açık değil | Düşük | W3.2 | `four_eyes_types`'a kritik türleri ekleyin, farklı rol koşulunu açın (Ayarlar → System → Segregation of duties); raporu periyodik olarak dışa aktarıp gözden geçirin |
| R4 | Kapatıldı (W0.10): düzenleyici an zincirine baş çapası, anların sıra kontrolü, başlamamış saatin `not_started` gösterilmesi, taslak metnindeki referansların doğrulanması. Kalan kısım R27'de | — | W0.10 | — |
| R5 | Onay araç adına bağlıdır, araç argümanlarına bağlı değil (ad sezgiseli ve onay sorusu eşlemesi W0.10'da düzeltildi) | Orta | FIXES.md, W1.7 takip | Onay sorusunda argümanlar gösterilir; onaylayıcı okumalı; R2 önlemleri |
| R6 | Defter zincirinin başı imzalı kontrol noktasına bağlı değil; onay, vaka ve ayar denetim kayıtları (imha tutanağı dahil) zincirsiz; SIEM'e akış yok | Yüksek | Planlı — `wp/w1.10-audit-chain`, `wp/w3.6-audit-export` | `vigil_app` rolü defterde salt ekleme; denetim tablolarını salt okuma rolüyle düzenli olarak dışarı alın |
| R7 | Bifrost istek günlüğü (`logs.db`) AutoSecOps saklama kurallarının dışında | Düşük | Kod incelemesi | Bifrost veri dizinini kurum politikasıyla temizleyin |
| R8 | İmha işi var ama varsayılan kapalı ve politikasız; elle silme uçları yasal saklamaya bakmaz ve tutanağa girmez; politikalar yalnız `default` kiracısında; konsol ekranı yok | Orta (KVKK) | W3.5 kapsamı | Politikaları API ile tanımlayın, kuru çalıştırmayı inceleyin, sonra `RETENTION_PURGE_DRY_RUN=false`; elle silmeyi süreçle yasaklayın |
| R9 | MFA bir rol için zorunlu kılınamaz | Orta | Kod incelemesi | Yönetici/onaylayıcı hesaplarında MFA'yı süreçle zorunlu tutun, `mfa_enabled` alanını denetleyin |
| R10 | SSO (OIDC) ve merkezi hesap yaşam döngüsü yok | Orta | Planlı — `wp/w1.9-oidc` | Yerel hesaplar; işten ayrılmada hesabı devre dışı bırakma prosedürü |
| R11 | Kodun varsayılanı `DAEMON_AUTO_RESPONSE=true`, `DAEMON_FORCE_APPROVAL=false` (Act görünümü) | Düşük | Kod incelemesi | Otonomi katmanlarının varsayılanı Approve: bir kişi bir katmanı Autonomous yapmadıkça kişi onayı olmadan eylem yok; `DAEMON_FORCE_APPROVAL=true` önerilir |
| R12 | CSRF kodda varsayılan olarak yalnızca raporlama modunda | Düşük | `core/config.py` | `VIGIL_CSRF_REPORT_ONLY=false` (`env.example` böyle) |
| R13 | Rol izinleri veritabanında değiştirilirse denetim kaydı yok | Düşük | Kod incelemesi | Veritabanı erişimini sınırlayın; değişiklik yönetimi |
| R14 | `DEV_MODE=true` açılışı engellemez | Orta | `core/auth/dev_mode.py` (bilinçli tasarım) | Helm/`env.example` varsayılanı `false`; yapılandırma denetimi |
| R15 | Bulut model sağlayıcı seçilirse alarm içeriği sağlayıcıya gider (yurt dışı aktarım) | Yüksek (KVKK) | Mimari | Air-gap profili / yerel model; sağlayıcıyı müşteri seçer |
| R16 | Temel Helm grafiğinde `networkPolicies.enabled=false`; NetworkPolicy uygulamayan CNI'da egress kısıtı etkisiz | Orta | `infra/helm/vigil/values.yaml` | `values-airgap.yaml` açar; NetworkPolicy uygulayan CNI şart |
| R17 | Helm yedek CronJob'u varsayılan kapalı ve dökümü şifrelemez; gömülü Postgres tek kopya; RTO müşteri ortamında ölçülmedi; sıcak yedekte veritabanı dışı yan etkiler (satıcı API çağrıları, agent-worker işleri) çitlenmez | Orta | W3.9, `docs/operations/rpo-rto.md` | `backup.enabled=true`, şifreli PVC/nesne deposu; harici HA Postgres; geri yükleme tatbikatı ve süre kaydı |
| R18 | `master.key` sır deposuyla aynı dizinde ve aynı yedekte; yerleşik döndürme yok | Orta | Kod incelemesi | Kubernetes'te sırları Secret/ExternalSecrets ile verin; restic parolasını ayrı saklayın |
| R19 | `url_safety` CGNAT 100.64.0.0/10'u (ör. 100.100.100.200 metadata) reddetmiyor. Alıcı belgesi ve SLA tekilleştirmesi W0.10'da düzeltildi | Orta | FIXES.md, W1.8 takip; düzeltme Planlı — `wp/w3.6-audit-export` | `WEBHOOK_ALLOWED_CIDRS`'i boş bırakın; egress NetworkPolicy |
| R20 | Yük ve sağlayıcı kesintisi testleri ve dış pentest yapılmadı. Alım dayanıklılığı için kaos testleri vardır (Postgres yeniden başlatma, daemon öldürme, Redis yeniden başlatma; `tests/perf/test_ingest_durability_chaos.py`), ama isteğe bağlıdır ve CI'da koşmaz | Yüksek | Planlı — `wp/w4.1-load-chaos`; dış pentest için dal yok (W4.4) | Kaos testlerini kurum ortamında elle çalıştırın (bkz. [docs/operations/ingest-durability.md](../operations/ingest-durability.md)) |
| R21 | SBOM ve imzalı imajlar yok | Orta | Planlı — `wp/w4.7-release` | Air-gap paketi SHA-256 + imzalı |
| R22 | Kapatıldı (W0.10): Entra ID yürütücüsü yalnızca kimliği olan rol kaydını reddeder | — | W0.10 | — |
| R23 | Egress tarayıcısında kural boşlukları (ör. asyncio.open_connection, ftplib, grpc tanınmıyor), `scripts/` taranmıyor; CI eylemleri SHA'ya sabitli değil | Düşük | FIXES.md, W3.4 takip | Çalışma zamanı testi ve NetworkPolicy |
| R24 | Kapatıldı (W0.10): QA `seed` yalnızca test modunda kabul edilir | — | W0.10 | — |
| R25 | Kapatıldı (W0.10): konsoldaki eski "Vigil" metinleri; Revert 502 ayrıntısı gösterilir | — | W0.10 | — |
| R26 | Kural kaynağı ekleme ucu (`POST /api/detection-rules/sources`) yalnızca oturum ister ve git adresini denetlemez. Oturum açmış her kullanıcı (Viewer dahil) git üzerinden iç adreslere istek yaptırabilir (kör SSRF) ve sunucuda okunabilen yerel bir git deposunu kural dizinine kopyalatabilir; bunlar gerçektir. Adres git'e `--` olmadan verildiği için seçenek enjeksiyonu da mümkündür. Komut çalıştırma sunucunun git yapılandırmasına bağlıdır: yalnızca çok eski bir git ya da git'in `ext` taşımasına izin veren bir yapılandırmada mümkündür ([bulgu raporu](../security/w4.3-redteam-findings.md)) | **Yüksek** | İç inceleme (W4.3 F-1); acil düzeltme Planlı — `wp/w0.11-security-hotfix` | Düzeltme birleşene kadar ters vekil/ingress'te `/api/detection-rules/...` altındaki yazma isteklerini engelleyin; hesapları yalnız güvenilir personele açın; kural kaynaklarını air-gap paketinden yükleyin |
| R27 | Düzenleyici an tabloları (`regulatory_clock_events`, `regulatory_clock_heads`) `TRUNCATE` ile boşaltılabilir; tablo sahibi ya da süper kullanıcı zinciri ve çapayı birlikte yeniden yazabilir | Orta | W0.10 doğrulayıcı; düzeltme Planlı — `wp/w0.11-security-hotfix` | Uygulamayı sahip olmayan `vigil_app` rolüyle çalıştırın; sahip rolün kullanımını kısıtlayıp kayda alın |
| R28 | Yalnızca oturum isteyen bazı durum değiştiren uçlar Viewer'a açık (`tests/security/auth_only_write_routes.txt`) | Orta | İç inceleme (W4.3 F-2); düzeltme Planlı — `wp/w0.11-security-hotfix` | Viewer hesaplarını az tutun; ters vekilde gereksiz uçları kapatın |
| R29 | Geri yüklemede `JWT_SECRET_KEY` kurulum dışında tanımlıysa ve sürece verilmediyse (ör. Kubernetes Secret) geri yükleme anahtarı döndüremez ve hata ile biter; anahtar döndürülene kadar eski oturumlar geçerlidir. Anahtar yalnızca ortamdan geliyorsa döndürme `secrets.enc` üzerinden çalışır (backend onu ortamdan önce okur), ama geri yüklemenin çıktısı yanlışlıkla ortamın öncelikli olduğunu söyler | Orta | W4.6 doğrulayıcı incelemesi; `core/backup/restore.py`, `core/secrets_manager.py` | Geri yüklemeden sonra anahtarı tanımlandığı yerde döndürün; ortamdaki değeri de yenileyin (bkz. [yönetici kılavuzu](yonetici-kilavuzu.md#docker-compose--tek-sunucu)) |
| R30 | Sohbet `approve_action` aracını sunar (`core/llm/chat_layers.py`): model bu aracı çağırırsa bekleyen eylem, sohbet eden kişinin adıyla ve onun `ai_decisions.approve` izniyle onaylanır. Sohbete alınan alarm metnindeki talimat (prompt injection) modeli buna yönlendirebilir | Yüksek | W4.6 doğrulayıcı incelemesi; düzeltme Planlı — `wp/w1.7b-chat-approval` | Onay yetkisi olan kişiler onay bekleyen eylem varken sohbette güvenilmez alarm metni işlemesin; kritik türlerde dört göz onayı ve farklı rol koşulunu açın; `approval_decisions` ve görevler ayrılığı raporunu gözden geçirin |
