# Tehdit modeli (STRIDE)

> **English summary.** STRIDE threat model per component of AutoSecOps at
> `integration` @ `b8795def`. For each threat it lists the mitigation that is actually
> implemented in this release and points to the open risk when there is one.
> The open-risk register at the end combines the non-blocking follow-ups the
> independent verifiers recorded for merged work packages, findings of the
> internal reviews, and the risks that remain because planned work packages
> are not merged (SBOM, injection gate, external pentest). Since the previous
> edition OIDC SSO (R10 narrowed), SIEM audit export (R6 narrowed; free-text
> PII redaction is best effort, R32), the CGNAT fix (R19 closed), FIPS mode
> (with known gaps, R31), approval argument bounds and no re-triage after a
> Redis outage are merged. In this release the
> detection-rule source hotfix (R26), the viewer write routes (R28) and the
> regulatory-table TRUNCATE (R27, narrowed) are fixed, models can no longer
> approve a pending action, `/mcp` included (R30 closed), and approvals are bound to the tool
> call's arguments (R5 closed). Approvals and case audit records are
> hash-chained with signed checkpoints, but configuration audit and approval
> decisions are not (R6). Approved agent MCP tools still bypass the response
> policy (R2). No external pentest and no capacity measurement have been run
> on this release.

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
| S | Parola tahmini, kimlik bilgisi doldurma | bcrypt (FIPS modunda PBKDF2-HMAC-SHA256); 5 hatalı girişte 15 dk kilit; giriş dakikada 5 istek; parola politikası (12+ karakter, zxcvbn ≥ 3, geçmiş 5, yasaklı liste); TOTP MFA; OIDC SSO ile yerel girişi break-glass hesaplarına sınırlama | MFA AutoSecOps'ta zorunlu kılınamaz (R9); yanlış MFA kodu kilitleme sayacına yazılmaz, sınır IP başına 5/dk |
| S | SSO geri dönüşünde sahte ya da tekrar oynatılmış kimlik | PKCE (S256); `state` tek kullanımlık ve tarayıcıya bağlı; `nonce`; ID token imzası sağlayıcının JWKS'iyle, yalnızca RS256/ES256; `iss`/`aud`/`azp`/`exp`/`iat` ve saat kayması; geri dönüş sonrası yalnızca göreli yola yönlendirme | IdP oturumu kapatma ve SCIM yok (R10) |
| E | SSO rol eşlemesiyle Admin yetkisi | Eşleşme yoksa Viewer; Admin'e eşleme ve doğrulanmış e-postayla var olan hesaba bağlanma yalnızca açıkça açılırsa ve bunu kaydetmek Admin rolü ister; hizmet hesapları SSO ile giremez | — |
| S | Çalınmış oturumla MFA'yı kapatma ya da kendine kurtarma kodu üretme | MFA açıkken kapatma ve kurtarma kodu üretme geçerli TOTP ya da kurtarma kodu ister; MFA açıkken yeniden kurulum 409; kapatma kurtarma kodlarını siler | — |
| S | Çalınan belirteçle oturum | Kısa erişim belirteci (30 dk); çıkışta JTI, parola/rol/e-posta değişiminde kullanıcı bazında iptal; Redis yokken kapalı başarısız; `Secure` + `SameSite=strict` çerez | — |
| T | CSRF ile durum değiştirme | Çift gönderim çerezi CSRF ara katmanı; Helm ve `env.example` zorlar; oturum çerezi taşıyan alım istekleri muaf değildir | Kodun varsayılanı yalnızca raporlama (R12) |
| R | Kullanıcının ayar değişikliğini inkârı | `config_audit_log` oturumdaki kullanıcıyı yazar | Zincirsiz (R6) |
| I | Yetkisiz okuma | Rota başına izin; Viewer salt okuma; kanarya verisi yalnızca Admin | — |
| D | Giriş uçlarına yük | Hız sınırları; ilk hesap ucu ilk kullanıcıdan sonra kapalı | Kapasite ölçülmedi (R20) |
| E | Bir yöneticinin e-postasını değiştirip parola sıfırlamayla hesabını ele geçirme | Admin olmayan biri yalnızca kendi hesabının ya da izinleri kendisininkinden kesin olarak az bir hesabın e-postasını, rolünü, etkinliğini değiştirebilir; hizmet hesabının e-postası `PUT /api/auth/me` ile değişmez; sıfırlama belirteci e-postaya bağlı | Sıfırlama belirteci parola değişince geçersiz olmaz (TTL boyunca) |
| E | Rol atamasıyla yetki yükseltme | Yalnızca sahip olunan tüm izinleri veren rol atanabilir; hizmet hesabı Viewer'a kilitli; her rota × her rol matrisi CI'da, gerçek HTTP isteğiyle doğrulanır | Rol izinlerinin veritabanında değiştirilmesi denetlenmez (R13) |
| E | `DEV_MODE=true` ile tüm kimlik doğrulamanın kapanması | Varsayılan `false`; açılışta ve ağdan erişilebilir adreste yüksek sesli uyarı | Açılışı engellemez (R14) |
| E | Kural kaynağı ekleme ucuyla (`POST /api/detection-rules/sources`) SSRF, sunucudaki yerel depoların okunması, git argüman enjeksiyonu | Kural kaynağı uçları `settings.write` ister (Manager, Admin); git kaynağı yalnızca `https://host/yol`, kimlik bilgisi/sorgu içermez; host iç, özel ya da metadata adrese çözülürse reddedilir (`VIGIL_DETECTION_GIT_ALLOWED_CIDRS` ile iç git sunucusuna izin verilebilir, metadata yine reddedilir); git kabuksuz, `--` ayırıcısıyla, yalnızca HTTPS protokolüne izinle, yönlendirmesiz, alt modülsüz, denetlenen adrese sabitlenerek ve zaman aşımıyla çalışır; güncelleme saklanan adresi yeniden denetler ve klonun kendi yapılandırmasına güvenmez | Vekil kullanan kurulumda adres sabitleme etkisizdir (R26) |
| E | Viewer'ın yalnızca oturumla erişebildiği durum değiştiren uçlar | Her yazma rotası ya izin ister ya da gözden geçirilmiş listededir (CI); W0.11 Viewer'a açık yazma uçlarının çoğunu izinle kapıladı | Kalan liste bilinçli (kendi hesabı, POST ile okuma, yardımcıda denetlenen) (R28) |

## 2. Alarm alımı ve AI triage

| STRIDE | Tehdit | Önlem (bu sürüm) | Kalan |
|---|---|---|---|
| S | Sahte kaynaktan alarm itme | Daemon webhook portu NetworkPolicy ile izinli CIDR'lere sınırlı; federation kaynakları yalnızca yönetici tanımlı | Webhook içeriği kaynağa kriptografik bağlı değil |
| T | Alarm alanına prompt injection yazarak "zararsız" kararı | JSON şemalı triage, katı ayrıştırma; köken kodla atanır; sensöre dayanmayan `benign` → `inconclusive`; model çıktısı doğrudan eyleme dönüşmez; insan onayı ve müdahale politikası; QA örneklemesi ve kanaryalar kaçırmayı ölçer; CI'da injection başarı oranı kayıtlı tabanı aşamaz | Yalnız saldırgan alanlarına dayanan `malicious` geçerli; `data_source` gönderenin seçimi; ≤ %5 hedefi kapı değil (R1) |
| T | Yüke analiz alanı (`triage_confidence`, `recommended_action`, `ai_triage`, `enrichment`, `category`, önceki karar) yazarak müdahaleyi ya da şeridi yönlendirme | Bu alanlar işlemeden önce atılır (`drop_payload_analysis`); otonomi kategorisi gönderenin yazdığı kategori alanından değil sensör alanlarından ve triage kararından | — |
| T | Bayrak kapalıyken yükteki `alert_lane` alanıyla triage'ı atlatma | Bayrak kapalıyken kanca bulguya dokunmaz; açıkken gelen alan atılır, yalnızca bu çalıştırmanın kararı kullanılır; kiracı yükten alınmaz; şiddeti bilinmeyen alarm bastırılmaz | — |
| R | Hangi kuralın/modelin karar verdiğinin bilinmemesi | Şerit kararı `alert_lane_decisions` tablosuna; triage kararında `model` ve `prompt_version`; onay satırına kararı veren kural | — |
| I | Alarm içeriğinin modele/dışarı gitmesi | Air-gap profili: yalnızca yerel model, bulut anahtarları boş, egress kapalı; kanarya alarmları dış zenginleştirmeye gitmez | Bulut sağlayıcı seçilirse alarm içeriği sağlayıcıya gider (R15) |
| D | Alarm seli, bütçe tükenmesi | Bütçe baskısında alarm düşürülmez, sıraya alınır; orkestratör bütçeleri; alım kuyruğu doluysa webhook 503 + `Retry-After` döner | Kapasite ölçülmedi (R20) |
| D | Veritabanı kesintisinde ya da daemon çökünce kabul edilmiş alarmın kaybı | Webhook 200'ü bulgu diskteki kalıcı kuyruğa (`fsync`) yazıldıktan sonra döner; yazım başarısızsa bulgu yeniden denenir; yazımı reddeden veritabanı (salt okunur, disk dolu, yetki) kesinti sayılır, bulgu karantinaya gitmez; açılışta kuyruk yeniden oynatılır, çift satır ve çift triage yok | Helm'de `daemon.persistence.enabled=false` ise kuyruk pod silinince kaybolur ([docs/operations/ingest-durability.md](../operations/ingest-durability.md)) |
| T | Redis kesintisinden sonra kararı verilmiş bulgunun yeniden triage edilip yanıtın iki kez çalışması | Kural şeridi ya da kuyruğa alınmış verdict run kararı kesici açıkken de kaydedilir; backfill `alert_lane_decisions`'ta kapatan kararı olan bulguyu yeniden şeritlemez; kararlar okunamazsa o tur hiçbir şey kuyruğa alınmaz (kapalı başarısız) | `alert_lane_decisions` tablosu yoksa eski davranış, hata logu ve metrik |
| E | Alarmın otonom soruşturmayı tetikleyip yetkili araç çağırması | Onay gerektiren araçlar onay noktası olmadan reddedilir; onay araç argümanlarına bağlıdır; kanarya otonom soruşturmaya giremez | Onaydan sonra politika yok (R2) |

## 3. Ajan katmanı ve araçlar (MCP)

| STRIDE | Tehdit | Önlem (bu sürüm) | Kalan |
|---|---|---|---|
| S | Küme içinden `/internal` uçlarını çağırma | `AGENT_INTERNAL_TOKEN` (sabit zamanlı karşılaştırma); NetworkPolicy (grafikte açılırsa) | Temel grafikte `networkPolicies.enabled=false` (R16) |
| T | Defter olaylarını değiştirme | `agent_events` hash zinciri; `vigil_app` rolünün UPDATE/DELETE yetkisi yok; zincir başı Ed25519 imzalı kontrol noktasına girer (`python -m core.audit.verify --agent-events`) | Son kontrol noktasından sonraki olaylar korunmaz; kontrol noktası imza anahtarı verilmezse yazılmaz (R6) |
| R | Ajanın yaptığını inkâr | Her koşunun olayları zincirli defterde; koşu başına doğrulama ucu | — |
| I | Araç çıktısıyla sır sızması | Kimlik bilgileri ajanlarda değil sır deposunda; log ve telemetri maskeleme | — |
| D | Sonsuz döngü/maliyet | Koşu ve saatlik bütçe tavanları, acil durdurma (`POST /api/orchestrator/kill`) | — |
| E | Yıkıcı aracın onaysız çağrılması | Tek tablo (`core/llm/tool_effects.py`); tabloda olmayan ad, açıkça okuma fiiliyle başlamıyorsa en kısıtlayıcı sınıfa; sohbet onay gerektiren araç sunmaz; TS çalıştırıcısı ve `/internal/tools/invoke` iki ayrı kapı; onay araç adına ve argümanlarının özetine (`args_sha256`) bağlı; ratchet: onaysız yazma aracı = 0 | — |
| E | Modelin (prompt injection ile) bekleyen bir eylemi onaylaması ya da reddetmesi | `decision` sınıfı yalnızca insana ait; `/mcp` sunucusu dahil karar araçları hiçbir model yüzeyinde yok, `/internal/tools/invoke` ve MCP yürütücüsü reddeder; kişi AI Decisions → Approvals ekranından karar verir; ratchet `tests/unit/_ratchets/test_no_model_approvals.py` | — (R30 kapatıldı) |
| T | Onaylayanı yanıltan argüman: çok uzun değer, sahte `Arguments:` satırı, görsel olarak ters çevrilmiş host adı | Onay satırı kanonik argümanların tamamını taşır; hedef değerleri 200 karakterde kesilir ve kaçışlanır (kontrol, bidi, sıfır genişlik karakterleri); 64 KB'ı aşan argümanlı çağrı onaya park edilmez (413) ve çalışmaz | Ters eğik çizgi kaçışlanmaz (yalnızca gösterim belirsizliği; bağlama ham değerle) |
| E | Onaylanmış yıkıcı aracın korunan varlığa uygulanması | Bir kişinin onay noktasını onaylaması | Bu yolda müdahale politikası, korunan varlık listesi, saatlik sınır, süre dolumu ve dört göz onayı yok (R2) |

## 4. LLM ağ geçidi ve model

| STRIDE | Tehdit | Önlem (bu sürüm) | Kalan |
|---|---|---|---|
| S | Sahte model uç noktası | Sağlayıcı URL'leri için SSRF koruması; air-gap'te yalnız küme içi Bifrost/Ollama | — |
| T | Modelin önerilen eylemi değiştirmesi | Öneri insan onayından ve müdahale politikasından geçer; Cloudflare'de hedef otoriter, parametre izin listesi; `ttl_seconds` sınırlı | MCP araç yolu politikasız (R2) |
| I | İstek günlüğünde hassas veri | Bifrost günlüğü kurulum içinde kalır | Bifrost istek günlüğünün saklama süresi AutoSecOps tarafından yönetilmez (R7) |
| D | Sağlayıcı kesintisi | Yerel model şeridi (W2.3) var ama varsayılan kapalı; açıldığında yalnızca küçük model şeridindeki triage'ı yerel modele gönderir. Kesintide şeritler arasında geri düşme yoktur: bulut sağlayıcı düşerse yerel modele, yerel model düşerse buluta geçilmez; bulgu hata ile kaydedilir ve backfill yeniden dener | Otomatik yerel modele iniş yok; kesinti davranışı yalnızca duman koşusunda denendi (R20) |
| I | Yerel model şeridinin alarm içeriğini kurum dışına göndermesi | Şerit yalnızca yapılandırılmış Bifrost'a gider; Bifrost adresi yerel/özel değilse şerit kurulmaz (`LOCAL_LANE_ALLOW_NONLOCAL_GATEWAY=false`) | — |

## 5. Müdahale hattı (onaylar ve yürütücüler)

| STRIDE | Tehdit | Önlem (bu sürüm) | Kalan |
|---|---|---|---|
| S | Onaylayanın kimliğine bürünme | Onaylayan oturumdan alınır; `ai_decisions.approve` gerekir | — |
| T | Güven puanını şişirerek onaysız eylem | Otonomi katmanının varsayılanı Approve: güven tek başına eylemi serbest bırakmaz; kişisiz yalnızca Autonomous katmanı (geri alınabilir sınıf, süre ≤ 7 gün, güven tabanı, kategorinin QA sınırı tutar) serbest bırakır ve yanıtlayıcı katmanı uygulamadan önce yeniden kararlaştırır; [0,1] dışı güven insan bekletir; geri alınamaz eylem her zaman bekler | Varsayılan ortam Act görünür (R11) |
| E | Otonomi katmanının yetkisiz ya da kanıtsız yükseltilmesi | `settings.write`; yalnızca kişi (hizmet hesabı 403, ajan/MCP yazamaz); `https://` kanıt bağlantısı zorunlu; `*` ve `other` kategorileri hiç Autonomous olamaz; her değişiklik `config_audit_log`'da; devre kesici QA sınırı bozulunca katmanı düşürür | Ayar kayıtları zincirsiz (R6) |
| T | Bir dersin (W3.11) zararsız ipucuyla gerçek alarmları gizlemesi | Ders yalnızca geçmiş etiketli alarmlarda gerilemesiz replay ile ve öneren dışında `ai_decisions.approve` sahibi bir kişi tarafından etkinleştirilir; en çok 90 gün; `critical` alarma uygulanmaz; analist dışı kökenli ders etkinleşemez; canlı triage bu sürümde dersleri hiç uygulamaz | — |
| E | Sohbete giren alarm metniyle modeli bekleyen eylemi onaylamaya yönlendirme | Karar araçları kaldırıldı; onay ve red yalnızca kişinin oturumlu HTTP isteğiyle (`POST /api/v1/approvals/{action_id}/approve`, `.../reject`) | — (R30 kapatıldı) |
| T | Korunan varlığa (DC, yönetim IP'si) eylem | Müdahale politikası: korunan hedef ve etiketler, normalize eşleşme, geniş aralık reddi; öneride ve uygulamada iki kez; yürütücülerin kendi kuralları | MCP araç yolu politikasız (R2) |
| T | Eylemin kalıcı kalması | Geri alınabilir eylemde süre; süresi dolunca daemon geri alır ve doğrular; gerekçeli elle geri alma | — |
| R | "Ben onaylamadım" | Onaylayan(lar), zaman ve karar kuralı satırda; her geri alma ayrı satır; vaka zaman çizelgesinde; `approval_actions` `audit_chain`'de zincirli; vaka kanıt paketi imzalı | `approval_decisions` zincirsiz (R6) |
| E | Tek kişinin kritik eylemi tek başına onaylaması | `ai_decisions.approve` yalnız Senior Analyst ve üstünde; kimlik eylemlerinde dört göz onayı; sınıf başına açılabilen farklı rol koşulu; her karar rolüyle `approval_decisions`'ta; görevler ayrılığı raporu ihlalleri listeler | Varsayılanda diğer türler tek onaylı ve farklı rol koşulu kapalı (R3) |
| D | Onay kuyruğunun tıkanması; toplu eylem | Yanıtlanmayan onaylar 7 günde süresi doluyor; tür başına saatlik sınır; bir satırın hatası kuyruğu durdurmaz | — |

## 6. Veri depoları ve denetim kayıtları

| STRIDE | Tehdit | Önlem (bu sürüm) | Kalan |
|---|---|---|---|
| T | Defter/denetim kaydı kurcalama | Defter, `audit_chain` (onaylar, vaka denetimi) ve düzenleyici an zinciri; uygulama rolü bunlarda salt ekleme ya da salt okuma; zincir başları imzalı kontrol noktasında; `python -m core.audit.verify` tetikleyici atlanarak yapılan değişikliği de bulur | Ayar kayıtları ve onay kararları zincirsiz; kontrol noktası anahtar ve iş açık olmadan yazılmaz (R6) |
| R | Düzenleyici bildirim anlarının sonradan değiştirilmesi | `regulatory_clock_events` salt ekleme, güncelleme ve `TRUNCATE` tetikleyiciyle reddedilir, değişiklik gerekçe ister; zincir başı çapası son olay silinmesini gösterir; çapa tablosu yoksa zincir "doğrulanmadı" görünür; anların sırası denetlenir | Tablo sahibi iki tabloyu birlikte yeniden yazabilir (R27) |
| I | Veritabanı dökümüyle ya da süresi geçmiş veriyle kişisel veri sızması | Uygulama sahip olmayan rolle bağlanır; restic yedekleri şifreli; sınıf başına saklama, yasal saklama, kuru çalıştırmalı imha işi | İmha varsayılan kapalı ve politikasız; Helm dökümü şifresiz (R8, R17) |
| D | Veri kaybı, daemon kesintisi | Doğrulanan şifreli yedek, test geri yükleme; Helm yedek CronJob'u; daemon sıcak yedeği ve çitleme | CronJob varsayılan kapalı; gömülü Postgres tek kopya; RTO müşteri ortamında ölçülmedi (R17) |
| T | Denetim kayıtlarının veritabanında sonradan silinmesi ya da yeniden yazılması | SIEM aktarımı açıksa olaylar ve imzalı kontrol noktaları veritabanı dışında, SIEM'de durur | Aktarım varsayılan kapalı; en az bir kez teslim (SIEM'de `id` ile tekilleştirme) |
| I | SIEM aktarımıyla sır ya da kişisel verinin SIEM'e gitmesi | Gönderimden önce sır ve kişisel veri maskelemesi; yapısal alanlarda anahtar adına göre; jetonlar sır deposunda ve uç noktaya bağlı; TLS doğrulaması varsayılan açık | Serbest metin maskelemesi en iyi çabadır (R32) |
| I | Kanıt paketiyle vaka verisinin dışarı çıkması | İndirme `cases.read` ister; paket imzalı, kurcalama çevrimdışı görünür | Paket redaksiyon yapmaz; `EVIDENCE_PACK_SIGNING_KEY` yoksa geçici anahtarla imzalanır ve kaynağı kanıtlamaz |

## 7. Sırlar ve yapılandırma

| STRIDE | Tehdit | Önlem (bu sürüm) | Kalan |
|---|---|---|---|
| I | Entegrasyon kimlik bilgisinin sızması | Şifreli `secrets.enc`; veritabanına/JSON'a yazılmaz; API'de maskeli; Secret/ExternalSecrets | `master.key` aynı dizinde ve aynı yedekte; döndürme komutu yok (R18) |
| I | OIDC istemci sırrının ya da SIEM jetonunun sızması | Sır deposunda; API geri döndürmez; SIEM jetonu girildiği uç noktaya bağlı, hedef değişirse yeniden girilmeli (409) | — |
| S | Kontrol noktası ya da kanıt paketi imza anahtarının çalınması | `AUDIT_CHECKPOINT_SIGNING_KEY` ve `EVIDENCE_PACK_SIGNING_KEY` sır deposunda; doğrulayıcıya yalnızca açık anahtar verilir | Anahtar döndürme arayüzü yok; anahtarı ele geçiren veritabanı sahibi zinciri ve kontrol noktalarını yeniden yazabilir (R6) |
| S | Geri yüklemeden sonra eski oturum belirteçlerinin geçerli kalması | Geri yükleme JWT anahtarını döndürür ve bekleyen onayları reddeder; anahtar yalnızca ortamdan geliyorsa yenisini `secrets.enc`'e yazar ve backend `secrets.enc`'i ortamdan önce okur, yeniden başlatmadan sonra eski oturumlar düşer | Anahtar kurulum dışındaysa (ör. Kubernetes Secret) operatör döndürmeli (R29) |
| T | Air-gap profilinin sessizce gevşetilmesi | `values-airgap.yaml` ve `airgap.env` eşitliği testli; egress envanteri ratchet | — |
| E | Konsoldan yapılandırma ile yetki | `settings.write`/`integrations.write` izinleri; değişiklik `config_audit_log`'a | — |

## 8. Giden bildirimler (webhook, e-posta, Slack)

| STRIDE | Tehdit | Önlem (bu sürüm) | Kalan |
|---|---|---|---|
| S | Alıcının sahte bildirim alması | HMAC-SHA256 imza, zaman damgası; alıcı belgesi tekrar oynatmaya karşı imzalı gövdenin `id`'siyle tekilleştirmeyi söyler | — |
| I | SSRF ile iç servislere/metadata'ya istek | Çözümlenen adres denetimi, adres sabitleme, yönlendirme yok, vekil yok, metadata adresi her zaman reddedilir; global olmayan her adres (CGNAT dahil) izin listesi olmadan reddedilir | — (R19 kapatıldı) |
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
| R2 | Onaylanmış MCP araçları (`mde_isolate`, `aad_disable_user`, `pan_block_ip`, `cb_quarantine`, `cf_*`) `/internal/tools/invoke` üzerinden müdahale politikası, korunan varlık listesi, saatlik sınır, yürütücü kuralları, süre dolumu, otonomi katmanı ve dört göz onayı olmadan çalışır. Onay W1.7b'den beri kişiye gösterilen argümanlara bağlıdır, ama gösterilen hedef korunan bir varlık ya da çok geniş bir aralık (ör. `cf_waf_block_ip` ile `0.0.0.0/0`) olsa da çalışır | Yüksek | W4.6 doğrulayıcı incelemesi; dal yok | Bu satıcıların MCP sunucularını iş akışlarına açmayın (varsayılan kapalı); açıksa iş akışı onaylarını az sayıda kıdemli kişiye verin ve onay sorusundaki hedefi elle doğrulayın |
| R3 | Daraltıldı (W3.2): farklı rol koşulu ve görevler ayrılığı raporu var. Kalan: varsayılanda dört göz onayı yalnız kimlik eylemlerinde (`disable_user`, `revoke_sessions`) ve farklı rol koşulu hiçbir sınıfta açık değil | Düşük | W3.2 | `four_eyes_types`'a kritik türleri ekleyin, farklı rol koşulunu açın (Ayarlar → System → Segregation of duties); raporu periyodik olarak dışa aktarıp gözden geçirin |
| R4 | Kapatıldı (W0.10): düzenleyici an zincirine baş çapası, anların sıra kontrolü, başlamamış saatin `not_started` gösterilmesi, taslak metnindeki referansların doğrulanması. Kalan kısım R27'de | — | W0.10 | — |
| R5 | Kapatıldı (W1.7b): onay, kişiye gösterilen araç argümanlarının özetine (`args_sha256`) bağlıdır; başka argümanla tekrar oynatılamaz | — | W1.7b | — |
| R6 | Daraltıldı (W1.10). `approval_actions` ve `case_audit_logs` zincirli; ajan defteri ve `audit_chain` başları imzalı kontrol noktasına girer. Kalan: `config_audit_log` (imha tutanağı ve otonomi değişiklikleri dahil) ve `approval_decisions` zincirsiz; SIEM'e aktarım (W3.6) var ama varsayılan kapalı ve `approval_decisions`'ı taşımaz; kontrol noktası yalnızca imza anahtarı verilip iş açıksa yazılır ve ancak veritabanı dışında tutulan açık anahtarla doğrulanırsa anlamlıdır; son kontrol noktasından sonraki satırlar korunmaz | Orta | W1.10 sınırları; W3.6 | SIEM aktarımını `audit_checkpoints` kaynağıyla açın; `AUDIT_CHECKPOINT_SIGNING_KEY`'i verin, aralığı kısa tutun, `AUDIT_CHECKPOINT_FILE`'ı başka makinede tutun; `python -m core.audit.verify --require-signature --public-key <anahtar>`'ı zamanlanmış çalıştırın; denetim tablolarını salt okuma rolüyle düzenli olarak dışarı alın |
| R7 | Bifrost istek günlüğü (`logs.db`) AutoSecOps saklama kurallarının dışında | Düşük | Kod incelemesi | Bifrost veri dizinini kurum politikasıyla temizleyin |
| R8 | İmha işi var ama varsayılan kapalı ve politikasız; elle silme uçları yasal saklamaya bakmaz ve tutanağa girmez; politikalar yalnız `default` kiracısında; konsol ekranı yok | Orta (KVKK) | W3.5 kapsamı | Politikaları API ile tanımlayın, kuru çalıştırmayı inceleyin, sonra `RETENTION_PURGE_DRY_RUN=false`; elle silmeyi süreçle yasaklayın |
| R9 | MFA bir rol için zorunlu kılınamaz | Orta | Kod incelemesi | Yönetici/onaylayıcı hesaplarında MFA'yı süreçle zorunlu tutun, `mfa_enabled` alanını denetleyin |
| R10 | Daraltıldı (W1.9): OIDC SSO var. Kalan: SCIM ve IdP'den oturum kapatma yok; IdP'de kapatılan hesabın açık AutoSecOps oturumu belirteç ömrü boyunca sürer; SAML yalnızca bir OIDC aracıyla | Düşük | W1.9 kapsam dışı | İşten ayrılmada hesabı AutoSecOps'ta da devre dışı bırakın (oturumlar anında düşer); yerel girişi break-glass hesaplarına sınırlayın |
| R11 | Kodun varsayılanı `DAEMON_AUTO_RESPONSE=true`, `DAEMON_FORCE_APPROVAL=false` (Act görünümü) | Düşük | Kod incelemesi | Otonomi katmanlarının varsayılanı Approve: bir kişi bir katmanı Autonomous yapmadıkça kişi onayı olmadan eylem yok; `DAEMON_FORCE_APPROVAL=true` önerilir |
| R12 | CSRF kodda varsayılan olarak yalnızca raporlama modunda; Helm ve `env.example` W0.13'ten beri zorlar | Düşük | `core/config.py` | `VIGIL_CSRF_REPORT_ONLY=false` (Helm ve `env.example` böyle) |
| R13 | Rol izinleri veritabanında değiştirilirse denetim kaydı yok | Düşük | Kod incelemesi | Veritabanı erişimini sınırlayın; değişiklik yönetimi |
| R14 | `DEV_MODE=true` açılışı engellemez | Orta | `core/auth/dev_mode.py` (bilinçli tasarım) | Helm/`env.example` varsayılanı `false`; yapılandırma denetimi |
| R15 | Bulut model sağlayıcı seçilirse alarm içeriği sağlayıcıya gider (yurt dışı aktarım) | Yüksek (KVKK) | Mimari | Air-gap profili / yerel model; sağlayıcıyı müşteri seçer |
| R16 | Temel Helm grafiğinde `networkPolicies.enabled=false`; NetworkPolicy uygulamayan CNI'da egress kısıtı etkisiz | Orta | `infra/helm/vigil/values.yaml` | `values-airgap.yaml` açar; NetworkPolicy uygulayan CNI şart |
| R17 | Helm yedek CronJob'u varsayılan kapalı ve dökümü şifrelemez; gömülü Postgres tek kopya; RTO müşteri ortamında ölçülmedi; sıcak yedekte veritabanı dışı yan etkiler (satıcı API çağrıları, agent-worker işleri) çitlenmez | Orta | W3.9, `docs/operations/rpo-rto.md` | `backup.enabled=true`, şifreli PVC/nesne deposu; harici HA Postgres; geri yükleme tatbikatı ve süre kaydı |
| R18 | `master.key` sır deposuyla aynı dizinde ve aynı yedekte; yerleşik döndürme yok | Orta | Kod incelemesi | Kubernetes'te sırları Secret/ExternalSecrets ile verin; restic parolasını ayrı saklayın |
| R19 | Kapatıldı (W3.6): `url_safety` global olmayan her adresi, CGNAT 100.64.0.0/10 dahil, reddeder; şirket içi LLM ağ geçidi için `LLM_PROVIDER_ALLOWED_CIDRS`, webhook için `WEBHOOK_ALLOWED_CIDRS`; metadata adresleri her durumda reddedilir | — | W3.6 | — |
| R20 | Yük ve kaos test araçları var (`tests/perf/`, [docs/operations/load-chaos-runbook.md](../operations/load-chaos-runbook.md)): sürekli ve ani yük, şerit başına gecikme; model 5xx ve zaman aşımı, Postgres ve Redis yeniden başlatma, daemon öldürme, yedekli daemon öldürme, yavaş satıcı. Ancak isteğe bağlıdır ve CI'da koşmaz; yalnızca geliştirme makinesinde küçük bir duman koşusu kayıtlıdır. Bu sürüm için kapasite ölçümü ve SLO kanıtı yoktur; dış pentest yapılmadı | Yüksek | W4.1 (duman koşusu: `docs/wp/w4.1.md`); dış pentest için dal yok (W4.4) | Runbook'la staging'de tam yük ve kaos koşusu yapıp raporu saklayın; kurumun beklediği alarm hızında SLO'ları ölçün |
| R21 | SBOM ve imzalı imajlar yok | Orta | Planlı — `wp/w4.7-release` | Air-gap paketi SHA-256 + imzalı |
| R22 | Kapatıldı (W0.10): Entra ID yürütücüsü yalnızca kimliği olan rol kaydını reddeder | — | W0.10 | — |
| R23 | Egress tarayıcısında kural boşlukları (ör. asyncio.open_connection, ftplib, grpc tanınmıyor), `scripts/` taranmıyor; CI eylemleri SHA'ya sabitli değil | Düşük | FIXES.md, W3.4 takip | Çalışma zamanı testi ve NetworkPolicy |
| R24 | Kapatıldı (W0.10): QA `seed` yalnızca test modunda kabul edilir | — | W0.10 | — |
| R25 | Kapatıldı (W0.10): konsoldaki eski ürün adını taşıyan metinler; Revert 502 ayrıntısı gösterilir | — | W0.10 | — |
| R26 | Kapatıldı (W0.11): kural kaynağı uçları `settings.write` ister; git kaynağı yalnızca `https://` ve dış (ya da `VIGIL_DETECTION_GIT_ALLOWED_CIDRS` ile izinli) adres; git `--` ayırıcısı, protokol kısıtı (`ext`, `file` kapalı), yönlendirmesiz ve adres sabitlemeyle çalışır; güncelleme saklanan adresi `fetch -- <adres>` ile çeker, klonun yapılandırmasındaki tehlikeli anahtarları reddeder. Kalan: ad çözümlemesi API makinesinde yapılır; vekil kullanan kurulumda adres sabitleme etkisizdir | Düşük | W4.3 F-1, W0.11 | Kural kaynaklarını air-gap paketinden ya da yerel yoldan yükleyin; iç git sunucusu için yalnızca gerekli CIDR'i izinleyin |
| R27 | Daraltıldı (W0.11): düzenleyici an tabloları `TRUNCATE`'i tetikleyiciyle reddeder; çapa tablosu yoksa zincir doğrulanmamış görünür. Kalan: tablo sahibi ya da süper kullanıcı tetikleyicileri kapatıp zinciri ve çapayı birlikte yeniden yazabilir | Düşük | W0.10 doğrulayıcı, W0.11 | Uygulamayı sahip olmayan `vigil_app` rolüyle çalıştırın; sahip rolün kullanımını kısıtlayıp kayda alın; kanıt paketini olay anında dışarı alın |
| R28 | Daraltıldı (W0.11): Viewer'a açık yazma uçlarının çoğu mevcut izinlerle kapılandı (ör. ingest, gürültü işaretleme, beceriler, özel ajanlar, iş akışı üretme, SLA politikaları, vaka şablonları, maliyet yeniden hesabı, AI karar kaydı). Kalan liste (`tests/security/auth_only_write_routes.txt`) bilinçlidir: kendi hesabı ve oturum, kendi sohbetleri, yardımcıda denetlenenler, POST ile okumalar, bulgu zenginleştirme | Düşük | W4.3 F-2, W0.11 | Viewer hesaplarını az tutun; listeyi her sürümde gözden geçirin |
| R29 | (Açık) Geri yüklemede `JWT_SECRET_KEY` kurulum dışında tanımlıysa ve sürece verilmediyse (ör. Kubernetes Secret) geri yükleme anahtarı döndüremez ve hata ile biter; anahtar döndürülene kadar eski oturumlar geçerlidir. Anahtar yalnızca ortamdan geliyorsa döndürme `secrets.enc` üzerinden çalışır (backend onu ortamdan önce okur), ama geri yüklemenin çıktısı yanlışlıkla ortamın öncelikli olduğunu söyler | Orta | W4.6 doğrulayıcı incelemesi; `core/backup/restore.py`, `core/secrets_manager.py` | Geri yüklemeden sonra anahtarı tanımlandığı yerde döndürün; ortamdaki değeri de yenileyin (bkz. [yönetici kılavuzu](yonetici-kilavuzu.md#docker-compose--tek-sunucu)) |
| R30 | Kapatıldı (W1.7b): `approve_action` / `reject_action` araçları kaldırıldı; `decision` sınıfı yalnızca insana ait ve hiçbir model yüzeyinde (sohbet, iş akışları, `/mcp`, `/internal/tools/invoke`, MCP yürütücüsü) sunulmaz ya da çalışmaz | — | W1.7b | — |
| R31 | FIPS modunun bilinen boşlukları: denetim kontrol noktası ve kanıt paketi imzaları `FIPS_MODE=true` iken de Ed25519 kalır ve FIPS onaylı sayılmaz; veritabanı proxy'sinin `ssh_tunnel` türü algoritma seçimini kısıtlamaz ve FIPS modunda desteklenmez (kod engellemez); Medic güven kökü Ed25519; TypeScript ajanı için FIPS denetimi yok | Orta (FIPS isteyen kurulumda) | W3.10, [docs/fips.md](../fips.md) | FIPS kapsamını denetçiye bu boşluklarla bildirin; `ssh_tunnel` yerine TLS'li doğrudan bağlantı ya da HTTP proxy kullanın; ajan katmanını `node --enable-fips` ile çalıştırın |
| R32 | SIEM aktarımında serbest metindeki (`message`, `details` dizeleri, `user_agent`) kişisel veri ve kimlik bilgisi maskelemesi en iyi çabadır: tanınmayan düzyazı biçimleri (ayırıcısız `diagnosis HIV`, adı geçmeyen bir kişi adı, `+` öneksiz yerel telefon) olduğu gibi aktarılır. Kimlik doğrulama olayları API kopyasının yerel biriktiricisindedir; dizin paylaşılmazsa lider olmayan kopyaların olayları aktarılmaz | Orta (KVKK) | W3.6, [core/compliance/AUDIT_EXPORT.md](../../core/compliance/AUDIT_EXPORT.md) | Kesin maskelenmesi gereken değerleri yapısal alanlarda gönderin; SIEM tarafında erişimi ve saklamayı kişisel veri olarak yönetin; çok kopyalı API'de `$VIGIL_DIR/audit_export/`'u paylaşılan birime koyun |
