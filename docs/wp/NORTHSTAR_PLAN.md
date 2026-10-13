# autosecops2 Northstar uygulama planı

Oct 11, 2026 · @Muhammet Anıl Yağız

## Northstar: ne olmak istiyoruz

**Tek cümle: AutoSecOps, doğruluğunu müşterinin kendi verisinde kanıtlayan, her belirsiz alarmı kanıt öncelikli soruşturan, kendi başına yalnızca geri alınabilir eylem yapan ve verinin olduğu yerde çalışan AI SOC'tur.** Kısa slogan: *Kanıtlanabilir AI SOC.*

Neden bu tez: pazardaki her satıcı %90–99 doğruluk iddia ediyor, ama araştırmamızda otomatik kapatılan alarmlardaki kaçırma oranını (FN) yayımlayan bir satıcı bulamadık. Microsoft'un kendi kontrollü deneyinde, deneye bilerek yerleştirilen yanlış negatiflerin %46'sını ajanla çalışan analistler kaçırdı (kontrol grubunda %17); yani "insan kontrol eder" güvencesi tek başına çalışmıyor. Alıcının bir numaralı sorusu "alarmları kapatmasına güvenebilir miyim?". Bizim cevabımız pazarlama metni değil, ürünün içindeki ölçüm olacak.

&#91;embedded content: Kuzey yıldızı ve dört farklılaşma ayağı\]

### Bu planı şekillendiren kararlar

| Karar | Seçim | Plana etkisi |
| --- | --- | --- |
| Hedef | Düzenlenen sektöre (banka, kamu, kritik altyapı) 2.0 GA: **30 Ekim 2026**; 31 Ekim tampon | Plan sprint değil dalga ile ilerler: beş dalga, 19 gün |
| Yürütme | 2–3 mühendis + paralel alt ajan filosu; her iş paketini ayrı bir doğrulayıcı ajan denetler | Darboğaz kod yazmak değil, doğrulama ve insan onayı; plan bunu tasarlar |
| Müşteri sırası | Önce düzenlenen sektör (2.0, 30 Ekim), sonra MSSP (2.1, Kasım) | Çok kiracılık 2.0'da yok; yeni tablolar `tenant_id` ile doğar |
| Upstream | Sert fork, kendi yolumuz | Dalga 0'da son senkron; sonra yalnızca güvenlik düzeltmeleri seçilerek alınır |
| Otonomi varsayılanı | GA'da "onayla" katmanı; otomatik kapatma kategori bazında, karne kanıtladıkça açılır | Gerçek FN kanıtı takvim ister (hiç kaçırma yoksa kategori başına en az 299 incelenmiş örnek); GA'yı engellemez, düzenlenen sektör zaten insan onayı ister |

### Kuzey yıldızı metriği

**Güvenle kapanan alarm oranı (GKAO):** son 30 günde insan dokunmadan doğru sonuçlanan alarmların tüm alarmlara oranı. Bir kategorinin otomatik kapananları, o kategorinin son 30 günlük basit rastgele QA örnekleminde FN oranının tek taraflı %95 üst sınırı (Clopper–Pearson) %1'in altındaysa sayılır; değilse sıfır sayılır. Hiç kaçırma yoksa bu, kategori başına en az 299 incelenmiş örnek demektir. Böylece metrik hem değeri (analist zamanı) hem güveni (kalite) aynı anda ölçer; kaliteyi bozarak büyütülemez.

Koruma metrikleri, GKAO'nun şişirilmesini engeller:

| Metrik | Başlangıç hedefi | Nereden ölçülür |
| --- | --- | --- |
| Otomatik kapananlarda örneklenmiş FN oranı | %95 güvenle ≤ %1 | QA örnekleme kuyruğu (Dalga 1) |
| Gizli kanarya alarmları yakalama oranı | ≥ %99 | Kanarya enjektörü (Dalga 1) |
| Kategori bazında recall (etiketli korpus) | ≥ %95 | Eval düzeneği (Dalga 1) |
| Belirsiz karar oranı | ≤ %15 | Eval ve canlı dağılım |
| Injection saldırı başarı oranı | ≤ %5 | Injection test seti (Dalga 1) |
| Gerçek pozitifte alarmdan kontrol altına almaya süre | Pilot müşteri baz çizgisinin yarısı | Defter zaman damgaları |
| Alarm başına LLM maliyeti | Hepsi frontier modele göre −%60 | Mevcut core/llm/cost/ ve alert\_routes (Dalga 2) |
| Geri alınamaz otonom eylem sayısı | Her zaman 0 | Eylem politikası (Dalga 2) |

Hedefler pazar referanslarından türetilmiş başlangıç değerleridir; Dalga 1'deki baz çizgisi ölçülünce yeniden ayarlanır.

### Farklılaşma: dört ayak

| Ayak | Rakipler bugün | AutoSecOps | Kanıtı nasıl gösteririz |
| --- | --- | --- | --- |
| Ölçülen doğruluk | Yöntemi açıklanmayan satıcı rakamları | Ürün içi eval, gizli kanaryalar, otomatik kapananlarda örnekleme; müşterinin kendi verisinde karne | Yayımlanan metodoloji ve her sürümde güncellenen karne |
| Hipotez döngüsü | Tek ajan, kökensiz alarm alanları | Sıfır hipotezi, karşıt eleştirmen ve alan kökeni her belirsiz alarmda; saldırganın yazdığı alan tek başına "zararsız" kararı veremez | Injection test setinde ölçülen saldırı başarı oranı |
| Geri alınabilirlik | Onayla ve çalıştır; geri alma yok | Her eylemin tersi, süre dolumu ve eylem sonrası doğrulaması; ölçüme bağlı devre kesici; otonomiyi yalnızca insan yükseltir | Kaos testi: devre kesici kendiliğinden otonomiyi düşürür |
| Egemen ve açık | SaaS, kredi sayacı, tek bulut | Kendi barındırma, internetsiz kurulum, yerel ya da müşterinin seçtiği model; maliyeti alarm zorluğu belirler | İnternetsiz kurulum paketi ve alarm başı maliyet panosu |

Bu dört ayağın temeli zaten kodda: hash zincirli defter, replay ve fail-closed onay. Planın işi, bu temeli alarm yoluna, yanıta ve ölçüme taşımak.

## Tasarım ilkeleri ve bilerek yapmayacaklarımız

**Frontier olan şey muhakeme ve kanıttır, altyapı değil.** Mevcut süreçler (API, daemon, llm-worker, agent-worker), Postgres ve hunt döngüsü yeterli. Plan yeni bir veri deposu, yeni bir ajan çatısı veya mikroservis bölünmesi getirmez.

### On ilke

1. **Ölçemiyorsan otomatikleştirme.** Hiçbir otonomi artışı, eval ve canlı örneklemede kanıtlanmadan varsayılan açık olmaz. Her özellik bir bayrakla gelir ve bayrağın varsayılanı güvenli taraftır.
2. **Hunt döngüsünü yeniden kullan, yeni çatı yazma.** Alarm soruşturması, `services/agent/arch/registry.ts` içindeki `HUNT_LOOP`'u kullanan yeni bir run türüdür; `adjudicate` bunu zaten yapıyor.
3. **Tek veri deposu: Postgres.** Graf, vektör veya kuyruk için yeni sistem yok. Benzer vaka araması önce Postgres tam metin ve trigram ile yapılır; vektör ancak eval fark gösterirse gelir.
4. **LLM önerir, politika karar verir, executor uygular.** Model çıktısı hiçbir zaman doğrudan bir API çağrısına dönüşmez; tipli eylem şemasından ve politika kontrolünden geçer.
5. **Geri alınamayan şey otonom olamaz.** `reverse` ve `verify` fonksiyonu olmayan bir executor'ın eylemi en fazla "onayla" katmanında kalır.
6. **İç isimlere dokunma.** Marka değişimi yalnızca kullanıcıya görünen yüzeydedir. `vigil_app` rolü, Python paket yolları ve tablo isimleri aynı kalır; yeniden adlandırma değer değil hata üretir.
7. **Yeni tablo `tenant_id` ile doğar.** MSSP Kasım'da gelir; bugün eklenen ucuz bir sütun yarınki pahalı göçü önler. Ama satır düzeyi güvenlik (RLS) ve kiracı arayüzü 2.0'da yapılmaz.
8. **Mevcut sınıflandırmayı kullan.** Araç adından türetilen (changes\_for\_tool) `read_only`, `asks_first`, `on_its_own` sınıfları zaten var (`core/llm/chat_layers.py`, `core/agents/manager.py`). Yeni bir izin dili icat edilmez, bu sınıflar her yerde zorunlu hale getirilir.
9. **Paralel ajanlar ayrık dosyalarda çalışır.** Her iş paketi dokunabileceği dosyaları önceden beyan eder; iki paket aynı dosyaya dokunacaksa sıraya girer. Sözleşmeler (verdict şeması, Executor protokolü, tablo şemaları) Dalga 0'da donar ve paketler onlara karşı yazılır.
10. **Bitti tanımı (DoD):** bağımsız doğrulayıcı ajandan PASS, birim ve entegrasyon testi, eval'de regresyon yok, deftere olay yazılıyor, belge güncel, bayrak varsayılanı yazılı, Helm ve Compose'da çalışıyor.

### 2.0 kapsamı dışında bıraktıklarımız

| Ne | Neden | Ne zaman tekrar bakılır |
| --- | --- | --- |
| Medic (System Watcher) yatırımı | Kurulum sağlığı alıcının satın alma kriteri değil; yaklaşık 100 açık iş `icebox` etiketiyle dondurulur, mevcut kod gözlem modunda kalır | GA sonrası, işletim ihtiyacı doğarsa |
| Konsolun yeniden tasarımı, Tailwind 4 | Mevcut ekranlar yeterli; yalnızca dört yeni ekran eklenir: Karne, İnceleme kuyruğu, Eylem zaman çizelgesi, Otonomi | Müşteri geri bildirimi |
| Vektör DB, pgvector, graf DB | Postgres tam metin ve tablo tabanlı varlık ilişkileri yeterli | Eval fark gösterirse Kasım |
| Kendi model eğitimi, fine-tune | Küçük/yerel model hattı ve dersler önce denenir | GA sonrası |
| Her üretici için executor | 2.0'da Defender, Entra ID ve pilotun güvenlik duvarı; Cloudflare zaten var | Pilot ve müşteri talebiyle |
| Görsel SOAR playbook editörü | `compose` iş akışları ve WORKFLOW.md yeterli | – |
| Electron masaüstü, Windows paketi | Yalnızca bakım | – |
| Kafka zorunluluğu, Avro, Schema Registry | Webhook ve Federation yeterli | Kasım, OCSF ile |
| Yerel SAML uygulaması | OIDC + Keycloak veya Dex aracılığıyla SAML'i karşılar | Talep olursa |
| Sohbet asistanını genişletmek | Farklılaşma alarm yolunda, sohbette değil | – |

### Fork stratejisi: sert fork

- **Marka (tamamlandı, 12 Ekim).** Konsol, giriş ekranı, sohbet, şifre sıfırlama e-postası, doğrulayıcı uygulamadaki TOTP adı, OpenAPI sayfası, rapor şablonları ve masaüstü uygulaması artık AutoSecOps yazıyor (`main` @ `b71a98b1`). Bir alt ajan uyguladı, ayrı bir alt ajan üç turda doğruladı; kaçırılmış 8 yeri ve düzeltmenin getirdiği 2 yeni hatayı yakaladı. Logo işareti hâlâ Vigil'in devre-kalkan çizimi; yeni işaret açık bir karardır.
- **Son senkron (Dalga 0).** Upstream'de içe aktarımdan beri en az 16 yeni commit var (senkron anında yeniden sayılır): çoğu ölü kod temizliği ve konsol düzeltmesi, biri güvenlik düzeltmesi (#2153: rolü değişen kullanıcının oturumu kapanır), ikisi burada zaten birleştirilmiş PR'ların upstream kopyası. Upstream'in `40_skill_reads.sql` dosyası bizim `45_skill_reads.sql` ile çakışır; bizimki korunur. Bunlar son kez birleştirilir, birleştirme commit'i `fork-point-2026-10` etiketiyle işaretlenir.
- **Upstream radarı.** Sonrasında ayda bir yarım gün upstream taranır; yalnızca güvenlik ve veri kaybı düzeltmeleri `git cherry-pick -x` ile alınır. `FORK.md` haftalık senkron yerine bu modele göre yeniden yazılır.
- **Lisans.** Apache-2.0 `LICENSE` korunur (upstream'de `NOTICE` dosyası yok), değiştirilen dosyalar belirtilir. Apache-2.0 marka hakkı vermez; bu yüzden "Vigil" adı kullanıcıya görünen yerlerden çıkarıldı.
- **Bedeli.** Upstream'in faz 2'sinde planladığı otonomi denetleyicisi, Act contract, güven puanı ve çok kullanıcı özelliklerini bağımsız yazacağız (`docs/design/console/PRD-phase1.md`, bölüm 15). Upstream bunları ücretsiz yayımladığında farkımız ölçüm, eylem genişliği, düzenlenen sektör paketi ve MSSP'de kalmalı.

## Hedef mimari

**Yeni olan her şey mevcut alarm akışının içine, mevcut süreçlerin içinde modül olarak oturur.** Bugünkü akış kaynak → `FindingProcessor` → tek çağrılık triage → (kapalı) orchestrator → `investigate` run → onay satırı şeklindedir. Hedef akışta triage bir yönlendiriciye dönüşür, belirsiz alarmlar hunt döngüsüne gider ve her eylem bir politika ile executor arayüzünden geçer.

&#91;embedded content: Hedef alarm akışı · yeni modüller vurgulu\]

### Modüller ve yerleri

| Modül | Nerede | Ne yapar | Dalga |
| --- | --- | --- | --- |
| Eval düzeneği | Yeni `eval/` paketi; CLI `python -m eval` | Etiketli korpusu triage ve verdict yolundan offline geçirir; kategori bazında precision, recall, inconclusive, maliyet, gecikme üretir | 1 |
| Yapılandırılmış triage | `services/daemon/processor.py` (`_build_triage_prompt`, `_apply_triage_result`) | Satır satır ayrıştırılan düz metin yerine JSON şema; `verdict` alanında `inconclusive` zorunlu seçenek; alıntılanan alanlar ve kökenleri | 1 |
| Alan kökeni haritası | Yeni `core/federation/provenance.py` | Her adaptör için hangi alanın sensör, hangisinin saldırgan tarafından yazılabilir olduğunu tanımlar | 1 |
| Kanarya ve QA örnekleme | `services/daemon/probes.py` genişler; yeni `core/quality/` | Gizli kötücül replay'ler ve otomatik kapananlardan örnek inceleme; FN üst sınırı | 1 |
| OIDC SSO | Yeni `core/auth/oidc_router.py` (`core/**/*_router.py` keşif kuralına uyar) | Entra ID, Okta, Keycloak; grup → rol eşlemesi; yerel hesap acil erişim için kalır | 1 |
| Verdict run türü | Yeni `services/agent/arch/verdict.yaml`, `registry.ts`'te `HUNT_LOOP` ile kayıt | Sıfır hipotezi, ≤ 2 işçi, zorunlu eleştirmen; çıktı zararlı, zararsız veya belirsiz | 2 |
| Alarm yönlendirici | Yeni `core/lanes/alert_lanes.py (mevcut core/routing.py ve *_router.py keşif kuralıyla çakışmaz)`; daemon'dan çağrılır | Üç şerit: kural, küçük model, verdict run; eşikler `INTENT.md`'den okunur ve uygulanır | 2 |
| Eylem politikası | Yeni `core/response/policy.py` | Tipli eylem şeması, korunan varlık listesi, saatlik etki sınırı, dört göz onayı gerektiren sınıflar | 2 |
| Executor arayüzü | Yeni `core/response/executors/`; `autonomous_response_service.execute_approved_actions` içindeki if/elif dağıtımının yerine | `validate`, `execute`, `verify`, `reverse`, `default_ttl`; süresi dolan eylemi daemon döngüsü geri alır | 2 |
| Otonomi denetleyicisi | Yeni `core/autonomy/`; `services/api/routers/config.py`'deki türetilmiş Assist/Act etiketinin yerine | Kategori × eylem sınıfı başına katman; devre kesici; yalnızca insan yükseltir | 3 |
| Dersler | Yeni `core/lessons/`; verdict run bağlamına ve kural şeridine beslenir | Analist düzeltmesinden kapsamlı ve süreli ders; replay ile terfi; tek tıkla geri alma | 3 |
| Düzenlenen sektör paketi | `infra/airgap/`, `core/compliance/`, Helm değerleri | İnternetsiz kurulum paketi, FIPS modu, saklama politikaları, kanıt paketi, denetim akışı | 3 |

### Veri modeli eklemeleri

Tüm yeni tablolar `tenant_id TEXT NOT NULL DEFAULT 'default'` taşır ve `infra/database/init/46_…` numarasından başlar (Helm aynası ve `dbInit.sqlFiles` dahil, `FORK.md`'deki kurala göre).

| Tablo | İçerik | Dalga |
| --- | --- | --- |
| `eval_runs`, `eval_results` | Suite, model, sürüm, kategori bazında metrikler; karne buradan okur | 1 |
| `qa_samples` | Örneklenen alarm, örnekleme türü (basit rastgele ya da risk ağırlıklı), ajan kararı, analist kararı | 1 |
| `canary_injections` | Enjekte edilen gizli alarm, beklenen sonuç, yakalandı mı, ne zaman | 1 |
| `webhook_endpoints`, `webhook_deliveries` | Giden webhook hedefleri, imza anahtarı referansı, teslim denemeleri ve başarısız teslimler | 1 |
| `alert_routes` | Alarm başına seçilen şerit, neden, maliyet | 2 |
| `approval_actions` (mevcut tablo) | `30_approval_action_reversibility.sql`'in `reversibility` ve `idempotency_key` sütunları kullanılır; eklenenler: `expires_at`, `verified_at`, `verify_status`, `reversed_at`, `reverse_of`, `before_state`, `after_state`, `second_approver` | 2 |
| `autonomy_tiers` | Kategori, eylem sınıfı, katman, yükselten kişi, kanıt bağlantısı, düşürme nedeni | 3 |
| `lessons`, `suppression_rules` | Kapsam, geçerlilik süresi, gerekçe, replay sonucu, durum | 3 |
| `retention_policies` | Veri sınıfı, saklama süresi, silme yöntemi, yasal dayanak | 3 |

### İki sözleşme

Executor arayüzü, yanıt tarafındaki tüm yeni kodun tek giriş noktasıdır:

```python
class Executor(Protocol):
    action_types: frozenset[str]      # ör. {"isolate_host", "unisolate_host"}
    reversible_types: frozenset[str]  # yalnız bunlar otonom katmana çıkabilir
    default_ttl: timedelta | None     # ör. IP engeli 24 saat

    def validate(self, action: TypedAction) -> PolicyResult: ...
    def execute(self, action: TypedAction) -> ExecResult: ...
    def verify(self, action: TypedAction, result: ExecResult) -> VerifyResult: ...
    def reverse(self, action: TypedAction, result: ExecResult) -> ExecResult: ...
```

Verdict çıktısı, triage ve verdict run için ortak şemadır; karne ve otonomi denetleyicisi yalnızca bunu okur:

```json
{
  "verdict": "malicious | benign | inconclusive",
  "confidence": 0.0,
  "category": "phishing | malware | identity | network | cloud | other",
  "cited_fields": [{"field": "process.parent", "authored": "sensor | adversary | third_party"}],
  "gaps": ["edr_telemetry_unavailable"],
  "recommended_action": {"type": "isolate_host", "target": "host:WS-042"}
}
```

Kural: `benign` kararı, en az bir `authored: sensor` alanına dayanmıyorsa otomatik olarak `inconclusive` olur. authored alanını model değil kod, köken haritasından doldurur; model yalnız alan adını alıntılar. Bu, injection'a karşı yapısal savunmanın çekirdeğidir ama tek başına yeterli değildir (önemsiz bir sensör alanı alıntılanabilir); injection seti ve doğrulayıcı bunu ölçer.

## Takvim: 30 Ekim'de düzenlenen sektöre GA

**Plan sprint değil dalga ile ilerler: beş dalga, üç kapı, 19 gün.** Her dalgada çok sayıda iş paketi alt ajanlarla paralel yürütülür; bir kapı geçilmeden sonraki dalganın otonomi içeren işleri birleştirilmez. Alt ajanlar hafta sonu ve bayramda da çalışır; insan onayı gereken birleştirmeler iş günlerine sıralanır. 17–18 ve 24–25 Ekim hafta sonları için bir mühendislik inceleme nöbeti gerekir; nöbet yoksa Kapı A ve Dalga 3'ün Yüksek paketleri birer iş günü kayar.

&#91;embedded content: Plan tarihleri · 12–31 Ekim 2026, günlük\]

| Dalga | Tarih | Hedef | Paralel iş paketleri | Çıkış kapısı (kanıt) |
| --- | --- | --- | --- | --- |
| 0 | 12–13 Eki | Zemin ve ajan fabrikası | Son upstream senkronu; marka (tamamlandı); tam CI; fabrika: iş paketi şablonu, worktree, doğrulayıcı istemleri, birleştirme treni; sözleşmeler donar (verdict şeması, Executor protokolü, 46+ tablolar); staging; eval korpus tohumu; pentest ve M365 geliştirici kiracısı talebi; regüle gereksinim listesi | CI yeşil, sözleşmeler `main`'de, Dalga 1'in tüm iş paketi tanımları hazır |
| 1 | 14–17 Eki | Ölçüm ve dürüst çekirdek | Eval düzeneği; JSON triage ve alan kökeni; injection seti; kanarya; QA örnekleme ve Karne ekranı; araç etki sınıfları her yerde zorunlu; giden webhook ve vaka otomasyonu; OIDC SSO; denetim zincirinin onaylara ve vaka denetimine genişlemesi | **Kapı A**: eval CI'da yeşil ve tekrarlanabilir, baz çizgisi yayımlandı, kapısız yazma aracı 0 |
| 2 | 18–22 Eki | Soruşturma ve yanıt | Verdict run; üç şeritli yönlendirici ve yerel model şeridi; executor arayüzü, politika, süre dolumu, geri alma; Defender ve Entra ID executor'ları (M365 geliştirici kiracısında); pilot müşterinin güvenlik duvarı için executor; eylem zaman çizelgesi ve Geri al düğmesi | **Kapı B**: verdict recall ≥ triage recall; her geri alınabilir eylem türü sandbox'ta uygula-doğrula-geri al testinden geçti; politika korunan varlığa eylemi reddediyor |
| 3 | 23–26 Eki | Otonomi ve düzenlenen sektör paketi | Otonomi denetleyicisi (GA varsayılanı "onayla"); dersler; dört göz onayı; internetsiz kurulum paketi; FIPS modu; saklama ve silme politikaları; denetim akışının SIEM'e aktarımı; vaka başına kanıt paketi; düzenleyici bildirim saatleri; çıkış trafiği sıfır testi; daemon sıcak yedeği; Helm yedek CronJob'u | **Kapı C (rc.1)**: internetsiz kurulum temiz VM'de < 30 dk; çıkış trafiği sıfır testi yeşil; kritik eylemde dört göz zorunlu |
| 4 | 27–30 Eki | Sertleştirme ve GA | Yük ve kaos testleri; ajan kırmızı takımı (injection, yetki, SSRF); dış pentestin ön bulguları; 0.7.1'den yükseltme yolu; belgeler; SBOM ve imzalı imajlar; RC'de yalnızca hata düzeltme | **GA, 30 Ekim**: SLO'lar tutuyor, kritik veya yüksek açık yok, düzenlenen sektör kontrol listesi tam |
| Sonrası | Kasım | MSSP ve kanıtlı otonomi | Çok kiracılık (2.1), otomatik kapatmanın kategori bazında açılması, dış pentest raporu | Karne kategori başına FN üst sınırı ≤ %1 gösterdiğinde |

### Alt ajanla hızlandırılamayanlar

Ajan sayısı kod yazma süresini kısaltır ama takvime bağlı işleri kısaltmaz. Bunlar GA'yı engellemeyecek şekilde tasarlandı:

| İş | Neden takvime bağlı | GA'da nasıl ele alınır |
| --- | --- | --- |
| Gerçek FN kanıtı | Tek taraflı %95 güvenle ≤ %1 için kategori başına kusursuz en az 299 incelenmiş örnek gerekir; analist emeği ve canlı veri ister | GA'da otomatik kapatma kapalı ("onayla" katmanı); Kasım'da karne kanıtladıkça kategori bazında açılır |
| Pilot müşteri | Banka ve kamuda değişiklik onayı, erişim ve test ortamı hazırlığı haftalar sürebilir | 13 Ekim'e kadar pilot belli değilse GA kapısı müşteri ortamını taklit eden referans ortamda (internetsiz VM, test kiracısı, örnek güvenlik duvarı) gösterilir; SLO'lar sentetik yükle ayarlanır, pilot verisiyle Kasım'da yeniden ayarlanır |
| Test kiracısı | M365 geliştirici programı yalnız belirli abonelere açık; Defender izolasyonu için kiracıya bağlı bir makine gerekir | Uygun değilsek E5 ve Defender for Endpoint deneme kiracısı; başvuru 12 Ekim'de |
| Dış pentest | Firmanın takvimi; tipik olarak bir hafta, oysa 26–30 Ekim arasında 1,5 gün tatil var | Rezervasyon 12 Ekim'de; test 26 Ekim'de staging'deki aday sürümde başlar; GA iç kırmızı takım raporu ve dış testin ön bulgularıyla çıkar, tam rapor Kasım'da |
| Üretici kiracıları | CrowdStrike, SentinelOne gibi ürünler partner veya müşteri kiracısı ister | Bu executor'lar Kasım'da; GA'da Defender, Entra ID ve pilotun güvenlik duvarı |
| Sertifikalar (SOC 2, ISO 27001) | Aylarca gözlem süresi | GA'da yok; güvenlik teknik belgesi, SBOM, tehdit modeli ve mevzuat eşlemesi verilir |
| İnsan incelemesi | 2–3 mühendis; 28 Ekim 13.00'ten itibaren ve 29 Ekim resmî tatil; Dalga 3'te yalnızca iki iş günü var | Risk katmanlı inceleme; 17–18 ve 24–25 Ekim hafta sonu inceleme nöbeti; nöbet yoksa ilgili kapı bir iş günü kayar |

### Gecikirse önce düşenler

Kesme sırası bugünden karara bağlanır, dalga içinde tartışılmaz:

1. Dersler (Dalga 3) → Kasım.
2. Küçük modelin maliyet amaçlı kullanımı → GA'da yerel model yalnızca internetsiz kurulum ve sağlayıcı kesintisi için çalışır; maliyet için yönlendirme Kasım'da.
3. Güvenlik duvarı executor'ı → pilot müşterinin ürünü belli değilse Kasım.
4. Daemon sıcak yedeği → soğuk yedek ve belgelenmiş kurtarma ile GA.
5. FIPS modu → pilot müşteri istemiyorsa Kasım.

Asla düşmeyenler: eval düzeneği, köken kuralı, QA örnekleme, eylem politikası, geri alma ve doğrulama, dört göz onayı, internetsiz kurulum, denetim zinciri ve çıkış trafiği sıfır testi. Bunlar ürünün tezi ve düzenlenen sektörün giriş bileti.

## Dalga 0 ve 1: zemin, ölçüm ve dürüst çekirdek

Her iş paketi (İP) bir alt ajana verilir ve ayrı bir doğrulayıcı ajan tarafından denetlenir. **Risk** sütunu inceleme yolunu belirler: *Yüksek* paketler doğrulayıcıya ek olarak güvenlik doğrulayıcısından ve bir insandan onay alır; *Normal* paketler doğrulayıcı PASS ve yeşil CI ile birleşir.

### Dalga 0 · 12–13 Ekim · zemin ve ajan fabrikası

| İP | Ne | Nerede | Kabul kriteri | Risk |
| --- | --- | --- | --- | --- |
| W0.1 | Son upstream senkronu (en az 16 commit), `fork-point-2026-10` etiketi, `FORK.md` sert fork moduna | Tüm depo | Tüm test paketleri yeşil; upstream'in 40\_skill\_reads.sql dosyası bizim 45 lehine düşürüldü; #2153 güvenlik düzeltmesi geldi; FORK.md cherry-pick kuralını anlatıyor (veritabanı numarası çakıştığı için insan onaylı) | Normal |
| W0.2 | Marka | Konsol, e-posta, TOTP, OpenAPI, masaüstü | **Tamamlandı**, `main` @ `b71a98b1`; üç doğrulama turu | – |
| W0.3 | Tam CI: `ci-cd.yml` koşulu bizim depoya; `main`'de zorunlu kontroller; birleştirme kuyruğu | `.github/workflows/` | Her PR'da backend, web, agent, Helm, güvenlik işleri koşuyor | Normal |
| W0.4 | Ajan fabrikası: İP şablonu, worktree betikleri, standart kapı betiği, doğrulayıcı kontrol listeleri | `docs/wp/`, `scripts/wp/` | Bir deneme İP'si fabrikadan uçtan uca geçiyor | Normal |
| W0.5 | Sözleşmeleri dondur: verdict şeması (Python, TS, JSON Schema), `Executor` protokolü ve `TypedAction`, 46'dan başlayan yeni tabloların (webhook tabloları dahil) iskeleti (Helm aynası ve `dbInit` dahil) | `core/contracts/`, `services/agent/contracts/`, `core/response/executors/base.py`, `infra/database/init/` | Sözleşme testleri yeşil; şema anlık görüntüsü yenilendi | **Yüksek** |
| W0.6 | Staging: tek VM'de Helm, her gece `main`'den kurulum, demo veri ve replay akışı, Ollama'da küçük yerel model | `infra/staging/` | Gece kurulumu yeşil; konsol staging'de demo veriyle açılıyor | Normal |
| W0.7 | Eval korpusu v1: ≥ 2.000 etiketli alarm, kategori başına ≥ 150 pozitif, kategori bazında bölünmüş, ayrı test kümesi, veri sayfası (kaynak ve lisans) | `eval/corpus/v1/` | Lisansı temiz; etiketleri ikinci bir ajan ve bir insan örneklemle kontrol etti | Normal |
| W0.8 | Dış bağımlılıklar (insan): pentest rezervasyonu, Defender ve Entra ID test kiracısı (M365 geliştirici programına uygun değilsek E5 ve Defender for Endpoint deneme kiracısı) ve kiracıya bağlı bir test makinesi, pilot müşteriyle gereksinim atölyesi, pilotun güvenlik duvarı ürünü | – | Dalga 2 başlamadan kiracı erişimi var; pilot müşteri 13 Ekim'e kadar belli değilse referans ortam yedeği devreye girer | – |

### Dalga 1 · 14–17 Ekim · ölçüm ve dürüst çekirdek

On paket paralel yürür. Dosya kümeleri büyük ölçüde ayrıktır; ortak dosyalarda sıra vardır: processor.py'de önce W1.2 sonra W1.3, probes.py'de önce W1.2 sonra W1.5. SQL dosyalarının iskeleti, Helm aynası, dbInit listesi ve şema anlık görüntüsü W0.5'te tek seferde hazırlanır; paketler yalnız kendi SQL dosyalarının içini doldurur.

| İP | Ne | Nerede | Kabul kriteri | Risk |
| --- | --- | --- | --- | --- |
| W1.1 | Eval düzeneği: yükleyici, çalıştırıcı, puanlayıcı (kategori bazında precision, recall, F1, inconclusive, tek taraflı Clopper–Pearson güven sınırı), JSON ve Markdown rapor; PR CI'da kayıtlı model yanıtlarıyla (< 5 dk), gece canlı modelle bütçe tavanlı | Yeni `eval/`; `eval_runs`, `eval_results` | Aynı girdiyle iki koşu aynı sayıları veriyor; bugünkü triage'ın baz çizgisi yayımlandı | Normal |
| W1.2 | Yapılandırılmış triage: JSON şema router'ın tek şema çıkışıyla; ayrıştırma hatası `inconclusive` olur; prob sözlüğü güncellenir | `services/daemon/processor.py`, `services/daemon/probes.py` | Eval'de recall baz çizgisinin altına düşmüyor; 1.000 replay'de 0 ayrıştırma hatası | Normal |
| W1.3 | Alan kökeni: yedi Federation adaptörü ve webhook için sensör, saldırgan, üçüncü taraf haritası; `benign` en az bir sensör alanı alıntılamazsa kod `inconclusive` yapar (istem değil, kod) | Yeni `core/federation/provenance.py`; `processor.py` | Adaptör başına birim testleri; injection setinde saldırı başarısı ≤ %5 | **Yüksek** |
| W1.4 | Injection test seti: user agent, URL, komut satırı, e-posta konusu ve gövdesi, DNS sorgusu, dosya adı üzerinden ≥ 200 saldırı alarmı; saldırı başarısı = kararın zararsıza dönmesi veya saldırganın istediği eylemin önerilmesi | `eval/suites/injection/` | Baz çizgisi ölçüldü; W1.3 sonrası ≤ %5 | Normal |
| W1.5 | Kanarya: bilinen kötücül replay'ler normal alım yolundan, analistten gizli ama yöneticinin denetim kaydında görünür; müşteri ortamında varsayılan kapalı, açık onayla açılır; dışa aktarımlardan ve müşteri metriklerinden dışlanır | `services/daemon/probes.py`, `canary_injections` | Yakalanma oranı karnede; kanaryalar hiçbir dışa aktarımda yok | **Yüksek** |
| W1.6 | QA örnekleme ve Karne: otomatik kapanan ve zararsız kararlardan kategori başına basit rastgele örnek İnceleme kuyruğuna (FN üst sınırı yalnız bundan hesaplanır, risk ağırlıklı ek örnekler ayrı izlenir); analist kararı; kategori bazında tek taraflı %95 Clopper–Pearson üst sınırı; yeni Karne ekranı | Yeni `core/quality/`, `qa_samples`; `clients/web/src/screens/scorecard/` | Staging'de gerçek sayılar; ekran görüntüsü doğrulayıcıda | Normal |
| W1.7 | Araç etki sınıfları her yerde zorunlu: yerleşik araçlar, MCP araçları, compose kataloğu ve sohbet; yıkıcı araç yalnızca onay hattından | `core/agents/tool_registry.py`, `services/agent/workflows/compose/workflow.ts`, `core/llm/chat_layers.py` | Tüm araçları sayan test: sınıfsız veya kapısız yazma aracı 0 | **Yüksek** |
| W1.8 | Giden webhook (HMAC imzalı, yeniden deneme, başarısız teslim tablosu), bildirim dağıtıcısı (Slack, e-posta, webhook), SLA izleyicisinin yaşam döngüsüne bağlanması | `core/integrations/webhooks_router.py`, `core/cases/` | Yerel alıcıyla uçtan uca test | Normal |
| W1.9 | OIDC SSO: Entra ID, Okta, Keycloak; ilk girişte kullanıcı oluşturma; grup → rol; yerel acil erişim yöneticisi | Yeni `core/auth/oidc_router.py` | Staging'de Keycloak ile giriş; rol eşlemesi testleri | **Yüksek** |
| W1.10 | Denetim zinciri genişlemesi: onay ve vaka denetim kayıtlarına aynı hash zinciri (vaka denetim tablosu ORM'e ait olduğundan tetikleyici init SQL'de değil şema kurulumunda eklenir); zincir başlarının imzalı kontrol noktası (Ed25519, isteğe bağlı RFC 3161 zaman damgası) | `infra/database/init/`, `services/agent/ledger/verify.ts` | Kurcalama testi değişikliği yakalıyor; `verify` yeni zincirleri yürüyor | **Yüksek** |

**Kapı A (iş 17 Ekim Cumartesi biter; imza hafta sonu nöbetinde ya da 19 Ekim Pazartesi sabahı):** eval CI'da yeşil ve tekrarlanabilir; baz çizgisi ve injection oranı karnede; kapısız yazma aracı 0; Yüksek paketlerin hepsi insan onaylı. Kapıyı bir insan, karnedeki sayılara bakarak imzalar. Dalga 2 paketleri 18 Ekim'de donmuş sözleşmelere karşı başlar; birleştirmeleri kapıyı bekler.

## Dalga 2: her belirsiz alarmda soruşturma ve geri alınabilir yanıt

**18–22 Ekim.** Bu dalga ürünün iki tezini koda döker: belirsiz alarm hunt kalitesinde soruşturulur ve hiçbir eylem politika, doğrulama ve geri alma olmadan çalışmaz. Sözleşmeler Dalga 0'da donduğu için executor paketleri, politika paketiyle aynı anda yazılabilir.

| İP | Ne | Nerede | Kabul kriteri | Risk |
| --- | --- | --- | --- | --- |
| W2.1 | Verdict run türü: `HUNT_LOOP`'u kullanan yeni mimari; sıfır hipotezi taban oranla tahtada; en fazla 2 işçi; CONCLUDE'dan önce VALIDATE zorunlu; çıktı verdict şeması; alarm başına iterasyon, süre ve maliyet tavanı (ilk değerler eval ile ayarlanır); Python tarafında `HUNT_LIKE_RUN_KINDS`, TS tarafında `RUN_KINDS` ve `WatchRun.tsx` güncellenir; replay fikstürleri; `adjudicate` ile istem parçaları paylaşılır, verdict onun karar veren kardeşidir | Yeni `services/agent/arch/verdict.yaml`; `services/agent/arch/registry.ts`; `services/daemon/orchestrator.py`, services/agent/contracts/events.ts, core/workflows/workflows\_service.py, clients/web/src/screens/workflows/WatchRun.tsx | Eval'de verdict recall ≥ tek çağrı triage recall; inconclusive ≤ %15; fold-equivalence testleri yeşil | Normal |
| W2.2 | Alarm yönlendirici: kural şeridi, küçük model şeridi, verdict run; eşikler `INTENT.md`'den okunur ve artık uygulanır; bütçe baskısında alarm düşürülmez, sıraya alınır; Triage ekranında şerit sütunu | Yeni `core/lanes/alert_lanes.py`, `alert_routes`; `processor.py` | Eval'de hepsi frontier modele göre alarm başına maliyet −%60, recall kaybı ≤ 1 puan (tutmazsa gerçek sayı karneye yazılır) | Normal |
| W2.3 | Yerel model şeridi: Bifrost üzerinden Ollama; şemalı çıktı; aday modeller eval'de yarışır, varsayılan model eval'le seçilir | `core/llm/`, `eval/suites/` | Bu şerite yönlenen dilimde recall hedefte; internetsiz çalışıyor | Normal |
| W2.4 | Executor arayüzü ve eylem politikası: kayıt defteri; `execute_approved_actions` içindeki if/elif'in yerine geçer; tipli eylem şeması; korunan varlık listesi (etiket ve CMDB alımı); saatlik etki sınırı; dört göz onayının arka uçta zorunlu kılınması (aynı kişi iki kez onaylayamaz); süresi dolan eylemi geri alan daemon döngüsü; eylem yaşam döngüsü deftere; Cloudflare executor'ı referans olarak taşınır | Yeni `core/response/executors/`, `core/response/policy.py`; `core/response/autonomous_response_service.py`; `approval_actions` genişletmesi (mevcut reversibility ve idempotency\_key sütunları kullanılır) | Özellik tabanlı test: model önerisi politikayı hiçbir yoldan atlatamıyor; korunan varlığa eylem reddediliyor; süre dolunca eylem geri alınıyor ve doğrulanıyor | **Yüksek** |
| W2.5 | Microsoft Defender for Endpoint executor'ı: makineyi izole et ve izolasyonu kaldır; makine eylemi durumundan doğrulama | `core/integrations/microsoft_defender/executor.py` | Test kiracısında uçtan uca uygula-doğrula-geri al; mevcut mde\_isolate kodu kullanılır | **Yüksek** |
| W2.6 | Entra ID executor'ı: kullanıcıyı devre dışı bırak ve geri aç (geri alınabilir); oturumları iptal et (geri alınamaz, en fazla Onayla katmanında kalır); hesap durumundan doğrulama | `core/integrations/azure_ad/executor.py` | Aynı kiracıda uçtan uca; geri alınamaz eylem türü otonom katmana çıkamıyor; mevcut aad\_disable\_user kodu kullanılır | **Yüksek** |
| W2.7 | Pilot müşterinin güvenlik duvarı için executor (kesme listesinde 3.; örneğin FortiGate adres grubu veya Palo Alto dinamik adres grubu): süreli IP engeli, doğrulama, geri alma | `core/response/executors/` | Sözleşme testleri; pilotun test ortamında uçtan uca; Palo Alto için mevcut pan\_block\_ip kodu kullanılır | **Yüksek** |
| W2.8 | Eylem zaman çizelgesi: önerildi → onaylandı (kim, ikinci onaylayan) → uygulandı → doğrulandı → süresi doldu veya geri alındı; gerekçeli Geri al düğmesi; defter bağlantısı | `clients/web/src/screens/cases/CasePage.tsx` | Arayüz testleri ve doğrulayıcı ekran görüntüsü | Normal |
| W2.9 | Phishing hattı (isteğe bağlı, kesme listesinde değil ama kapasite kalırsa): M365 bildirilen posta kutusu, URL ve ek analizi, verdict run, onaylı posta temizleme ve geri yükleme | `core/integrations/`, `core/response/executors/m365_mail.py` | Geliştirici kiracısında uçtan uca | **Yüksek** |

**Kapı B (22 Ekim):** verdict recall ≥ triage recall; her geri alınabilir eylem türü sandbox'ta uygula-doğrula-geri al, geri alınamaz türler uygula-doğrula testinden geçti; politika korunan varlığa eylemi ve tek kişiyle dört göz sınıfını reddediyor; deftere yazılmayan eylem yok.

## Dalga 3 ve 4: otonomi, düzenlenen sektör paketi ve GA

### Dalga 3 · 23–26 Ekim · otonomi ve düzenlenen sektör paketi

Düzenlenen sektör alıcısı üç şey sorar: veri dışarı çıkıyor mu, kim neyi onayladı ve bunu denetçiye nasıl kanıtlarım. Bu dalga bu üç sorunun cevabını ürün özelliğine çevirir. W3.10 ve W3.11 kesme listesindedir; yalnızca on uygulayıcı sınırında yer açılırsa başlar.

| İP | Ne | Nerede | Kabul kriteri | Risk |
| --- | --- | --- | --- | --- |
| W3.1 | Otonomi denetleyicisi: kategori × eylem sınıfı başına katman (Gözle, Öner, Onayla, Otonom-geri alınabilir); GA varsayılanı Onayla; devre kesici: örneklenmiş FN üst sınırı eşiği aşarsa, kanarya kaçarsa, executor doğrulaması üst üste başarısız olursa veya harcama anormalleşirse katmanı kendiliğinden düşürür ve bildirir; yükseltmeyi yalnızca insan, kanıt bağlantısıyla yapar; `INTENT.md` beyanları uygulanır; Otonomi ekranı | Yeni `core/autonomy/`, `autonomy_tiers`; `services/api/routers/config.py`; `clients/web/src/screens/` | Kaos testinde devre kesici katmanı düşürüyor; ajan veya API anahtarı katman yükseltemiyor | **Yüksek** |
| W3.2 | Dört göz onayının ikinci yarısı (aynı kişinin iki kez onaylayamaması W2.4'te): farklı rol koşulu, görevler ayrılığı raporu ve arayüz | `core/response/approval_service.py`; Case sayfası | Rol koşulu testleri, görevler ayrılığı raporu, ekran görüntüsü | **Yüksek** |
| W3.3 | İnternetsiz kurulum paketi: imajlar (OCI düzeni), yerel kayıt defteri için Helm değerleri, yerel model ağırlıkları, kural korpuslarının anlık görüntüsü, çevrimdışı belgeler; sağlama ve imza doğrulamalı kurulum betiği; uzak MCP'ler ve telemetri varsayılan kapalı | Yeni `infra/airgap/` | Temiz, internetsiz VM'de kurulum < 30 dk, betikli ve CI'da | **Yüksek** |
| W3.4 | Çıkış trafiği sıfır testi: yığın ağı yalıtılmış bir ortamda uçtan uca akışlarla çalışır; izin listesi dışında tek bir dış bağlantı denemesi testi kırar | `.github/workflows/`, `tests/airgap/` | Yeşil; deneme olursa hangi bileşenden geldiği raporda | Normal |
| W3.5 | Saklama ve imha: veri sınıfı başına saklama süresi, KVKK periyodik imhası için zamanlanmış silme, vakada yasal saklama bayrağı, her silmenin zincirli denetim kaydı | `retention_policies`; yeni `core/compliance/retention.py` | Silme ve yasal saklama testleri; imha raporu üretiliyor | **Yüksek** |
| W3.6 | Denetim akışının dışa aktarımı: denetim ve defter olayları syslog (RFC 5424, TLS) ve HTTPS (JSON, CEF) ile müşterinin SIEM'ine; geri basınç ve yeniden deneme | Yeni `core/compliance/audit_export.py` | Yerel syslog alıcısıyla uçtan uca; olay kaybı yok | Normal |
| W3.7 | Vaka başına kanıt paketi: vaka, bulgular, zincir kanıtlı defter olayları, onaylar, eylemlerin öncesi ve sonrası, doğrulama sonuçları, imza; `autosecops verify-bundle` ile çevrimdışı doğrulanır | `core/compliance/evidence.py`; CLI | Kurcalanan paket doğrulamada reddediliyor | Normal |
| W3.8 | Düzenleyici bildirim saatleri: vakada DORA (ilk bildirim: büyük olay olarak sınıflandırmadan sonra 4 saat ve farkına varıldıktan sonra en geç 24 saat; ara rapor: ilk bildirimden sonra 72 saat; nihai rapor: son ara rapordan sonra 1 ay) ve NIS2 (farkına varıldıktan sonra 24 saat erken uyarı ve 72 saat bildirim; bildirimden sonra 1 ay nihai rapor) sayaçları ve rapor taslaklarının kanıt paketinden üretilmesi; süreler yapılandırılabilir | `core/compliance/`; Case sayfası | Her sayaç kendi başlangıç anına zincirli bağlı; taslak kanıt paketine bağlı | Normal |
| W3.9 | Daemon sıcak yedeği (kesme listesinde 4.; Postgres kilidiyle lider seçimi, iki kopya), Helm'de yedek CronJob'u, RPO ve RTO belgesi | `services/daemon/`, `infra/helm/` | Lider öldürüldüğünde devralma; geri yükleme testi | Normal |
| W3.10 | FIPS modu (kesme listesinde 5.): OpenSSL 3 FIPS sağlayıcısı, FIPS dışı algoritmaların (örneğin parola hash'inde bcrypt) yapılandırılabilir FIPS uyumlu karşılıkları | İmajlar, `core/auth/`, `core/secrets_manager.py` | FIPS modunda tüm testler yeşil | **Yüksek** |
| W3.11 | Dersler (kesme listesinde 1.): analist düzeltmesinden kapsamlı ve süreli ders; geçmiş alarmlarda replay ile terfi; tek tıkla geri alma; verdict bağlamına ve kural şeridine beslenir | Yeni `core/lessons/`, `lessons`, `suppression_rules` | Replay'den geçmeyen ders terfi etmiyor; FP düşüşü recall kaybı olmadan | Normal |

**Kapı C (iş 26 Ekim akşamı biter; imza ve rc.1 27 Ekim sabahı):** internetsiz kurulum temiz VM'de < 30 dk; çıkış trafiği sıfır testi yeşil; kritik eylemde dört göz zorunlu; devre kesici kaos testinde çalışıyor; Yüksek paketlerin hepsi insan onaylı.

### Dalga 4 · 27–30 Ekim · sertleştirme ve GA

rc.1'den sonra yalnızca hata düzeltilir. Her düzeltme de doğrulayıcıdan geçer.

| İP | Ne | Kabul kriteri |
| --- | --- | --- |
| W4.1 | Yük testi: pilotun alarm hacmiyle sürekli ve ani yük; şerit başına alımdan karara p95 gecikme | SLO tablosundaki değerler tutuyor (üretime hazırlık bölümü) |
| W4.2 | Kaos testleri: model sağlayıcısı çökmesi (kural ve yerel şeride iner, kuyruk büyür, alarm kaybolmaz), Postgres yeniden başlatma ve yedekten geri yükleme, executor API hatası, daemon öldürme | Veri kaybı yok; defter zinciri sağlam; durum tutarlı |
| W4.3 | Ajan kırmızı takımı: alarm alanlarından injection, rol × rota yetki matrisi, entegrasyon ve özel entegrasyon oluşturucu üzerinden SSRF, gizli bilgi sızıntısı, defter kurcalama; her bulgu yeni bir İP olur | Kritik ve yüksek bulgu açık değil |
| W4.4 | Dış pentest (26 Ekim'de aday sürümde başlar, tam rapor Kasım'da) | Ön bulgularda kritik ve yüksek açık yok veya kabul edilmiş risk olarak imzalı |
| W4.5 | 0.7.1'den 2.0'a yükseltme yolu: ileri yönlü göçler, 0.7.1 veritabanı anlık görüntüsüyle CI testi | Yükseltme sonrası tüm testler ve karne yeşil |
| W4.6 | Belgeler: internetsiz kurulum, yönetici kılavuzu, güvenlik teknik belgesi, tehdit modeli, mevzuat eşlemesi (BDDK bilgi sistemleri yönetmeliği, KVKK, DORA, NIS2), runbook'lar | Belge-kod uzlaşması testi: belgede geçen her ayar ve komut kodda var |
| W4.7 | Sürüm: SBOM, imzalı imajlar, sürüm notları, `v2.0.0` etiketi | GA karar toplantısı 30 Ekim |

**GA kapısı (30 Ekim):** SLO'lar tutuyor; kritik veya yüksek güvenlik bulgusu açık değil; düzenlenen sektör kontrol listesinin tamamı işaretli; karne yayımlandı; pilot müşteri ortamında (pilot gecikirse onu taklit eden referans ortamda) internetsiz kurulum ve bir uçtan uca onaylı eylem gösterildi.

## Üretime hazırlık ve düzenlenen sektör kontrol listesi

**GA, bu listenin tamamı işaretlenmeden ilan edilmez.** SLO değerleri ilk hedeflerdir; pilot müşterinin alarm hacmiyle Dalga 0'da netleşir.

### SLO'lar

| SLO | 2.0 hedefi | Nasıl ölçülür |
| --- | --- | --- |
| Alımdan karara gecikme, kural şeridi | p95 < 5 sn | `alert_routes` zaman damgaları |
| Alımdan karara gecikme, küçük model şeridi | p95 < 60 sn | Aynı |
| Alımdan karara gecikme, verdict run | p95 < 10 dk | Defter |
| Alarm kaybı | 0 (en az bir kez teslim, tekilleştirme) | Federation imleci ve başarısız teslim tablosu |
| API erişilebilirliği | Aylık %99,5 (GA'dan sonra ölçülmeye başlar) | OTEL |
| Onaydan uygulamaya süre | p95 < 60 sn | Defter |
| Eylem doğrulama başarısı | ≥ %99; başarısız doğrulama kendisi bir alarm üretir | Defter |
| RPO / RTO | 15 dk / 4 saat | Otomatik geri yükleme testi |

### Güvenlik

- [ ] OIDC SSO ve MFA; yerel acil erişim hesabı kasada, kullanımı alarm üretir
- [ ] Rol × rota yetki matrisi testi CI'da
- [ ] Gizli bilgiler KMS veya Vault üzerinden (ExternalSecrets) ya da şifreli dosyada; anahtar döndürme belgeli
- [ ] İmzalı imajlar, SBOM, bağımlılık taraması CI'da
- [ ] Tehdit modeli, iç kırmızı takım raporu, dış pentest raporu ya da tarihli planı
- [ ] Injection saldırı başarısı ≤ %5, karnede yayımlanıyor
- [ ] Ajanlar kimlik bilgisi tutmuyor; executor kimlik bilgileri yalnızca executor kodunda ve en dar yetkiyle

### Veri ve gizlilik

- [ ] Çıkış trafiği sıfır testi yeşil; tüm uzak bağlantılar varsayılan kapalı
- [ ] Tüm veri müşteri altyapısında; model çağrıları yerel modele ya da müşterinin seçtiği bölgedeki sağlayıcıya
- [ ] Saklama ve imha politikaları, imha raporu
- [ ] Denetim kayıtları zincirli, imzalı kontrol noktalı, SIEM'e akıyor
- [ ] Yedekler şifreli, geri yükleme testi otomatik

### İşletim

- [ ] Helm, Compose ve internetsiz paket kurulumları belgelendi ve CI'da test ediliyor
- [ ] OTEL panoları: alım gecikmesi, şerit dağılımı, maliyet, kuyruk derinliği, executor hataları, devre kesici olayları
- [ ] Runbook'lar: model sağlayıcı kesintisi, kuyruk birikmesi, executor hata fırtınası, defter doğrulama hatası, devre kesicinin tetiklenmesi, geri yükleme
- [ ] 0.7.1'den yükseltme yolu ve geri dönüş planı
- [ ] Destek paketi yeni klasör adlarıyla çalışıyor (12 Ekim'de düzeltildi)

### LLM'e özgü

- [ ] Model değişikliği eval kapısından geçmeden üretime çıkmaz (model yükseltme kapısı)
- [ ] İstem ve mimari dosyaları sürümlü; her karar hangi model ve istem sürümüyle verildiğini deftere yazar
- [ ] Harcama tavanları ve saldırı dalgasında alarm kaybetmeden sıraya alma
- [ ] Sağlayıcı kesintisinde kural ve yerel şeride inme

### Mevzuat eşlemesi

Bu tablo hukuki görüş değildir; Dalga 0'daki atölyede pilot müşterinin uyum ekibiyle doğrulanır.

| Düzenleme | İlgili beklenti | AutoSecOps karşılığı |
| --- | --- | --- |
| BDDK bilgi sistemleri ve elektronik bankacılık yönetmeliği | Birincil ve ikincil sistemlerin yurt içinde tutulması, iz kayıtları, görevler ayrılığı, erişim yönetimi | Kendi barındırma ve internetsiz kurulum; zincirli denetim kaydı; dört göz onayı; SSO ve rol matrisi |
| KVKK | Kişisel verinin işlenmesi, saklanması ve imhası; yurt dışı aktarım kısıtları | Yerel model şeridi, çıkış trafiği sıfır, saklama ve imha politikaları |
| DORA (AB finans kuruluşları) | BİT olaylarının sınıflandırılması ve süreli bildirimi, kayıt tutma, üçüncü taraf riski | Bildirim saatleri, vaka kanıt paketi, defter |
| NIS2 | 24 saat erken uyarı, 72 saat bildirim, 1 ay nihai rapor | Bildirim saatleri ve rapor taslakları |
| AB Yapay Zekâ Yasası | Yüksek riskli sistemlerde otomatik kayıt tutma; bir SOC aracı büyük olasılıkla yüksek riskli sayılmaz, iyi uygulama olarak karşılanır | Hash zincirli defter, replay, model ve istem sürümü kaydı |

## Alt ajan fabrikası ve sürekli doğrulama

**Hiçbir iş, uygulayıcının kendi beyanıyla `main`'e girmez.** Alt ajanlar kodu hızlı yazar; bu hız ancak her paketi uygulayıcıdan bağımsız bir taraf doğrularsa güvenlidir. Darboğaz artık kod yazmak değil doğrulamadır, bu yüzden doğrulama da paralel ve otomatik kurulur.

&#91;embedded content: İş paketi doğrulama akışı · altı katmandan beşi\]

### Roller

| Rol | Kim | Görür | Görmez | Çıktı |
| --- | --- | --- | --- | --- |
| Orkestratör | Bu oturumdaki Claude | Plan, kod, tüm raporlar | – | İP tanımları, birleştirme treni, günlük durum |
| Uygulayıcı | İP başına bir alt ajan, kendi worktree'sinde | İP tanımı, beyan edilen dosyalar, sözleşmeler | Diğer paketlerin çalışması | Commit ve rapor |
| Doğrulayıcı | Ayrı alt ajan, taze bağlam | İP tanımı ve diff | Uygulayıcının raporu ve gerekçesi | PASS veya FAIL, bulgular, kanıt (komut çıktısı, ekran görüntüsü) |
| Güvenlik doğrulayıcısı | Ayrı alt ajan, yalnız Yüksek paketlerde | Diff ve tehdit modeli | Uygulayıcının raporu | Denenen saldırılar ve sonuçları |
| İnsan | 2–3 mühendis | Doğrulayıcı raporları, karne | – | Yüksek paket onayı, kapı imzası |
| Sapma denetçisi | Ayrı alt ajan; haftalık ve her kapıda | Bu plan, kod, kamuya açık belgeler | – | Plan, kod ve belge arasındaki farklar |

Doğrulayıcının uygulayıcının raporunu görmemesi bilinçlidir: rapor "testler geçti" derse doğrulayıcı ona yaslanır. Doğrulayıcı yalnız tanımı ve diff'i görür, iddiayı kendisi yeniden üretir.

### İş paketi tanımı şablonu

```
İP:              W1.3 Alan kökeni
Amaç:            Saldırganın yazabildiği alan tek başına "zararsız" kararı veremesin
Dokunabilir:     core/federation/provenance.py (yeni), services/daemon/processor.py
Dokunamaz:       diğer her şey; sözleşme değişikliği gerekirse orkestratöre döner
Sözleşmeler:     core/contracts/verdict.schema.json v1
Kabul kriterleri: adaptör başına birim testleri; injection setinde saldırı başarısı ≤ %5;
                  eval recall baz çizgisinden en fazla 1 puan düşük
Kanıt:           komut çıktıları, eval raporu
Risk:            Yüksek (güvenlik doğrulayıcısı + insan onayı)
```

### Altı doğrulama katmanı

1. **İP doğrulaması (her pakette):** doğrulayıcı PASS verir. FAIL'de aynı uygulayıcı düzeltir; en fazla iki tur, üçüncü FAIL insana gider.
2. **Standart kapılar (her commit'te):** testler, tip kontrolü, lint (yeni hata yok kuralı), import-linter, ratchet testleri, kayıtlı model yanıtlarıyla eval duman testi.
3. **Birleştirme treni (her birleştirmede):** `integration` dalında tam CI ve eval regresyon kapısı (kayıtlı yanıtlarla deterministik koşuda recall düşmez ve injection başarısı artmaz; canlı modelle gece koşusu kapı değil rapordur); kırılırsa son birleştirme geri alınır.
4. **Gece doğrulaması (her gece):** staging'e kurulum, uçtan uca senaryolar, kanarya, kaos duman testi, canlı modelle eval; sabah raporu (karne ve kırmızılar) insanlara gider.
5. **Kapı doğrulaması (her dalga sonunda):** sapma denetçisi plan, kod ve belgeyi karşılaştırır; insan kapıyı karnedeki sayılarla imzalar.
6. **Ürün içi doğrulama (GA'dan sonra da):** karne, kanarya ve QA örnekleme müşterinin ortamında sürekli çalışır. Geliştirme sürecindeki doğrulama ile ürünün kendi doğrulaması aynı fikirdir.

### Paralellik kuralları

- Bir dalgada aynı anda en fazla on uygulayıcı; sınırı CI kapasitesi ve insan incelemesi belirler.
- Dosya kümeleri ayrıktır; çakışan paketler sıraya girer.
- Sözleşmeyi yalnız orkestratör değiştirir; değişince bağımlı tüm paketler yeniden doğrulanır.
- Birleştirme treni seri ilerler; her birleştirmeden sonra tam CI koşar.
- Bugün `main`'de 7 eski lint hatası var; Dalga 0'da temizlenir, sonra "yeni lint hatası yok" kuralı zorunlu olur.

### Bu model bugün çalıştı

Marka değişikliği bu modelle yapıldı. Uygulayıcı 75 dosyayı değiştirdi ve işin tamam olduğunu bildirdi. Doğrulayıcı ilk turda konsol dışında kullanıcının gördüğü 8 yer buldu: şifre sıfırlama e-postası, doğrulayıcı uygulamadaki ad, hunt istemleri, rapor şablonu, OpenAPI sayfası, masaüstü uygulaması ve diğerleri. İkinci turda düzeltmenin masaüstü destek paketini bozduğunu ve bir dilbilgisi hatasını yakaladı. Üçüncü turda PASS verdi. Kalite, uygulayıcının beyanından değil doğrulayıcıdan geldi. Bu değişiklik boyutunda bir paket, uygulama ve doğrulama için yaklaşık yarımşar saat sürdü.

## Riskler, açık kararlar ve GA sonrası

### Riskler

| Risk | Etki | Önlem |
| --- | --- | --- |
| Paralel ajanların işleri birbirini bozar | Yüksek | Ayrık dosya kümeleri, Dalga 0'da donan sözleşmeler, seri birleştirme treni, her birleştirmeden sonra tam CI |
| İnsan incelemesi darboğaz olur | Yüksek | Risk katmanlı inceleme; Yüksek paketler iş günlerine sıralanır; doğrulayıcı raporları kısa ve kanıtlı |
| Pilot müşterinin ortamı ve kiracı erişimi gecikir | Yüksek | Defender ve Entra ID geliştirici kiracısında doğrulanır; diğer executor'lar sözleşme testleriyle "beta" çıkar |
| Ajanın yazdığı kodda gizli kalite borcu | Orta | Bağımsız doğrulayıcı, sapma denetçisi, "yeni lint hatası yok", eval regresyon kapısı |
| Dış pentest takvime sığmaz | Orta | GA iç kırmızı takım raporuyla; dış rapor Kasım'da müşteriye |
| Eval korpusu gerçeği temsil etmez | Orta | Karne kaynağını yazar; pilot müşterinin etiketli verisiyle Kasım'da genişler; canlı QA örnekleme asıl kanıttır |
| Otonom eylem yanlış çalışır | Yüksek | GA'da "onayla" katmanı, politika, dört göz, süre dolumu, geri alma ve devre kesici |
| Upstream aynı özellikleri ücretsiz yayımlar | Orta | Fark ölçümde, düzenlenen sektör paketinde, eylem genişliğinde ve MSSP'de; hız |
| Sert fork yüzünden güvenlik düzeltmesi kaçar | Orta | Aylık upstream radarı ve upstream güvenlik bildirimlerinin izlenmesi |
| Model sağlayıcısı fiyatı veya davranışı değişir | Orta | Yerel model şeridi, model yükseltme kapısı, sürümlü istemler |

### Senin kararına kalanlar

1. **Logo işareti.** Arayüz artık AutoSecOps yazıyor ama yanındaki devre-kalkan çizimi Vigil'in işareti. Yeni işareti kim tasarlayacak?
2. **Masaüstü uygulama kimliği.** `appId` hâlâ `ai.deeptempo.vigil`; kendi alan adımızla değişmeli. Hangi alan adı?
3. **Pilot müşteri ve ürünleri.** Hangi kurum; hangi EDR, kimlik sağlayıcı ve güvenlik duvarı? En geç 13 Ekim'de belli olmalı: Dalga 2'nin executor kapsamı, yük testi hacmi ve GA kapısındaki gösterim buna bağlı.
4. **Lisans modeli.** Eklediğimiz kod Apache-2.0 mı kalacak, yoksa düzenlenen sektör paketi ve MSSP modülü ticari mi olacak?
5. **CI maliyeti.** GitHub Actions dakikaları mı, kendi runner'ımız mı?
6. **Dış pentest.** Firma ve bütçe; rezervasyon 12 Ekim'de yapılmalı.
7. **Türkçe arayüz.** Kamu ve bankacılık pilotu için GA'da gerekli mi?

### GA sonrası: Kasım

- **2.1 MSSP:** Postgres satır düzeyi güvenliğiyle çok kiracılık, kiracı başına model anahtarı ve bütçe, portföy görünümü, kiracılar arası kuyruk.
- **Kanıtlı otonomi:** kategori başına en az 299 kusursuz incelenmiş örnekle tek taraflı %95 FN üst sınırı ≤ %1 olan kategorilerde otomatik kapatmanın açılması; GKAO ilk kez anlamlı bir sayı olur.
- Kesme listesinden düşenler (dersler, küçük modelin maliyet amaçlı kullanımı, güvenlik duvarı executor'ı, sıcak yedek, FIPS) ve benzer vaka araması.
- Kapalı döngü tespit mühendisliği: bulgudan Sigma, KQL veya SPL kuralı, sentetik olayla doğrulama, müşterinin kural deposuna PR.
- OCSF normalizasyonu, syslog ve CEF alımı; CrowdStrike, SentinelOne ve Okta executor'ları.
- Şirket için SOC 2 hazırlığı; dış pentest raporunun yayımlanması.
