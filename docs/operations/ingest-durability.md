# AutoSecOps — alım dayanıklılığı (daemon webhook'u, kalıcı alım kuyruğu)

Bu belge, daemon webhook'unun (`POST /ingest`, `POST /webhook`) bir bulguyu
**200** ile kabul ettiğinde neyi garanti ettiğini, bunu sağlayan kalıcı alım
kuyruğunu (spool), sınırlarını, metriklerini ve lider seçimiyle (W3.9) birlikte
nasıl çalıştığını anlatır. Kaynak: W0.12 (`docs/wp/w0.12.md`), W4.1 kaos
testinin bulguları.

## 1. Sözleşme

- **200 = kalıcı.** Webhook, isteğin tüm bulguları diske yazılıp `fsync`
  edilmeden 200 dönmez. Daemon bundan sonra öldürülse, Postgres kapansa ya da
  pod yeniden başlasa bile bulgu kaybolmaz; veritabanına yazılana kadar
  yeniden denenir.
- **503 + `Retry-After` = kabul edilmedi.** Spool dolu, yazılamıyor ya da (spool
  kapalıyken) satır zamanında yazılamadı. Gönderen bulguyu tutar ve yeniden
  dener (LogLM bağlayıcısı ve genel göndericiler 503'te imleçlerini ilerletmez).
- **Çift satır yok.** Yeniden oynatma ve yeniden gönderim `finding_id` (ve
  `(data_source, external_id)`) ile tekilleşir: zaten yazılmış bir bulgu ikinci
  satır üretmez ve yeniden oynatmada ikinci kez triage edilmez.

Federation ve Kafka yolları değişmedi: onlar imleç/ofseti yalnızca satır
yazıldıktan sonra ilerletir (`core/ingestion/ack.py`), kaynak yeniden okunur.

## 2. Nasıl çalışır

```
gönderen ──POST──▶ webhook ──append+fsync──▶ spool (disk) ──▶ besleyici ──▶ işlemci ──▶ findings
                     │ 200 yalnızca burada                         ▲            │ yazıldı → spool'dan silinir
                     └ dolu/yazılamıyor → 503 + Retry-After        └────────────┘ yazılamadı → geri bırakılır
```

- Her istek bir segment dosyasıdır (`seg-*.jsonl`): geçici adla yazılır,
  `fsync`, yeniden adlandırma, dizin `fsync`. Yarım yazılmış dosya hiçbir zaman
  kabul edilmiş sayılmaz (açılışta `*.tmp` silinir).
- İşlemci bulguları istekten değil spool'dan alır. Veritabanı yazımı
  başarısızsa bulgu **bırakılmaz**: spool'a geri döner ve besleyici, ardışık her
  hatada ikiye katlanan bir beklemeyle (0,5 sn → en çok 10 sn) duraklar.
  Veritabanı dönünce birikim sırayla yazılır.
- Segmentin tüm bulguları yazılınca dosya silinir. Segmentin bir kısmı
  yazıldıysa yazılanlar tek tek `<segment>.done` dosyasına (satır başına bir
  gövde satırı sırası ve onun crc32 denetimi; yırtık işaret yok sayılır) işaretlenir (W0.12b). Daemon durur ya da öldürülürse
  kalan segmentler bir sonraki açılışta yüklenir ve yalnızca işaretlenmemiş
  bulgular yeniden oynatılır (`"replaying them"` uyarısı). İşaret `fsync`
  edilmez: süreç öldürülmesinde korunur; elektrik kesintisinde kaybolursa bulgu
  yeniden oynatılır ve depo onu "zaten yazılmış" olarak bildirir.
- **Yeniden oynatmada ikinci triage yok (W0.12b):** depo, satırı yeni mi
  yazdığını yoksa zaten var mı bulduğunu ayırt eder; arama hatası "yok" sayılmaz,
  başarısız yazım olarak yeniden denenir. Zaten yazılmış bir bulgu yalnızca
  saklanan satırda henüz triage yoksa (`ai_enrichment` boş ya da yalnızca
  `ai_triage_error`) ve bu süreçte üzerinde çalışılmıyorsa triage edilir.
- **Kesinti ile zehirli bulgu ayrımı (W0.12b):** veritabanının yazımı bütünüyle
  reddetmesi kesintidir, bulgu spool'da bekler, karantinaya **hiç** gitmez:
  bağlantı hataları (SQLSTATE `08…`), salt-okunur işlem (`25006`, yük devri
  sonrası bekleme sunucusu), disk dolu / kaynak yetersiz (`53…`), yetki yok
  (`42501`), operatör müdahalesi / kurtarma (`57…`), G/Ç (`58…`), kilitlenme ve
  serileştirme (`40…`), kilit alınamadı (`55P03`), eşzamanlı ekleme (`23505`).
  SQLSTATE taşımayan hatalarda ileti metnine bakılır ("read-only transaction",
  "No space left on device", "permission denied", ...).
- **Zehirli bulgu:** yalnızca bulgunun kendisinden kaynaklanan hata (`22…` veri
  hatası, `23…` bütünlük kısıtı, `54…` sınır aşımı, bulgu içeriğinden doğan
  `ValueError`/`TypeError`) ya da sınıflandırılamayan bir hata veritabanı
  `SELECT 1`'e yanıt verirken 5 kez yinelenirse bulgu `dead/` altına (aynı
  biçimde, `fsync`'li, `0600`) ayrılır ve kuyruk tıkanmaz. Silinmez: dosya
  spool dizinine geri taşınırsa sonraki açılışta yeniden oynatılır.
- **Bozuk satır (W0.12b):** başlığı okunamayan (biçimi bilinmeyen) segment
  bütünüyle `corrupt/` altına taşınır. Başlığı sağlam bir segmentte okunamayan
  satırlar yalnızca kendileri `corrupt/<segment>-lines-<ns>.jsonl` dosyasına
  (özgün başlık + satırlar olduğu gibi) kopyalanır ve işaretlenir; segmentin
  diğer bulguları oynatılır. Satırlar düzeltilip dosya spool dizinine geri
  taşınırsa oynatılır.
- **İzinler:** spool dizini, `dead/` ve `corrupt/` `0700`; tüm dosyalar `0600`.
  Açılışta mevcut dizin ve dosyalar bu kipe getirilir (sahibi başkasıysa
  uyarı yazılır).
- Bir dizini aynı anda tek süreç kullanır (`.lock` üzerinde `flock`).

Spool kapalıysa (`DAEMON_INGEST_SPOOL_ENABLED=false`) ya da açılamazsa (dizin
yazılamıyor, başka bir süreç kilitli) webhook **satır yazılınca** 200 döner;
15 sn içinde yazılamayan bulgu için 503 döner. Bu kipte de 200'den sonra kayıp
yoktur, ama Postgres kesintisinde gönderenler bekler.

## 3. Ayarlar

| Değişken | Varsayılan | Anlamı |
|---|---|---|
| `DAEMON_INGEST_SPOOL_ENABLED` | `true` | Spool'u kullan. `false`: 200 satır yazılınca |
| `DAEMON_INGEST_SPOOL_DIR` | boş → `<VIGIL_DIR>/spool/webhook` | Spool dizini; **kalıcı, pod'a özel** bir birimde olmalı |
| `DAEMON_INGEST_SPOOL_MAX_FINDINGS` | `10000` | Yazılmamış bulgu sınırı; aşılırsa 503 |
| `DAEMON_INGEST_SPOOL_MAX_MB` | `128` | Yazılmamış bulgu bayt sınırı (diskte); aşılırsa 503 |

Sınır, Postgres kesintisinde ne kadar süre kabul etmeye devam edileceğini
belirler: 10 000 bulgu, 10 bulgu/sn'de ~16 dakikalık kesintidir. Sonrasında
webhook 503 verir ve birikim gönderende kalır (geri basınç). Bekleyen bulgular
bellekte de tutulur (diskteki boyutun birkaç katı); sınırı yükseltirken
daemon bellek sınırını (`daemon.resources.limits.memory`) da gözetin.

## 4. Kurulumlar

- **Helm:** `daemon.persistence.enabled=true` (varsayılan) iken grafik
  `DAEMON_INGEST_SPOOL_DIR=<persistence.mountPath>/.ingest-spool` ayarlar; spool
  her daemon podunun kendi `investigations` PVC'sindedir (StatefulSet
  `volumeClaimTemplates`, ReadWriteOnce). Pod yeniden başlasa ya da başka düğüme
  taşınsa da PVC'si ile döner. `persistence.enabled=false` ise spool
  `stateDirectory`'ye düşer; varsayılan `emptyDir` yalnızca konteyner yeniden
  başlatmasında korunur, pod silinince içindekiler kaybolur.
- **Docker Compose:** `VIGIL_DIR` `vigil_home` adlı birimdedir; spool
  `<VIGIL_DIR>/spool/webhook` altında kalıcıdır.

## 5. Lider seçimiyle (W3.9)

- Spool'u yalnızca **lider** açar ve yeniden oynatır (`_init_components`
  yalnızca liderlikte çalışır). Takipçi spool'a dokunmaz; webhook'u 503 +
  `Retry-After: 2` döner.
- Spool **pod'a özeldir**: iki pod spool paylaşmaz. Öldürülen bir liderin
  spool'unda kalan bulgular o pod yeniden **lider olduğunda** oynatılır.
  Yeniden başlayan pod takipçi olarak dönerse, açılışta şu uyarıyı yazar:
  `Standby: N ingest spool segment(s) on this pod wait until it leads`.
  Bu bulgular kaybolmamıştır, ama bekler. Takipçi beklerken bekleyen bulgu
  sayısını `soc_daemon_ingest_spool_standby_pending` göstergesinde yayımlar
  (30 sn'de bir dizinden salt-okunur sayılır; pod lider olunca 0). Hemen
  aktarmak için mevcut lider podu yeniden başlatın (`kubectl delete pod
  <lider>`); bekleyen pod kilidi alır ve oynatır. Rolleri `/health`
  (`"role"`) gösterir. Uyarı önerisi:
  `soc_daemon_ingest_spool_standby_pending > 0` 10 dakikadan uzun sürerse
  devri elle yapın.
- Lider olan pod başka podların spool'unu **oynatmaz**: Helm'de her pod kendi
  ReadWriteOnce PVC'sini görür, başka bir podun dizinine erişemez. Bütün
  podlar aynı paylaşılan (ReadWriteMany) dizini `DAEMON_INGEST_SPOOL_DIR` ile
  gösterirse tek bir spool vardır: dizini `flock` ile o anki lider tutar ve
  yeni lider devraldığında (eski süreç çıkınca kilit bırakılır) kalanı
  oynatır. Bu kip desteklenen varsayılan değildir: ağ dosya sistemlerinde
  `flock` davranışı ve `fsync` garantisi sağlayıcıya bağlıdır; yeni lider
  kilidi eski süreç çıkmadan almaya çalışırsa spool'suz kipe ("satır yazılınca
  200") düşer.
- Bir PVC silinirse (ör. StatefulSet ölçeği küçültülüp PVC'ler temizlenirse)
  içindeki yazılmamış bulgular gider. Ölçek küçültmeden önce o podun spool'unun
  boş olduğunu doğrulayın (`soc_daemon_ingest_spool_pending` = 0 ya da dizinde
  `seg-*.jsonl` yok).

## 6. Metrikler ve durum

OTEL/Prometheus (`/metrics`, `VIGIL_OTEL_ENABLED=true`):

| Metrik | Anlamı |
|---|---|
| `soc_daemon_ingest_spool_pending` | Kabul edilmiş, henüz yazılmamış bulgu |
| `soc_daemon_ingest_spool_bytes` | Spool'un tuttuğu bayt |
| `soc_daemon_ingest_spool_appended_total` | Spool'a alınan bulgu |
| `soc_daemon_ingest_spool_rejected_total{reason=full\|error}` | 503 ile reddedilen istek |
| `soc_daemon_ingest_spool_store_retries_total` | Yazılamayıp spool'a geri dönen deneme |
| `soc_daemon_ingest_spool_replay_skipped_total` | Zaten yazılmış (ve triage edilmiş ya da triage'ı sürmekte) bulunup yeniden triage edilmeyen |
| `soc_daemon_ingest_spool_quarantined_total` | `dead/` altına ayrılan bulgu |
| `soc_daemon_ingest_spool_standby_pending` | Takipçi podun kendi spool'unda, o pod lider olana dek bekleyen bulgu (W0.12b) |

`/status` (sağlık portu) `metrics.ingest_spool` altında aynı sayıları
(W0.12b: `corrupt_lines` dahil) ve `processor.store_retried`,
`processor.spool_quarantined`, `processor.spool_store_outages` (kesinti
sayılan başarısız yazım), `processor.spool_existing_enriched` (zaten yazılmış
ama triage'sız bulunup triage edilen), `processor.backfill_skipped_inflight`
alanlarını gösterir.

Uyarı önerileri: `soc_daemon_ingest_spool_pending` 5 dakikadan uzun süre
artıyorsa (veritabanı yazılamıyor), `rejected_total{reason="full"}` artıyorsa
(sınır doldu, gönderenler bekliyor), `quarantined_total > 0` (elle inceleme).

## 7. LLM worker ve Redis

LLM worker (`python -m services.worker`) Redis bağlantısını kaybedince artık
süreçten çıkmaz: yeni bir worker ile yeniden bağlanır (1 sn'den 30 sn'ye
ikiye katlanan bekleme, bir dakika sağlıklı çalışınca sıfırlanır). Redis dışı
hatalar süreci yine sonlandırır. Helm'deki `arq --check` canlılık probu Redis
uzun süre yokken podu yine yeniden başlatabilir; bu beklenen davranıştır.

## 8. Backfill

Zenginleştirme backfill taraması, o anda yazılmakta ya da triage edilmekte
(model yanıtı beklenen, sıradaki) bulguları atlar; bir bulgu aynı anda iki
kez triage edilmez (`backfill_skipped_inflight`).
