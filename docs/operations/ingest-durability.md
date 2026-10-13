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
- Segmentin tüm bulguları yazılınca dosya silinir. Daemon durur ya da
  öldürülürse kalan segmentler bir sonraki açılışta yüklenir ve yeniden
  oynatılır (`"replaying them"` uyarısı).
- **Zehirli bulgu:** veritabanı `SELECT 1`'e yanıt verirken bir bulgunun
  yazımı 5 kez reddedilirse bulgu `dead/` altına (aynı biçimde, `fsync`'li)
  ayrılır ve kuyruk tıkanmaz. Silinmez: dosya spool dizinine geri taşınırsa
  sonraki açılışta yeniden oynatılır. Okunamayan segmentler `corrupt/` altına
  taşınır.
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
  Bu bulgular kaybolmamıştır, ama bekler. Hemen aktarmak için mevcut lider
  podu yeniden başlatın (`kubectl delete pod <lider>`); bekleyen pod kilidi
  alır ve oynatır. Rolleri `/health` (`"role"`) gösterir.
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
| `soc_daemon_ingest_spool_replay_skipped_total` | Yeniden oynatmada zaten yazılmış bulunan |
| `soc_daemon_ingest_spool_quarantined_total` | `dead/` altına ayrılan bulgu |

`/status` (sağlık portu) `metrics.ingest_spool` altında aynı sayıları ve
`processor.store_retried`, `processor.spool_quarantined`,
`processor.backfill_skipped_inflight` alanlarını gösterir.

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
