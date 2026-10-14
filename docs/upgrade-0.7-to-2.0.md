# Vigil 0.7.x'ten AutoSecOps 2.0'a yükseltme

Bu kılavuz, Vigil 0.7.1 (veya 0.7.0) çalıştıran bir kurulumun veritabanını
AutoSecOps 2.0 şemasına taşır. Yükseltme **yalnızca ileri yönlüdür**: geri
göç (down migration) yoktur, geri dönüşün tek yolu yükseltmeden önce alınan
yedeğin geri yüklenmesidir. Bu yüzden yedek adımı isteğe bağlı değildir.

Aracın kendisi `scripts/upgrade_database.py`'dir. Ne yaptığı, sırasıyla:

| Adım | Ne olur |
|---|---|
| `preflight` | Salt okunur kontroller (aşağıda). Biri `FAIL` ise hiçbir şey değişmez. |
| `backup` | `--backup DOSYA` verildiyse `pg_dump -Fc` ile tam yedek. |
| `sql-1` | 0.7.1'den yeni init SQL dosyaları (`infra/database/init/NN_*.sql`, NN > 40), dosya adı sırasıyla, hataya toleranslı. |
| `orm` | Yalnızca uygulama modellerinin tanımladığı tablolar (`create_all`) ve varsayılan referans satırları. |
| `migrate` | `scripts/migrate_schema.py`: mevcut tablolara eksik kolonlar ve veri düzeltmeleri. Her adım uygulanmalıdır. |
| `sql-2` | Aynı SQL dosyaları tekrar, bu kez katı: ilk hatada durur, her dosya tek işlemde. |
| `verify` | Ortaya çıkan şema, taze bir 2.0 kurulumunun şemasıyla (`core/storage/schema.snapshot.json`) karşılaştırılır. Eksik tablo/kolon veya tür farkı yükseltmeyi başarısız sayar. |
| `stamp` | `system_config.schema_version` yeni sürüme, çalıştırma kaydı `system_config['upgrade.history']`'e yazılır. |

Araç aynı veritabanında birden fazla kez çalıştırılabilir; ikinci çalıştırma
hiçbir şeyi değiştirmez. Yarıda kalan bir çalıştırma, sorun giderildikten
sonra yeniden çalıştırılarak tamamlanır.

## Önkoşullar

- PostgreSQL 14 veya üzeri sunucu (16 test edilen sürüm). `psql` ve
  `pg_dump` istemcileri sunucunun ana sürümünden eski olmamalı.
- Veritabanına **süper kullanıcı** olarak veya tüm tabloların sahibi olan
  rollerin hepsine üye bir rolle bağlanılmalı. Compose kurulumunda bu
  `deeptempo` kullanıcısıdır; `vigil_app` yetmez (ön kontrol `privileges`
  adımında reddeder ve sahipleri adıyla söyler).
- Yedek için veritabanı boyutu kadar boş disk.
- Bakım penceresi: yükseltme sırasında backend, daemon, LLM işçisi, ajan
  işçileri ve Medic durdurulmuş olmalı (ön kontrol, veritabanında başka
  oturum görürse uyarır).
- Kaynak sürüm 0.7.0 veya 0.7.1 olmalı. Daha eskiyse önce 0.7.1'e
  yükseltin; ön kontrol `source-version` adımında reddeder.

## Ön kontroller ve deneme çalıştırması

Her zaman önce `--dry-run` çalıştırın. Hiçbir şey yazmaz; ön kontrolleri ve
planı (uygulanacak SQL dosyaları, eklenecek tablo ve kolonlar) basar:

```bash
read -rsp 'veritabanı parolası: ' PAROLA; echo
export DATABASE_URL="postgresql://deeptempo:${PAROLA}@localhost:5432/deeptempo_soc"
python scripts/upgrade_database.py --dry-run
```

`--database-url` verilmezse bağlantı `DATABASE_URL`'den, sonra
`~/.deeptempo/.env`'den, sonra `POSTGRES_*` değişkenlerinden okunur
(`scripts/migrate_schema.py` ile aynı sıra). Parola, `psql` ve `pg_dump`'a
yalnızca ortam değişkeniyle geçer, komut satırında görünmez. Parola içeren
bir adresi `--database-url` ile vermeyin: aracın kendi komut satırı da `ps`
ile okunabilir; `DATABASE_URL`'yi kullanın.

Ön kontroller: `connect`, `server-version`, `vigil-database` (boş veya Vigil
olmayan veritabanı reddedilir: bu bir kurulumdur, yükseltme değil),
`source-version` (yeni sürümden daha yeni bir veritabanı reddedilir; ileri
yönlü kural), `privileges`, `extensions`, `sessions`, `init-files`,
`schema-delta`, `psql` ve uygulama modunda `backup`. Makine tarafından okunacak
çıktı için `--json` ekleyin.

## Yedek

Yükseltme komutu, yedek kararı verilmeden çalışmaz: ya `--backup DOSYA`
(araç `pg_dump -Fc` alır; dosya önceden var olmamalı) ya da kendi yedeğinizi
aldıktan sonra `--no-backup` vermelisiniz.

Önerilen: ikisini birden yapın.

1. **0.7.1 araçlarıyla tam yedek** (veritabanı, Bifrost verisi, durum dizini):
   0.7.1 kurulumu henüz çalışırken `./start.sh backup --repo YOL
   --passphrase-file YOL`. Bu restic anlık görüntüsü, 0.7.1'in kendi `restore`
   komutuyla geri yüklenebilir.
2. **Yükseltme aracının veritabanı yedeği:** `--backup /yedekler/pre-2.0.dump`.
   Geri alma için en hızlı yol budur.

Veritabanı dışında, yükseltmeden önce şunları da kopyalayın: `.env`
(sırlar), `~/.deeptempo/` ve `~/.vigil/` durum dizinleri, `backups.json`,
`data/` altındaki inceleme çalışma dizinleri. Redis yalnızca kuyruk ve oturum
tutar; yükseltmeden sonra kullanıcıların yeniden oturum açması yeterlidir.

## Yükseltme: Docker Compose

Komutlar 2.0 sürümünün kaynak ağacının kökünden çalıştırılır.

```bash
# 1. 0.7.1 yığınını durdurun (birimler kalır).
docker compose -f infra/docker/docker-compose.yml down

# 2. 2.0 imajlarını oluşturun veya çekin, yalnızca Postgres'i başlatın.
docker compose -f infra/docker/docker-compose.yml build
docker compose -f infra/docker/docker-compose.yml up -d postgres

# 3. Deneme çalıştırması. Backend imajında scripts/ yoktur; salt okunur bağlanır.
# Yedek dizini yalnızca sizin: araç kapsayıcıda sizin UID'nizle çalışır ve
# yedeği 0600 izinle (yalnızca sahibi okur) yazar. Dizini başkalarına yazılabilir
# yapmayın; yedek, parola özetleri dahil tüm veritabanını içerir.
install -d -m 700 backups
# Bağlantı adresi (parolayla) komut satırına değil ortama konur: komut satırını
# (`ps`, /proc) makinedeki herkes okuyabilir. `export` kabuğun kendi komutudur,
# `-e DATABASE_URL` (değersiz) değeri bu ortamdan kapsayıcıya aktarır.
export DATABASE_URL="postgresql://deeptempo:${POSTGRES_PASSWORD}@postgres:5432/deeptempo_soc"
docker compose -f infra/docker/docker-compose.yml run --rm --no-deps \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/scripts:/app/scripts:ro" -v "$PWD/backups:/backups" \
  -e DATABASE_URL \
  --entrypoint python backend scripts/upgrade_database.py --dry-run

# 4. Yükseltme (yedekle birlikte).
docker compose -f infra/docker/docker-compose.yml run --rm --no-deps \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/scripts:/app/scripts:ro" -v "$PWD/backups:/backups" \
  -e DATABASE_URL \
  --entrypoint python backend scripts/upgrade_database.py --backup /backups/pre-2.0.dump

# 5. Yığını başlatın.
unset DATABASE_URL
docker compose -f infra/docker/docker-compose.yml up -d
```

`POSTGRES_PASSWORD` 0.7.1'de kullandığınız değer olmalıdır. Başlangıçta
çalışan `db-seed` ve backend'in `create_all`'u artık yapacak iş bulamaz.

## Yükseltme: Helm ve kurulum dışı (bare-metal)

Aracı, 2.0 kaynak ağacı ve Python ortamı (`./setup_dev.sh`) olan bir yönetici
makinesinden çalıştırın; Postgres'e Helm kurulumunda port yönlendirmeyle
erişin:

```bash
kubectl scale deploy -n NAMESPACE -l app.kubernetes.io/instance=SURUM --replicas=0
kubectl port-forward -n NAMESPACE svc/SURUM-postgresql 5432:5432 &
# Parola komut satırında görünmesin diye --database-url yerine DATABASE_URL.
read -rsp 'postgres parolası: ' PAROLA; echo
export DATABASE_URL="postgresql://postgres:${PAROLA}@localhost:5432/VERITABANI"
python scripts/upgrade_database.py --dry-run
python scripts/upgrade_database.py --backup ./pre-2.0.dump
unset DATABASE_URL PAROLA
helm upgrade SURUM infra/helm/vigil -n NAMESPACE -f degerler.yaml
```

Helm'de tablolar iki farklı role (chart'ın veritabanı kullanıcısı ve
`vigil_app`) ait olduğundan süper kullanıcıyla (`postgres`) bağlanın. Araç,
uyguladığı dosyaları Helm db-init Job'unun `_vigil_schema_versions`
tablosuna işler; `helm upgrade` bu dosyaları yeniden uygulamaz.

## Doğrulama

- Komut `upgrade complete: <eski> -> <yeni>` ile ve çıkış kodu 0 ile biter.
  `verify` adımı şemanın taze kurulumla aynı olduğunu zaten denetlemiştir.
- `SELECT value FROM system_config WHERE key IN ('schema_version', 'upgrade.history');`
  yeni sürümü ve bu çalıştırmayı gösterir.
- Uygulama başladıktan sonra yönetim ekranındaki depolama durumu
  (`/api/storage/status`) şema kayması (`drifted`) göstermemelidir.
- Defter zinciri bozulmamış olmalıdır; aşağıdaki sorgu `0` döndürmelidir
  (CI bunu 0.7.1 dökümünde her değişiklikte denetler):

  ```sql
  SELECT count(*) FROM (
    SELECT prev_hash, event_hash,
           coalesce(lag(event_hash) OVER (PARTITION BY run_id ORDER BY seq), '') AS beklenen_onceki,
           agent_event_hash(prev_hash, payload) AS beklenen
    FROM agent_events) z
  WHERE prev_hash IS DISTINCT FROM beklenen_onceki OR event_hash IS DISTINCT FROM beklenen;
  ```
- Yükseltme, #1276 öncesi sahte izolasyon kayıtlarını (`isolate_host`,
  mesajı `(MOCK)` içeren) `failed` olarak işaretler ve bu konakları günlüğe
  yazar: bu konaklar hiç izole edilmemiştir, gözden geçirin.

## Geri alma

Geri göç yoktur; geri alma = 0.7.1 yazılımına dönmek + yedeği geri yüklemek.
Yükseltmeden sonra yazılan veriler (yeni alarmlar, vakalar) kaybolur; bunları
gerekiyorsa önce dışa aktarın.

Compose, aracın aldığı yedekle:

```bash
docker compose -f infra/docker/docker-compose.yml down
git checkout <0.7.1 sürümü>        # veya 0.7.1 dağıtım arşivi
docker compose -f infra/docker/docker-compose.yml up -d postgres
docker compose -f infra/docker/docker-compose.yml exec -T postgres \
  dropdb -U deeptempo --force deeptempo_soc
docker compose -f infra/docker/docker-compose.yml exec -T postgres \
  createdb -U deeptempo deeptempo_soc
docker compose -f infra/docker/docker-compose.yml exec -T postgres \
  pg_restore -U deeptempo -d deeptempo_soc --exit-on-error < backups/pre-2.0.dump
docker compose -f infra/docker/docker-compose.yml up -d
```

Yedek, sahiplikleri ve yetkileri taşır (`vigil_app` rolü kümede durduğu
için geri yükleme onları korur). restic anlık görüntüsüyle geri dönüş için
0.7.1 ağacında `./start.sh restore` kullanın. Geri yüklemeden sonra
`system_config.schema_version` yine `0.7.1` olmalıdır.

Helm ve bare-metal: uygulamayı durdurun, 0.7.1 chart'ına/koduna dönün,
veritabanını silip boş olarak yeniden oluşturun ve
`pg_restore -d VERITABANI --exit-on-error pre-2.0.dump` çalıştırın.

## Sorun giderme

| Mesaj | Anlamı ve çözüm |
|---|---|
| `[FAIL] privileges: N object(s) this role cannot alter` | Süper kullanıcıyla veya adı geçen sahiplerin üyesi bir rolle bağlanın. |
| `[FAIL] source-version: database is at X, newer than this release` | Veritabanı bu sürümden yeni; doğru sürümü kullanın ya da uygun yedeği geri yükleyin. |
| `[FAIL] source-version: ... upgrade to Vigil 0.7.1 first` | 0.7.0'dan eski kaynak: önce 0.7.1'e yükseltin. |
| `[FAIL] backup: pass --backup PATH ...` | Yedek kararı verilmedi; `--backup` veya `--no-backup` ekleyin. |
| `[WARN] sessions: N other session(s)` | Uygulama süreçleri hâlâ bağlı; durdurun. |
| `NN_x.sql failed on the strict pass` | Önceki adımlar işlenmiştir ve yeniden çalıştırılabilir; hatayı giderip komutu tekrar çalıştırın veya yedeği geri yükleyin. |
| `schema after upgrade differs from a fresh install` | Kod ile veritabanı arasında beklenmeyen fark; bulgu listesini destek ekibine iletin, uygulamayı başlatmayın. |

## Geliştiriciler için

- `infra/database/init/` altında **40 ve altı numaralı dosyalar dondurulmuştur**
  (0.7.1 bunları zaten çalıştırdı); yalnızca yorumları değişebilir
  (`tests/unit/test_upgrade_database.py`). Şema değişikliği yeni bir
  `NN_ad.sql` (NN > 40) dosyasıyla yapılır; araç onu kendiliğinden ve dosya adı
  sırasıyla alır. Dosya idempotent olmalıdır (`IF NOT EXISTS`, `ON CONFLICT`,
  `DROP ... IF EXISTS` sonra `CREATE`), çünkü her yükseltmede iki kez çalışır.
- Yeni dosyayla birlikte `python scripts/generate_schema_snapshot.py` çalıştırıp
  anlık görüntüyü güncelleyin. `tests/integration/test_upgrade_from_071.py`
  0.7.1 dökümünü yükseltip sonucu taze kurulumla karşılaştırır.
- 0.7.1 dökümü ve manifest `python scripts/build_upgrade_fixture.py` ile
  yeniden üretilir (upstream'de `v0.7.1` etiketi olmadığı için 0.7.1 sürüm
  commit'i `f72243c4` kullanılır).
