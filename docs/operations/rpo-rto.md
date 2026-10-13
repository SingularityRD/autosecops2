# AutoSecOps — RPO / RTO, daemon sıcak yedeği ve veritabanı yedekleri

Bu belge, AutoSecOps'un Kubernetes (Helm) kurulumunda hangi arızada ne kadar veri
kaybedilebileceğini (**RPO**, Recovery Point Objective) ve hizmetin ne kadar sürede
geri geleceğini (**RTO**, Recovery Time Objective) tanımlar; bu hedefleri sağlayan
mekanizmaları (daemon lider seçimi, yedek CronJob'u) ve geri yükleme prosedürünü
anlatır. Docker Compose (tek kutu) kurulumu için yedekleme `python -m core.backup`
(restic) ile yapılır; o yol bu belgenin kapsamı dışındadır, yalnızca §6'da anılır.

## 1. Özet tablo

Varsayılan değerlerle (`daemon.leaderElection.leaseSeconds=15`,
`retrySeconds=2`, `backup.schedule` günlük):

| Arıza | RPO | RTO (hedef) | Mekanizma |
|---|---|---|---|
| Daemon süreci çöker / `SIGKILL` / OOM | DB: 0. Bellekteki işlenmemiş bulgular (aşağıya bakın) | ≤ 2 sn devralma + bileşen açılışı (tipik 10–60 sn) | Kilit oturumu kapanır, yedek en geç `retrySeconds` içinde alır |
| Planlı yeniden başlatma / rollout (`SIGTERM`) | 0 | ≤ 2 sn + açılış | Lider bileşenleri durdurur, kilidi bırakır |
| Daemon düğümü kaybı, ağ bölünmesi, süreç donması (SIGSTOP, VM duraklaması) | DB: 0 (çitleme) | 10–17 sn devralma + açılış | Sunucu tarafı `idle_session_timeout` kilidi düşürür |
| Postgres verisinin kaybı (disk/PVC bozulması, yanlış silme) | ≤ yedek aralığı (varsayılan 24 saat) | Geri yükleme süresi + uygulama açılışı; hedef ≤ 1 saat (≤ 10 GB veritabanı) | `backup` CronJob'u + §5 prosedürü |
| Küme / bölge kaybı | ≤ yedek aralığı | Yeni küme kurulumu + geri yükleme; hedef ≤ 4 saat | `backup.objectStore` ile küme dışı kopya |

Daha düşük RPO için `backup.schedule` sıklaştırılır (ör. saatlik `"7 * * * *"`);
sıfıra yakın RPO gerekiyorsa veritabanı, sürekli WAL arşivlemeli harici bir HA
Postgres hizmetinde (yönetilen bulut veritabanı, Patroni/CloudNativePG) çalıştırılmalı
ve `postgresql.enabled=false` ile bağlanmalıdır. Grafikteki gömülü Postgres tek
kopyadır; kendi kaybına karşı yalnızca bu yedekler korur.

## 2. Daemon sıcak yedeği (lider seçimi)

### Nasıl çalışır

`daemon.leaderElection.enabled=true` (varsayılan) iken daemon StatefulSet'i iki pod
çalıştırır (`podManagementPolicy: Parallel`, mümkünse farklı düğümlere yerleşmeyi
tercih eden pod anti-affinity). Her süreç açılışta Postgres oturum düzeyi danışma
kilidini `(1287, 3900)` almaya çalışır:

- **Lider** (kilidi alan): tüm döngüleri başlatır — Federation poller ve webhook,
  Kafka, processor, responder, scheduler, orchestrator, case automation. Kilidi
  `leaseSeconds / 3` (varsayılan 5 sn) aralıkla kalp atışıyla doğrular.
- **Takipçi (standby)**: hiçbir döngü çalıştırmaz. `/health` 200 ve
  `"role": "standby"` döner (probelar geçer, rollout takılmaz); webhook portu
  `/ingest` ve `/webhook` isteklerine 503 + `Retry-After: 2` verir. Kilidi
  `retrySeconds` (varsayılan 2 sn) aralıkla yeniden dener.

Kilit ayrı, havuz dışı bir bağlantıda tutulur ve bu oturuma
`idle_session_timeout = leaseSeconds` atanır:

- Lider süreci ölürse TCP oturumu kapanır, Postgres kilidi hemen bırakır →
  takipçi en geç `retrySeconds` içinde lider olur.
- Lider donarsa ya da ağ koparsa oturum açık kalır ama sessizleşir; Postgres son
  kalp atışından `leaseSeconds` sonra oturumu sonlandırır → takipçi
  `leaseSeconds − leaseSeconds/3` ile `leaseSeconds + retrySeconds` arasında
  lider olur (varsayılanla 10–17 sn).
- Kalp atışı, kilit alındığı anda başlayan ayrı bir iş parçacığında (thread)
  çalışır; bileşenlerin açılışı (`_init_components`) ya da olay döngüsünü
  bloklayan herhangi bir eşzamanlı çağrı onu geciktirmez. Açılış `leaseSeconds`'tan
  uzun sürse bile kilit korunur. Her bileşen başlatılmadan hemen önce liderlik
  yeniden doğrulanır (`ensure_leader`); açılış sırasında kilit kaybedildiyse hiçbir
  bileşen başlamaz.
- Lider kendi tarafında da bekler: son başarılı kalp atışından
  `leaseSeconds − leaseSeconds/3` geçtiyse ya da kalp atışı başarısızsa kendini
  indirir, bileşenleri durdurur ve **75** çıkış koduyla çıkar. Kubernetes podu
  yeniden başlatır; süreç takipçi olarak döner. Bellekteki durum asla yeniden
  kullanılmaz. Olay döngüsü bloklu olduğu için düzgün çıkış yapılamıyorsa kalp
  atışı iş parçacığı, kayıptan `min(1 sn, leaseSeconds/6)` sonra süreci kendisi
  sonlandırır (`os._exit(75)`) — yani takipçinin kilidi alabileceği en erken andan
  önce; eski bileşenler yeni liderle aynı anda çalışmaz.

Ölçülen değerler (`tests/integration/test_daemon_leader_election.py`, iki gerçek
daemon süreci, `lease=6 sn`, `retry=1 sn`, yüklü 2 CPU'lu test makinesi):
`SIGKILL` sonrası devralma ≈ 1,0 sn; `SIGTERM` ≈ 1,1 sn; `SIGSTOP` ≈ 5,0 sn; kilit
oturumunun sunucu tarafında kesilmesi (bölünme benzetimi) ≈ 1,0 sn. Bunlara
gerçek kurulumda bileşenlerin açılış süresi (MCP bağlantıları vb.) eklenir.

### Çitleme (fencing)

Donup geri gelen eski lider, kendini indirmeden önce kısa bir süre hâlâ lider
olduğunu sanabilir. Veritabanına yazmasını engelleyen iki adım vardır:

1. Daemon'un tüm SQLAlchemy bağlantıları `application_name =
   vigil-daemon:<örnek>` taşır ve her yeni bağlantı açılışta kilidin sahibinin
   kendi kilit oturumu (`vigil-daemon-lock:<örnek>`) olduğunu doğrular; değilse
   bağlantı reddedilir (`FencedError`).
2. Yeni lider kilidi aldıktan hemen sonra, kendisi dışındaki tüm
   `vigil-daemon:*` oturumlarını `pg_terminate_backend(pid, 5000)` ile sonlandırır
   ve çıkmalarını bekler; eski liderin açık işlemleri geri alınır. Bu adım
   başarısız olursa yeni lider liderliği bırakır.

Sonuç: yeni lider çalışmaya başladıktan sonra eski örnekten hiçbir veritabanı
yazımı işlenmez (testte satır kimlikleriyle doğrulanır).

### Operatör için

- Hangi pod lider? `kubectl exec <pod> -- curl -s localhost:9091/health` →
  `"role"`; `/status` içinde `leadership` (örnek kimliği, ne zamandan beri).
  Prometheus: `soc_daemon_leader` (lider 1, takipçi 0). Uyarı önerisi:
  `sum(soc_daemon_leader) != 1` 1 dakikadan uzun sürerse.
- Veritabanında: `SELECT application_name FROM pg_stat_activity WHERE
  application_name LIKE 'vigil-daemon-lock:%';`
- Tek kopyaya dönmek: `--set daemon.leaderElection.enabled=false`.
- Gereksinim: PostgreSQL ≥ 14. Daha eski sunucuda seçim açıkken daemon
  `UnsupportedServerError` ile çıkar (pod CrashLoopBackOff'ta görünür); seçimi
  kapatın ya da sunucuyu yükseltin.
- **PgBouncer / bağlantı havuzlayıcı**: kilit oturumu Postgres'e doğrudan (ya da
  `pool_mode = session` bir havuzdan) gitmelidir. İşlem (`transaction`) veya
  ifade (`statement`) havuzlamasında her ifade başka bir sunucu oturumuna
  düşebilir: oturum düzeyi danışma kilidi yanlış oturumda kalır (ve istemci
  ölünce bırakılmaz), `SET idle_session_timeout` başka bir oturuma uygulanır;
  kira (lease) ve devralma güvencesi kalmaz. Bu yüzden:
  - Platform veritabanı PgBouncer vekili (`proxy_type = pgbouncer`) üzerinden
    yapılandırılmışsa ve `DAEMON_LEADER_DATABASE_URL` boşsa, seçim açıkken daemon
    `UnsupportedServerError` ile açılmayı reddeder.
  - `DAEMON_LEADER_DATABASE_URL` (ör. `postgresql://user:pass@postgres:5432/deeptempo_soc`)
    yalnızca kilit oturumu için doğrudan bir DSN verir; veri bağlantıları
    olduğu gibi kalır.
  - Yapılandırmada görünmeyen bir havuzlayıcı için kilit bağlantısı açılışta
    sınanır: ikinci bir istemci bağlantısı tek bir ifade çalıştırır; aynı sunucu
    sürecine (backend pid) düşerse ya da kilit bağlantısının pid'i / oturum
    ayarı değişirse `PooledConnectionError` ile seçim reddedilir.
  - Veri bağlantıları da işlem havuzlu bir PgBouncer'dan geçiyorsa çitlemenin 2.
    adımı (eski liderin `vigil-daemon:*` oturumlarının sonlandırılması) güvenilir
    değildir: `application_name` havuzdaki sunucu oturumuna yapışır, sonlandırma
    başka istemcilerin işlemlerini de kesebilir. Daemon'u seçim açıkken
    Postgres'e doğrudan bağlayın.
- `leaseSeconds` küçültülürse donma/bölünmede devralma hızlanır ama kısa ağ
  kesintileri gereksiz devirlere yol açar; 10 sn'nin altı önerilmez.
  `retrySeconds < leaseSeconds` olmalıdır.

### Kalan riskler (çitlenmeyen durumlar)

- **Veritabanı dışı yan etkiler**: Redis yazımları (tekrar önleme kümeleri,
  kuyruklar) ve dış API çağrıları (müdahale eylemleri, satıcı API'leri, Slack /
  PagerDuty) çitlenmez. Donma anında yolda olan bir çağrı, süreç uyandığında
  tamamlanabilir. Etki sınırlıdır: süreç uyanır uyanmaz kalp atışı gecikmesini
  görüp kendini indirir ve yeni bir veritabanı okuması yapamaz (eylem kararları
  ve onaylar veritabanından okunur).
- **agent-worker işleri (dolaylı yazımlar)**: orchestrator ajan çalıştırmalarını
  Redis'teki BullMQ kuyruğuna (`bull:agent-runs:*`, `core/agents/queue.py`)
  koyar; bunları ayrı `agent-worker` süreçleri yürütür ve veritabanına kendi
  bağlantılarıyla yazar. Bu bağlantılar `vigil-daemon:*` değildir, çitlenmez:
  eski liderin kuyruğa koyduğu bir iş, yeni lider başladıktan sonra da çalışıp
  yazabilir (araştırma sonuçları, ajan olayları, `workflow_runs`). Kuyruğa
  koyma Redis'e doğrudan yazar ve çitlenmez; orchestrator `workflow_runs`
  satırı yazılamasa bile işi kuyruğa koyar. Pencere: eski lider kilidi
  kaybettiği andan süreç bitene kadar (olay döngüsü çalışıyorsa milisaniyeler,
  bloklu ise en fazla kalp atışı iş parçacığının `min(1 sn, leaseSeconds/6)`
  bekleme süresi) ve donma anında yolda olan çağrılar. Bu pencerede gereken
  veritabanı okumaları (araştırma kaydı vb.) çitlendiği için pratikte yalnızca
  hazırlığı bitmiş bir `enqueue` kaçabilir. Etkisi: aynı araştırma için iki
  çalıştırma görülebilir; agent tarafındaki `leases.claim` koşullu UPDATE'i ve
  `advance()`'in terminal kontrolü aynı çalıştırma kimliğinin iki kez
  ilerlemesini engeller, ama farklı kimlikli iki iş ikisi de tamamlanır.
  Operatör çift çalıştırmayı konsoldan iptal edebilir. Kalıcı çözüm (iş
  yükünde liderlik dönemini taşıyıp agent-worker'da doğrulamak) bu WP'nin
  kapsamı dışındadır.
- **Bellekteki kuyruklar**: processor/responder kuyruklarındaki henüz
  saklanmamış bulgular lider değişiminde kaybolur. Federation imleçleri
  veritabanında olduğundan kaynaklar yeniden okunur; webhook gönderenler 503 ya
  da zaman aşımında yeniden dener.
- **Takipçiye düşen webhook istekleri**: Kubernetes Service iki poda da yönlendirir;
  takipçi 503 + `Retry-After` döner. Gönderenler zaten 503'te yeniden denediği
  için veri kaybı olmaz, ancak gecikme artabilir.
- **İnceleme çalışma alanı**: her daemon podunun kendi `investigations` PVC'si
  vardır; eski liderin diskindeki ara çıktılar yeni lidere geçmez.
- **Çalışma anında veritabanı hedef değişimi** (retarget): kilit bağlantısı eski
  hedefte kalır. Hedef değiştirildikten sonra daemon podlarını yeniden başlatın.

## 3. Veritabanı yedeği (Helm CronJob)

`backup.enabled=true` ile (varsayılan kapalı) grafik bir CronJob kurar:

- `pg_dump -Fc` (özel biçim, sıkıştırılmış) geçici bir adla yazılır,
  `pg_restore --list` (içindekiler) ve ardından `pg_restore -f /dev/null` (tüm
  veri bloklarının okunup açılması; içindekilerden sonra kesilmiş bir döküm
  burada yakalanır) ile geri okunarak doğrulanır, `.sha256` dosyası üretilir ve
  ancak bundan sonra kalıcı adına (`<db>-<UTC zaman>.dump`) taşınır; `LATEST`
  en yeni dökümün adını tutar. Betik: `infra/helm/vigil/files/backup/pg-backup.sh`.
- **Saklama**: en yeni `backup.keepLast` (varsayılan 14) döküm her zaman kalır;
  diğerleri `backup.retentionDays` (varsayılan 30) günden eskiyse silinir
  (`0` = yalnızca son `keepLast`).
- **Hedef**: `backup.persistence` PVC'si (varsayılan 50 Gi;
  `helm.sh/resource-policy: keep` ile `helm uninstall` sonrasında da kalır)
  ve/veya `backup.objectStore` (S3 uyumlu; `bucket`, `prefix`, `endpointUrl`
  MinIO/Ceph için, `existingSecret` içinde `AWS_ACCESS_KEY_ID` /
  `AWS_SECRET_ACCESS_KEY` ya da IRSA). Nesne deposunda saklama için kova yaşam
  döngüsü (lifecycle) kuralı tanımlayın. İkisi de kapalıysa grafik kurulmaz.
- `concurrencyPolicy: Forbid`: süren bir döküm varken yenisi başlamaz.
- Ağ politikası açıksa (`networkPolicies.enabled`) yedek podunun Postgres'e
  erişimi otomatik eklenir. Nesne deposu çıkışı varsayılan çıkış kuralına tabidir.
- **Gizlilik**: dökümler şifrelenmemiştir ve tüm platform verisini (bulgular,
  vakalar, şifreli sırların şifreli hâlleri) içerir. Şifreli bir
  `storageClassName` ve kovada sunucu tarafı şifreleme (SSE) kullanın; erişimi
  yalnızca yedek operatörlerine verin.
- **İzleme**: `kube_cronjob_status_last_successful_time` (kube-state-metrics)
  için, `schedule` aralığının iki katından eski olduğunda uyarı tanımlayın.

## 4. Ölçüm: RPO ve RTO nasıl doğrulanır

- **Daemon devralma**: `tests/integration/test_daemon_leader_election.py` (iki
  gerçek süreç, gerçek Postgres; öldürme, düzgün kapanma, donma, bölünme). Canlı
  ortamda: lider podu `kubectl delete pod --grace-period=0 --force` ile silin,
  diğer podun `/health` `role` alanının `leader` olmasına kadar geçen süreyi ölçün.
- **Yedek + geri yükleme**: `tests/integration/test_helm_pg_backup.py` betiği gerçek
  Postgres'e karşı çalıştırır, dökümü boş bir veritabanına geri yükler ve tüm
  satırları karşılaştırır. Canlı ortamda ayda bir §5'teki tatbikatı yapın ve süreyi
  kaydedin; RTO hedefi bu ölçümle güncellenir.

## 5. Geri yükleme prosedürü (Helm)

Aşağıda `REL` sürüm adı, `NS` ad alanıdır.

1. **Dökümü seçin ve doğrulayın.** PVC'yi bağlayan geçici bir pod açın:

   ```bash
   kubectl -n NS run pg-restore --rm -it --image=postgres:16-alpine \
     --overrides='{"spec":{"securityContext":{"runAsUser":70,"fsGroup":70},
       "containers":[{"name":"pg-restore","image":"postgres:16-alpine",
       "stdin":true,"tty":true,"command":["sh"],
       "volumeMounts":[{"name":"b","mountPath":"/backup"}]}],
       "volumes":[{"name":"b","persistentVolumeClaim":{"claimName":"REL-vigil-backup"}}]}}'
   # pod içinde:
   cd /backup && cat LATEST && sha256sum -c "$(cat LATEST).sha256"
   ```

   Nesne deposundan alınacaksa `aws s3 cp s3://<bucket>/<prefix>/<dosya> .`
   ve aynı `sha256sum -c` kontrolü.
2. **Yazanları durdurun**: `kubectl -n NS scale statefulset/REL-vigil-daemon
   --replicas=0` ve `deployment/REL-vigil-backend`, `llm-worker`,
   `agent-worker`, `agent-serve` için `--replicas=0`.
3. **Geri yükleyin** (pod içinde, `PGHOST/PGUSER/PGPASSWORD` ayarlı):

   ```bash
   pg_restore --clean --if-exists --no-owner --exit-on-error \
     -d deeptempo_soc "/backup/$(cat /backup/LATEST)"
   ```

   Daha güvenli seçenek: önce yeni bir veritabanına (`createdb restore_check`)
   geri yükleyip satır sayılarını kontrol edin, sonra asıl veritabanına uygulayın.
4. **Doğrulayın**: `psql -c "SELECT count(*) FROM findings"` vb. beklenen
   değerlerle karşılaştırın.
5. **Başlatın**: `helm upgrade REL … --reuse-values` (db-init kancası şemayı
   tamamlar) veya ölçeklemeyi eski değerlerine döndürün. Daemon için iki kopya
   geri gelir; biri lider olur.

Geri yükleme, döküm anından sonraki tüm verileri siler; RPO bu andır.

## 6. Docker Compose (tek kutu)

Compose kurulumunda daemon tek süreçtir (`DAEMON_LEADER_ELECTION_ENABLED=false`);
yedekler `python -m core.backup` (restic, şifreli, `backups.json` zamanlaması)
ile alınır ve geri yüklenir. İkinci bir daemon çalıştırmak isteyen kurulumlar
seçimi açıp aynı veritabanına iki daemon bağlayabilir; aynı kurallar geçerlidir.
