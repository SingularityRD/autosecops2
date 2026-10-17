# İşletim rehberi: boyutlandırma, portlar, bağlantılı kurulum, çıkış

> **English summary.** Sizing starting points (chart requests and limits, not
> measured throughput), the port and firewall matrix, installing the Helm chart on
> a cluster with internet access, and the exit procedure: export, uninstall,
> secure deletion and a destruction record.

Bu belge [internetsiz kurulum kılavuzunun](kurulum-internetsiz.md) ve
[yönetici kılavuzunun](yonetici-kilavuzu.md) tamamlayıcısıdır (W0.47).

## 1. Boyutlandırma

Aşağıdaki sayılar grafiğin varsayılan istek ve sınırlarıdır
(`infra/helm/vigil/values.yaml`). **Ölçülmüş bir hacim taahhüdü değildir:** bu
sürümde alarm hacmine göre ölçülmüş bir kapasite tablosu yoktur. Kendi hacminizi
staging'de [yük ve kaos el kitabıyla](../operations/load-chaos-runbook.md) ölçün;
oradaki hedefler (kural şeridi p95 < 5 sn, küçük model şeridi p95 < 60 sn) bir
kurulumun geçmesi gereken eşiklerdir.

| Bileşen | Kopya | CPU istek / sınır | Bellek istek / sınır | Kalıcı birim |
|---|---|---|---|---|
| Backend (API ve konsol) | 2 | 250m / 1000m | 512Mi / 1Gi | — |
| Daemon (alım, triyaj, orkestratör) | 2 (biri lider) | 500m / 2000m | 1Gi / 4Gi | 10Gi |
| LLM işçisi | 2 | 250m / 1000m | 512Mi / 2Gi | — |
| Ajan işçisi | 1 | 100m / 1000m | 256Mi / 1Gi | — |
| Ajan sunucusu | 1 | 100m / 1000m | 256Mi / 1Gi | — |
| PostgreSQL | 1 | 250m / 2000m | 512Mi / 4Gi | 50Gi |
| Kanıt dosyaları (isteğe bağlı) | — | — | — | 20Gi (ReadWriteMany) |
| Yedek (isteğe bağlı) | — | — | — | 50Gi |

Başlangıç noktaları (ölçülmedi; staging'de doğrulayın):

- **Pilot / POC** (günde birkaç bin alarm, 5–10 analist): varsayılanlar. Toplam
  istek yaklaşık 2 vCPU ve 4 GiB; sınırlara göre 8 vCPU ve 16 GiB ayırın.
- **Üretim** (günde on binlerce alarm): daemon ve LLM işçisi sınırlarını iki
  katına çıkarın, PostgreSQL'i ayrı bir sunucuda ya da yönetilen bir hizmette
  çalıştırın (`postgresql.external.*`), bulgu saklama süresini
  [saklama politikasıyla](yonetici-kilavuzu.md#saklama-ve-imha) sınırlayın.
- **Yerel model** (internetsiz, `OLLAMA_URL`): modelin kendisi kadar bellek ve model
  boyutu + ~2 GB disk; GPU'suz CPU çıkarımı triyajı dakikalara uzatır. Küçük model
  şeridinin p95 hedefini tutturmak için bir GPU düğümü önerilir. Eşzamanlılık:
  `OLLAMA_NUM_PARALLEL` ve `LLM_MAX_CONCURRENT`.
- **Disk:** PostgreSQL büyümesini alarm başına ham olay boyutu belirler. İlk ay
  veritabanı boyutunu (PostgreSQL pg_database_size) izleyip saklama süresiyle çarparak tahmin edin.

## 2. Port ve güvenlik duvarı matrisi

### Kubernetes (Helm)

| Kaynak → Hedef | Port | Protokol | Ne için | Varsayılan |
|---|---|---|---|---|
| Kullanıcı → ingress → backend | 6987 | HTTPS (ingress'te TLS) | Konsol ve REST API | ingress kapalı (`ingress.enabled`) |
| SIEM/EDR → daemon | 8081 | HTTP + bearer | Webhook alımı (`/ingest`, `/ingest/syslog`) | küme içi; dışarıdan `networkPolicies.daemon.webhookAllowFrom` |
| Syslog göndericisi → daemon | 5514 | TCP / TLS, isteğe bağlı UDP | Syslog alımı | kapalı (`daemon.syslog.enabled`) |
| Prometheus → daemon | 9090 | HTTP | Metrikler (yalnız OTEL açıkken) | küme içi |
| kubelet → daemon | 9091 | HTTP | `/health`, `/status` | küme içi |
| Uygulama → PostgreSQL | 5432 | TCP | Veritabanı | küme içi |
| Uygulama → Redis | 6379 | TCP | Kuyruk, oturum | küme içi |
| Backend → ajan sunucusu | 6989 | HTTP + iç belirteç | İş akışları | küme içi |
| Uygulama → Bifrost / Ollama | 8080 / 11434 | HTTP | Model geçidi, yerel model | küme içi |
| Uygulama → SIEM / EDR / güvenlik duvarı | satıcıya göre (çoğunlukla 443) | HTTPS | Alarm çekme, müdahale | `networkPolicies.egress.extraCIDRs` |
| Daemon → SMTP aktarıcısı | 25 / 587 | SMTP (STARTTLS) | Bildirim e-postası | `SMTP_HOST` boş |
| Backend → OIDC sağlayıcısı | 443 | HTTPS | SSO | yapılandırılmadıkça yok |

`networkPolicies.enabled` açıkken giriş kuralları yukarıdaki gibidir; çıkış
(`networkPolicies.egress.inClusterOnly`) yalnız küme içine ve `extraCIDRs`
listesine izin verir. DNS: küme DNS'i (CoreDNS) yeterlidir, dış ad çözümlemesi
gerekmez; NodeLocal DNS kullanıyorsanız `169.254.20.10/32`'yi `extraCIDRs`'e ekleyin.

### Docker Compose (tek sunucu)

`infra/docker/docker-compose.yml` dışarıya yalnızca şunları açar: backend 6987,
daemon 8081 ve 9090; PostgreSQL 5432, Redis 6379, daemon sağlık 9091 ve Bifrost 8080
yalnız `127.0.0.1`'e bağlanır. Syslog dinleyicisini açtıysanız daemon servisine
port eşlemesini kendiniz ekleyin. Konsolu bir ters vekil sunucu (TLS) arkasında
yayımlayın; 6987'yi doğrudan internete açmayın.

### TLS

Konsol TLS'i ingress'te ya da ters vekilde sonlanır. Kurum içi CA ile imzalanmış
sunuculara giden çağrılar için `caBundle.existingSecret` (tüm süreçler) ya da
entegrasyonun "CA Certificate Path" alanı; syslog TLS için `daemon.syslog.tls`.

## 3. Bağlantılı (internete erişen) Helm kurulumu

İnternetsiz kurulum imzalı paketle yapılır (bkz.
[kurulum kılavuzu](kurulum-internetsiz.md#5-kurulum-kubernetes)). İnternete erişen bir
kümede imajlar doğrudan GHCR'dan çekilir:
`ghcr.io/singularityrd/autosecops-{backend,daemon,agent}:<sürüm>`
(`global.imageRegistry`, `global.imageNamespace`). Grafik bu sürümde bir Helm
deposunda yayımlanmaz; sürüm etiketinin kaynak kodundan kurulur.

```bash
git clone --branch v<sürüm> https://github.com/SingularityRD/autosecops2.git
cd autosecops2
helm dependency build infra/helm/vigil   # yalnız Bitnami PostgreSQL/Redis ya da OTEL alt grafikleri açıksa
helm upgrade --install autosecops infra/helm/vigil \
  --namespace autosecops --create-namespace \
  -f musteri-values.yaml
```

- İmaj deposu özelse bir çekme sırrı oluşturup `global.imagePullSecrets` ile verin.
- `musteri-values.yaml` içinde mutlaka verilecekler internetsiz kurulumla aynıdır:
  [tablo](kurulum-internetsiz.md#musteri-valuesyaml-içinde-mutlaka-verilecekler).
- İmza anahtarları (`signingKeys.generate`) ve veri anahtarı (`dataKey.generate`)
  ilk kurulumda üretilir ve korunur; açık anahtarları kurulumdan sonra alın:
  [yönetici kılavuzu](yonetici-kilavuzu.md#imza-anahtarları-kurulumda).
- İlk yönetici kurulum belirteciyle oluşturulur; belirteç backend logundadır
  (bkz. [kurulum sonrası](kurulum-internetsiz.md#7-kurulum-sonrası-ilk-15-dakika)).
- Bulut model sağlayıcısı kullanacaksanız anahtarını konsoldan girin; bu durumda
  bulgu içeriği sağlayıcıya gider (KVKK md. 9 değerlendirmesi kurumundur).

## 4. Çıkış prosedürü

Hizmet sona erdiğinde ya da başka bir ürüne geçerken izlenecek sıra. Her adımın
çıktısını imha tutanağına ekleyin.

### 4.1 Dışa aktarım

1. **Tam yedek:** `python -m core.backup create --repo <depo> --passphrase-file <dosya>`
   (Compose'da `./start.sh backup`). Veritabanının `pg_dump -Fc` dökümü, standart
   PostgreSQL araçlarıyla (`pg_restore`) AutoSecOps olmadan da açılır. Helm'de
   yedek CronJob'u (`backup.enabled`) ya da kendi `pg_dump` işiniz.
2. **Vaka başına kanıt paketi:** `GET /api/cases/{case_id}/evidence-pack` (imzalı,
   AutoSecOps olmadan doğrulanabilir) ve vaka raporu
   `GET /api/cases/{case_id}/report.pdf`.
3. **Bulgular:** `POST /api/findings/export` (izinli ve denetim kaydına yazılır).
4. **Denetim kayıtları:** SIEM aktarımı açıksa kayıtlar zaten SIEM'dedir; değilse
   tam yedek içindedir. Zincir doğrulaması: `python -m core.audit.verify`. Ajan
   defteri arşivi: `GET /api/compliance/retention/agent-ledger/archive`.
5. **İmha tutanakları:** `GET /api/compliance/retention/reports`.

### 4.2 Kaldırma

- **Kubernetes:** `helm uninstall autosecops -n autosecops`. Grafik bazı kaynakları
  bilerek **bırakır** (`helm.sh/resource-policy: keep`): veri anahtarı Secret'ı
  (`<fullname>-data-key`), imza anahtarları Secret'ı, kanıt ve yedek birimleri.
  StatefulSet birimleri (PostgreSQL, Redis, daemon) de silinmez. Kalanları görün ve
  kasıtlı olarak silin:

  ```bash
  kubectl get secret,pvc -n autosecops
  kubectl delete pvc --all -n autosecops        # geri alınamaz
  kubectl delete secret --all -n autosecops     # geri alınamaz
  kubectl delete namespace autosecops
  ```

- **Docker Compose:** servisleri durdurup birimlerini silin
  (`docker compose -f infra/docker/docker-compose.yml down -v`), ardından durum
  dizinini (`VIGIL_DIR`) ve depo kökündeki `.env` dosyasını silin.
- **Masaüstü:** [yönetici kılavuzu](yonetici-kilavuzu.md#kaldırma).

### 4.3 Güvenli silme

- **Anahtar imhası:** konsoldan girilen sırlar ve MFA sırları veri anahtarıyla
  (`VIGIL_DATA_KEY`), Compose'da sır deposu `master.key` ile şifrelidir. Bu
  anahtarların kümede ve kasada **tüm kopyalarını** silmek, şifreli sırları
  yedeklerde de okunamaz kılar.
- **Veritabanı ve birimler:** AutoSecOps veritabanını kendisi şifrelemez. Bulgu,
  vaka ve kanıt içeriği için depolama katmanının silme yöntemi geçerlidir:
  şifreli birimde anahtarın imhası, değilse birimin üzerine yazılması ya da
  fiziksel imha (kurumun ve depolama sağlayıcısının prosedürü).
- **Yedekler:** restic deposunu ve parolasını silin; nesne deposundaki yedeklerin
  sürüm geçmişini (object versioning) de temizleyin.
- **Dış kopyalar:** SIEM'e aktarılmış denetim kayıtları, e-posta ve Teams
  bildirimleri, model sağlayıcısına giden içerik AutoSecOps'un dışındadır; kendi
  saklama kurallarına tabidir.

### 4.4 İmha tutanağı

Tutanakta en az şunlar bulunur: tarih ve saat; kurulumun adı ve sürümü; alınan
dışa aktarımlar ve kime teslim edildiği (özet değerleriyle); silinen kaynakların
listesi (yukarıdaki `kubectl get` çıktısı, silmeden önce ve sonra); anahtar imhasının
yöntemi ve kopyaların yeri; birimlerin silme yöntemi; son
`GET /api/compliance/retention/reports` çıktısı; yapan ve tanık olan kişilerin adı
ve imzası. KVKK kapsamındaki kişisel veriler için tutanak, kurumun Silme, Yok Etme
veya Anonim Hale Getirme Yönetmeliği uyarınca tuttuğu kayıtla birlikte saklanır
(hukuki görüş değildir).
