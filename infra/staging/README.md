# AutoSecOps staging — tek VM, k3s + Helm, her gece `main`

Bu klasör, AutoSecOps'u tek bir Ubuntu VM'de **staging** olarak çalıştırır:
k3s üzerinde `infra/helm/vigil` şeması, her gece `main`'den yeniden kurulum,
demo veri, değerlendirme korpusunun yeniden oynatılması (replay) ve küme
içinde Ollama'da çalışan küçük bir yerel model (varsayılan `qwen2.5:1.5b`).
Bulut API anahtarı gerekmez; hiçbir gizli değer depoya girmez.

## Önkoşullar

| | En az | Önerilen |
|---|---|---|
| İşletim sistemi | Ubuntu 22.04 LTS | Ubuntu 24.04 LTS |
| vCPU / RAM | 4 / 12 GB | 8 / 16 GB |
| Disk | 60 GB | 100 GB (imajlar + model + PV) |
| Ağ | 80/tcp açık (konsol), dışarıya HTTPS (GitHub, Docker Hub, get.k3s.io, get.helm.sh, ollama.com) | |

Depo özelse VM'ye salt okunur bir **deploy key** ekleyin ve
`STAGING_REPO_URL`'yi SSH adresi yapın (`git@github.com:SingularityRD/autosecops2.git`).

## Kurulum (bir kez)

```bash
git clone https://github.com/SingularityRD/autosecops2.git /tmp/autosecops
sudo DRY_RUN=1 /tmp/autosecops/infra/staging/bootstrap.sh   # önce planı görün
sudo /tmp/autosecops/infra/staging/bootstrap.sh
sudo systemctl start autosecops-staging-nightly.service       # ilk kurulumu hemen başlat
journalctl -fu autosecops-staging-nightly.service
```

`bootstrap.sh` **idempotenttir**: her adım önce mevcut durumu denetler, yalnızca
eksik ya da yanlış olanı değiştirir; ikinci çalıştırma hiçbir şeyi bozmaz.
Yaptıkları:

1. apt paketleri: `curl git jq python3 openssl docker.io` (imaj kurulumu için Docker).
2. **k3s** (sabit `K3S_VERSION`, Traefik ingress ve local-path depolama dahil);
   kubeconfig `0600`, yalnızca root okur.
3. **Helm** (sabit `HELM_VERSION`; tarball `sha256sum` ile doğrulanır).
4. İsteğe bağlı **yerel imaj kayıt defteri** (`STAGING_LOCAL_REGISTRY=1`):
   `127.0.0.1:5000`'de `registry:2` ve k3s `registries.yaml` aynası. Kapalıyken
   (varsayılan) imajlar doğrudan k3s containerd'ye aktarılır.
5. Depo kopyası: `/opt/autosecops-staging/src` (gece kurulumu bunu günceller).
6. `/etc/autosecops-staging/` (`0700`), dosyalar `0600`, **VM'de üretilir, asla üzerine yazılmaz**:
   - `staging.env` — gizli olmayan ayarlar (`staging.env.example`'dan kopya; düzenleyin)
   - `secrets.yaml` — Helm değerleri: `secrets.postgresPassword`, `secrets.jwtSecretKey`, `secrets.agentInternalToken` (rastgele)
   - `admin.env` — ilk yönetici hesabı (`STAGING_ADMIN_USER/EMAIL/PASSWORD`, parola rastgele)
7. systemd: `autosecops-staging-nightly.timer` (her gece 02:30 UTC ±15 dk) ve
   `autosecops-staging-replay.timer` (05:00 UTC ±10 dk), ikisi de `Persistent=true`.

Konsola giriş: `http://<STAGING_HOST>/`, kullanıcı ve parola
`/etc/autosecops-staging/admin.env` içinde (`sudo cat` ile okuyun).
`STAGING_HOST` için DNS kaydı yoksa `203.0.113.7.sslip.io` gibi IP tabanlı bir ad kullanın.

## Gece kurulumu (`nightly.sh`)

`autosecops-staging-nightly.service` root olarak çalıştırır; elle de çalışır.

| Adım | Ne yapar |
|---|---|
| update | `git fetch` + `reset --hard origin/main` + `git clean`; ardından **güncellenmiş** `nightly.sh --no-update` ile kendini yeniden başlatır |
| build | `Dockerfile.{backend,daemon,agent}` → `<kayıt>/autosecops/vigil-<bileşen>:<commit 12 hane>`; yerel kayıt defterine `push` ya da `k3s ctr images import` |
| chart | `helm dependency build`, `helm lint`, `helm template` (şablon hatası kurulumdan önce yakalanır) |
| llm | `manifests/llm.yaml`: Ollama (PVC'li) + Bifrost (yalnızca Ollama sağlayıcısı), ikisi de yalnızca ClusterIP; `ollama pull $STAGING_LOCAL_MODEL` |
| helm | `helm upgrade --install --atomic --wait` (`values-staging.yaml` + `/etc/autosecops-staging/secrets.yaml` + imaj etiketleri + `STAGING_HOST`); başarısızsa Helm önceki sürüme döner |
| register-model | `lib/register_local_model.py` backend pod'unda: Bifrost katalog eşitlemesi, `bifrost-ollama` sağlayıcısı varsayılan ve `default_model=$STAGING_LOCAL_MODEL`; daemon ve llm-worker yeniden başlatılır |
| smoke | `smoke.sh` (aşağıda) |
| seed | `seed-demo.sh` (aşağıda) |

Sonuç `/var/lib/autosecops-staging/last-run.json` dosyasına yazılır
(`result`, `step`, `sha`, `smoke`); herhangi bir adım başarısızsa çıkış kodu
sıfırdan farklıdır ve systemd birimi `failed` görünür
(`systemctl --failed`). Aynı commit zaten yeşil kurulduysa yeniden kurulmaz
(`STAGING_FORCE=1` ile zorlanır), duman testi yine çalışır. Aynı anda tek iş
çalışır (`flock`, replay ile ortak kilit).

Staging değerleri bilerek üretimden farklıdır: kimlik doğrulama **açık**
(`DEV_MODE=false`), **müdahale eylemleri kapalı** (`DAEMON_AUTO_RESPONSE=false`,
`DAEMON_DRY_RUN=true`, Slack/PagerDuty kapalı) — demo/replay verisi hiçbir
izolasyon/engelleme tetiklemez; TLS yok (`VIGIL_COOKIE_SECURE=false`); her
bileşenden bir kopya.

## Duman testi (`smoke.sh`)

```bash
# ingress üzerinden (gece kurulumu kendi port-forward'ını açar)
sudo STAGING_BASE_URL=http://autosecops-staging.local /opt/autosecops-staging/src/infra/staging/smoke.sh
```

1. `GET /api/health` ve `/api/health/ready`: `status=healthy`, `auth_bypassed=false`
2. Boş kurulumda ilk yönetici (`POST /api/auth/bootstrap`), sonra `POST /api/auth/login`
3. Tek bulgu yükleme (`POST /api/ingest/ingest-string`, `smoke-<zaman>-<rastgele>`)
4. Geri okuma (`GET /api/v1/findings/{id}`)
5. Daemon'un geri doldurma taraması bulguyu yerel modelle triage edene kadar
   bekleme (`ai_enrichment.ai_triage`; en çok `SMOKE_TRIAGE_TIMEOUT` sn)

Son satır `SMOKE: PASS` ya da `SMOKE: FAIL <adım>`. Parola ve belirteç komut
satırına hiç yazılmaz (gövde stdin'den, `Authorization` başlığı curl
yapılandırmasından gider).

## Demo veri (`seed-demo.sh`)

`eval/corpus/v1`'in `$DEMO_SUITES` bölümlerinden ilk `$DEMO_LIMIT` uyarı,
`demo-` önekli sabit kimliklerle yüklenir. Kimlikler sabit olduğundan ikinci
çalıştırma bir şey eklemez (`SEED: imported=0 skipped=N`). Etiketler (`labels`,
`meta`) VM'den çıkmaz; yalnızca `alert` gönderilir.

## Replay (`replay.sh`)

Gece kurulumundan sonra `$REPLAY_SUITES` (varsayılan `test,injection`)
bölümlerinden ilk `$REPLAY_LIMIT` uyarı, çalışmaya özgü `r<yyMMddHHmm>-`
önekiyle **yeni bulgu** olarak yüklenir; daemon bunları yerel modelle triage
eder. `$REPLAY_WAIT_MINUTES` dakika beklenir, sonra `lib/replay_report.py`
her bulgunun triage'ını etiketle karşılaştırır (evalkit `legacy-v1` eşlemesi:
`isolate/block/investigate → malicious`, `dismiss/monitor → benign`, diğerleri
`inconclusive`, triage yoksa `pending`).

Rapor: `/var/lib/autosecops-staging/replay/<etiket>/report.json`
(`coverage`, `decided_accuracy`, `false_benign`, karışıklık matrisi, vaka
listesi); en sonuncusu `replay/latest.json`. `REPLAY_MIN_COVERAGE` (0–1)
verilirse kapsam bunun altında kaldığında birim `failed` olur.

Bu sayılar küçük bir CPU modelinin **staging'deki** davranışını izlemek
içindir; model kalitesinin resmî ölçümü `python -m evalkit` ile yapılır
(bkz. `evalkit/README.md`).

## Ayarlar

`/etc/autosecops-staging/staging.env` (şablon: `staging.env.example`):

| Değişken | Varsayılan | Anlamı |
|---|---|---|
| `STAGING_REPO_URL` | `https://github.com/SingularityRD/autosecops2.git` | izlenen depo |
| `STAGING_BRANCH` | `main` | izlenen dal |
| `STAGING_HOST` | `autosecops-staging.local` | Traefik ingress ana makine adı |
| `STAGING_LOCAL_MODEL` | `qwen2.5:1.5b` | Ollama modeli |
| `STAGING_LOCAL_REGISTRY` | `0` | `1`: `127.0.0.1:5000` kayıt defteri |
| `STAGING_NAMESPACE` / `STAGING_RELEASE` | `autosecops-staging` / `autosecops` | ad alanı / Helm sürümü |
| `STAGING_FORCE` | `0` | aynı commit'i yeniden kur |
| `DEMO_SUITES` / `DEMO_LIMIT` | `dev` / `40` | demo veri |
| `REPLAY_SUITES` / `REPLAY_LIMIT` | `test,injection` / `25` | replay kapsamı |
| `REPLAY_WAIT_MINUTES` / `REPLAY_MIN_COVERAGE` | `60` / `0` | replay bekleme / eşik |
| `SMOKE_TRIAGE_TIMEOUT` | `900` | triage için en çok bekleme (sn) |

Ortam değişkeniyle ayrıca: `K3S_VERSION` (`v1.31.4+k3s1`), `HELM_VERSION`
(`v3.16.4`), `STAGING_HELM_TIMEOUT` (`20m`), `SMOKE_SKIP_TRIAGE=1` (modelsiz
kutuda triage adımını atla), `DRY_RUN=1` (yalnız `bootstrap.sh`: plan yaz).

## Sorun giderme

```bash
sudo cat /var/lib/autosecops-staging/last-run.json
sudo journalctl -u autosecops-staging-nightly.service -n 200 --no-pager
sudo kubectl -n autosecops-staging get pods
sudo kubectl -n autosecops-staging logs statefulset/autosecops-daemon --tail=100
sudo kubectl -n autosecops-staging exec deploy/ollama -- ollama list
sudo helm -n autosecops-staging history autosecops
```

- **Triage gelmiyor**: daemon günlüğünde `No LLM provider configured` → register
  adımı başarısız; `nightly.sh --no-update` ile `STAGING_FORCE=1` yeniden deneyin.
  Model CPU'da yavaşsa `SMOKE_TRIAGE_TIMEOUT`'u artırın ya da daha küçük model
  (`qwen2.5:0.5b`) seçin.
- **Giriş 429**: `/api/auth/login` dakikada 5 istekle sınırlı; bir dakika bekleyin.
- Zamanlayıcıyı durdurmak: `sudo systemctl disable --now autosecops-staging-nightly.timer autosecops-staging-replay.timer`.

## Testler (VM olmadan)

```bash
python -m pytest -q tests/unit/staging
shellcheck -x infra/staging/*.sh infra/staging/lib/*.sh
```

Testler betikleri sahte `git`/`docker`/`helm`/`kubectl`/`k3s` ikilileri ve
sahte bir AutoSecOps API'si (`tests/unit/staging/fake_api.py`) ile uçtan uca
çalıştırır; `values-staging.yaml`'daki her anahtarın şemanın `values.yaml`'ında
bulunduğunu denetler (Helm yanlış yazılmış anahtarı sessizce yok sayar).
Gerçek `helm template` doğrulaması VM'de `nightly.sh`'in `chart` adımında yapılır.
