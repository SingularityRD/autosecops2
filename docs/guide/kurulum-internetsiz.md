# İnternetsiz (air-gapped) kurulum kılavuzu

> **English summary.** How to install AutoSecOps where the deployment has no
> internet access. A release engineer builds a signed bundle on a connected
> machine (`infra/airgap/build-bundle.sh`); the customer verifies it against a
> public key received out of band and installs it with
> `infra/airgap/install.sh`, which copies the bundle into a private staging
> directory, verifies signature, checksums, file list and archive members on
> that copy, and refuses to run any docker/kubectl/helm command if anything is
> off. Kubernetes installs use `values-airgap.yaml` (local registry, MCP and
> telemetry off, NetworkPolicy egress limited to the cluster); host/Compose
> installs load `airgap.env`. `tests/airgap` proves zero outbound connections.
> The detailed script reference stays in
> [infra/airgap/README.md](../../infra/airgap/README.md).

Bu kılavuz, kurulumu baştan sona bir kontrol listesi olarak anlatır. Her betiğin
tüm seçenekleri ve hata iletileri için ayrıntılı başvuru kaynağı
[infra/airgap/README.md](../../infra/airgap/README.md)'dir; burada yalnızca
müşteri ortamında izlenecek sıra, kararlar ve kurulum sonrası sertleştirme vardır.

## 1. Süre ve roller

| Adım | Kim | Nerede | Süre (hedef) |
|---|---|---|---|
| İmzalama anahtarı (bir kez) | sürüm mühendisi | imzalama makinesi | — |
| Paketi üretme | sürüm mühendisi | internetli derleme makinesi | 10–20 dk |
| Aktarım | müşteri | onaylı aktarım yolu (veri diyotu, onaylı medya) | müşteri sürecine bağlı |
| Doğrulama | müşteri kurulum mühendisi | hedef ortam | 2–5 dk |
| Kurulum | müşteri kurulum mühendisi | hedef ortam | ~10 dk |
| Kurulum sonrası ayarlar | müşteri yöneticisi | konsol + küme | ~5–15 dk |

Paket elde olduğunda hedef süre **30 dakikanın altıdır**. Bu bir hedeftir, ölçülmüş
bir değer değildir. `tests/unit/airgap/test_airgap_bundle.py` betiklerin doğru
davrandığını çevrimdışı sınar, süreyi ölçmez. Gecelik staging ortamı
(`infra/staging/`) `main`'i her gece k3s'e kurup duman testi yapar. Ancak internetsiz
paket yolunu kullanmaz ve kurulum süresini ölçmez. Kurulum gününde adımların
sürelerini kaydetmenizi öneririz.

## 2. Ön koşullar

**Hedef ortam (internetsiz):**

- Kubernetes ≥ 1.25 ve NetworkPolicy uygulayan bir CNI (Calico, Cilium …). Politika
  uygulamayan bir CNI'da egress kısıtı **kâğıt üzerinde kalır**.
- Düğümlerin çekebildiği yerel bir OCI kayıt defteri (Harbor, `registry:2`) ya da
  her düğüme `--loader ctr` ile aktarım.
- Kurulum makinesinde: `bash`, `sha256sum`, `openssl`, `kubectl`, `helm`,
  `docker` veya `ctr`.
- Varsayılan StorageClass (Postgres, Redis, Bifrost, Ollama birimleri).
- Ollama için model boyutu + ~2 GB disk; tercihen GPU düğümü.
- Paketin bir kopyası kadar boş `$TMPDIR` alanı (yükleyici paketi önce oraya kopyalar).

**Bant dışı alınacaklar (paketle birlikte değil):**

- İmza açık anahtarı (`autosecops-airgap.pub`) ve parmak izi. Parmak izini sürüm
  mühendisiyle telefonda ya da imzalı yazıyla karşılaştırın:

  ```bash
  openssl pkey -pubin -in autosecops-airgap.pub -outform DER | sha256sum
  ```

## 3. Paketi üretme (sürüm mühendisi)

İmzalama anahtarı yalnızca imzalama makinesinde (tercihen HSM/akıllı kart ya da
şifreli kasa) durur; paketin içinde hiçbir anahtar yoktur. Anahtar üretimi ve
sızma durumunda yapılacaklar: [infra/airgap/README.md](../../infra/airgap/README.md) §1.

Uygulama imajları yerelde derlenmez. Pakete, `v<sürüm>` etiketiyle `release.yml`'nin
GHCR'a yayımladığı imzalı imajlar girer:
`ghcr.io/singularityrd/autosecops-{backend,daemon,agent}:<sürüm>` (Helm ve paket
varsayılanı). Paketi üretmeden önce GitHub Release dosyalarını indirip
`sh verify-release.sh --dir release-<sürüm> --version <sürüm>` ile doğrulayın
(`RESULT: VERIFIED`; bkz. [docs/release/dogrulama.md](../release/dogrulama.md)),
paketi ürettikten sonra çekilen imajların kimliğini imzalı `images.json`'daki
`config_digest` ile karşılaştırın
([infra/airgap/README.md](../../infra/airgap/README.md) §2, adım 3). Etiket
itilmeden bu imajlar yoktur; paket üretimi `not found` ile durur.

```bash
# 1) Önce neyin pakete gireceğini görün (hiçbir şey çekilmez)
infra/airgap/build-bundle.sh --dry-run --version 2.0.0

# 2) Paketi üretin (kural depoları ~/security-detections altında önceden klonlu olmalı)
AIRGAP_PYTHON=/path/to/venv/bin/python \
infra/airgap/build-bundle.sh --version 2.0.0 \
  --key ~/keys/autosecops-airgap.key \
  --ollama-model llama3.1:8b \
  --out dist/airgap
```

Sonuç: `dist/airgap/autosecops-airgap-<sürüm>.tar`. Pakette imajlar (OCI arşivleri),
Helm grafiği, `values-airgap.yaml`, `airgap.env`, `k8s/llm-stack.yaml` (Bifrost +
Ollama), model ağırlıkları, kural korpusları, çevrimdışı belgeler, `install.sh`,
`manifest.json`, `SHA256SUMS` ve imzası bulunur. Kural ve model arşivlerine yalnızca
normal dosya ve dizin girer; ağaç dışına çıkan ya da kırık bir sembolik bağ derlemeyi
durdurur.

Lisanslar da paketle gider (Apache-2.0 §4): `licenses/` dizininde AutoSecOps'un
`LICENSE`, `NOTICE` ve `THIRD_PARTY_LICENSES` dosyaları; her kural korpusunun yanında
kendi lisans dosyası (`rules/<klon>.LICENSE`; Sigma DRL 1.1, Elastic Elastic License
2.0) ile `rules/README-LICENSES.md` ve `rules/DRL-1.1.md`; Llama modeli pakete
girdiyse `models/LLAMA_NOTICE.txt` ("Built with Llama", Llama 3.1 Community License
ve Kabul Edilebilir Kullanım Politikası). Paketi üçüncü bir tarafa dağıtmadan önce bu
koşulları okuyun. Redis imajı BSD lisanslı 7.2 hattına özetle (`@sha256:…`)
sabitlenmiştir; derleme o özeti çeker.

## 4. Hedef ortamda doğrulama

1. Dış tar'ı **açmadan önce listeleyin**; yalnızca `autosecops-airgap-<sürüm>/`
   altında normal dosya ve dizin olmalı:

   ```bash
   tar -tvf autosecops-airgap-2.0.0.tar | less
   ```

2. Yalnızca sizin yazabildiğiniz **yeni, boş** bir dizine açın:

   ```bash
   install -d -m 0700 /opt/autosecops-kurulum
   tar -xf autosecops-airgap-2.0.0.tar -C /opt/autosecops-kurulum --no-same-owner
   cd /opt/autosecops-kurulum/autosecops-airgap-2.0.0
   ```

3. Yükleyicinin kendisine güvenmeden önce imzayı elle doğrulayın:

   ```bash
   openssl pkeyutl -verify -pubin -inkey /guvenli/yol/autosecops-airgap.pub \
     -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
   sha256sum --check --strict SHA256SUMS
   ```

4. Tam doğrulama:

   ```bash
   ./install.sh verify --pubkey /guvenli/yol/autosecops-airgap.pub
   ```

`install.sh` paketi önce `$TMPDIR` altında yalnız kendisinin okuyabildiği bir
hazırlık dizinine (`mktemp -d`, 0700) kopyalar ve tüm denetimleri **bu kopya
üzerinde** yapar; kurulum da yalnızca bu kopyadan yapılır. Böylece "bundle verified"
iletisinden sonra paket dizininde yapılan bir değişiklik kuruluma yansımaz.
Aşağıdakilerden herhangi biri olursa `REFUSED: ...` ile durur ve hiçbir
`docker`/`ctr`/`kubectl`/`helm` komutu çalıştırmaz:

- imza yok ya da geçersiz;
- özet tutmuyor ya da dosya eksik; güvensiz yol;
- `SHA256SUMS`'ta olmayan dosya, bağ, FIFO, soket, aygıt ya da dizin;
- `manifest.json`/`images.tsv` ile çelişki;
- kural/model arşivinde normal dosya ve dizin dışında üye.

Paketin içinde bir açık anahtar olsa bile kullanılmaz; yalnızca `--pubkey` ile
verdiğiniz anahtar geçerlidir.

İmza paketin tamamını kapsar; paketteki konteyner imajları tek tek imzalı değildir
ve bir SBOM eşlik etmez (Planlı — `wp/w4.7-release`, bu sürümde yok).

## 5. Kurulum (Kubernetes)

```bash
./install.sh install \
  --pubkey /guvenli/yol/autosecops-airgap.pub \
  --registry harbor.musteri.local/autosecops \
  --namespace autosecops --release autosecops \
  --rules-into-backend \
  -- -f musteri-values.yaml
```

- Önce `--dry-run` ile neler yapılacağını görün (doğrulama yine yapılır).
- Kayıt defteri yoksa `--loader ctr` ile her düğümde çalıştırın; tek düğümlü Docker
  ortamında `--loader docker`.
- `--` sonrasındaki argümanlar `helm upgrade --install`'a geçer. Müşteriye özgü
  değerleri (sırlar, ingress, kaynak sınırları) ayrı bir `musteri-values.yaml`
  dosyasında tutun; `values-airgap.yaml`'ı düzenlemeyin.
- Kural korpusları: `--rules-into-backend` backend pod'unun `~/security-detections`
  dizinine açar; o dizin kalıcı değilse pod yeniden başladığında tekrarlayın ya da
  `--rules-dir` ile kalıcı bir birime açın.

### `musteri-values.yaml` içinde mutlaka verilecekler

| Değer | Neden |
|---|---|
| `secrets.existingSecret` ya da `secrets.externalSecret.enabled` | JWT anahtarı, Postgres parolası, `AGENT_INTERNAL_TOKEN` gibi sırlar grafikte düz değer olarak durmasın; ExternalSecrets Operator ile kasa (Vault vb.) desteklenir |
| `secrets.jwtSecretKey` (ya da aynı anahtarı taşıyan Secret) | `DEV_MODE=false` iken backend `JWT_SECRET_KEY` olmadan açılmaz |
| `secrets.agentInternalToken` | Ajan katmanının `/internal` uçlarına tek kimlik doğrulaması; boşsa iş akışları 503 alır |
| `secrets.postgresPassword` | Varsayılan değer (`change-me-before-production`) üretimde kullanılmamalı |
| `stateDirectory.volume` | Varsayılan `emptyDir`'dir; konsoldan girilen sırlar (`secrets.enc`) ve `master.key` pod yeniden başlayınca kaybolur. Kalıcı ReadWriteMany birim verin ya da tüm kimlik bilgilerini Secret ile sağlayın |
| `evidence.persistence` | Vaka kanıt dosyalarının kalıcı birimi; `values-airgap.yaml`'da **kapalıdır**, bu durumda kanıt dosyaları pod yeniden başlayınca kaybolur. Kümede ReadWriteMany sağlayan bir StorageClass varsa `enabled: true`, `accessModes: [ReadWriteMany]`, `storageClassName: <sınıf>` verin. `ReadWriteOnce` birden çok pod bağladığı için reddedilir (bkz. [yönetici kılavuzu](yonetici-kilavuzu.md#kubernetes)) |
| `networkPolicies.egress.extraCIDRs` | Kümenin dışındaki şirket içi hedefler (SIEM, EDR, güvenlik duvarı yönetim arayüzü, NodeLocal DNS `169.254.20.10/32`) |
| `networkPolicies.daemon.webhookAllowFrom` | Daemon'un webhook portuna alarm itebilecek kaynak CIDR'leri; boşsa yalnız küme içi |
| `caBundle.existingSecret` | TLS denetleyen bir vekil sunucu ya da kurum içi CA varsa |
| `backup.enabled` ve `backup.persistence` / `backup.objectStore` | Veritabanı yedek CronJob'u varsayılan kapalıdır; dökümü şifrelemez, şifreli bir birim ya da nesne deposu verin (bkz. [yönetici kılavuzu](yonetici-kilavuzu.md#kubernetes)) |

Daemon Helm'de varsayılan olarak iki kopya çalışır (`daemon.leaderElection.enabled`);
yalnızca biri liderdir. Ayrıntı: [docs/operations/rpo-rto.md](../operations/rpo-rto.md).

`values-airgap.yaml`'ın kapattıkları (yerel kayıt defteri, uzak MCP ve kendi MCP
yüzeyi, OTEL, Slack/PagerDuty, bulut sandbox'ları, Kafka, Darktrace, Medic,
`DEMO_MODE`, e-postanın loga gitmesi, `networkPolicies.egress.inClusterOnly: true`)
için tablo: [infra/airgap/README.md](../../infra/airgap/README.md#values-airgapyaml-ne-kapatır).

## 6. Kurulum (tek sunucu: host üzerinde ya da Docker Compose)

Kubernetes dışı kurulumlarda aynı kapatmalar `infra/airgap/airgap.env` profilindedir
ve normal yapılandırmanın **üstüne** yüklenir:

```bash
# Host üzerinde
set -a; . infra/airgap/airgap.env; set +a; ./start.sh
```

Compose'da her servise `env_file: [../airgap/airgap.env]` ekleyin ve iç adresleri
(`127.0.0.1`) servis adlarıyla değiştirin (`bifrost`, `backend` …). Profilin anahtar
grupları:

| Grup | Anahtarlar | Değer |
|---|---|---|
| İzin listesi | `AIRGAP_EGRESS_ALLOWLIST` | boş = bu makine dışında hiçbir şey |
| Açılış davranışı | `DEMO_MODE`, `MCP_AUTO_CONNECT_ON_STARTUP` | `false` |
| Telemetri | `VIGIL_OTEL_ENABLED`, `SENTRY_DSN`, `OTEL_EXPORTER_OTLP_ENDPOINT` | kapalı / boş / loopback |
| İç servisler | `POSTGRES_HOST`, `REDIS_URL`, `BIFROST_URL`, `OLLAMA_URL`, `AGENT_URL`, `VIGIL_RUNS_URL` … | loopback ya da servis adı |
| Model sağlayıcıları | `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_APPLICATION_CREDENTIALS`, `ANTHROPIC_BASE_URL` | **boş**: bulut sağlayıcıya hiç gidilmez |
| Dış satıcı alt sistemleri | `KAFKA_ENABLED`, `DARKTRACE_ENABLED`, `DAEMON_ESCALATION_ENABLED`, `DAEMON_SLACK_ENABLED`, `DAEMON_PAGERDUTY_ENABLED`, `JOE_SANDBOX_ENABLED`, `CAPE_SANDBOX_ENABLED`, `HYBRID_ANALYSIS_ENABLED`, `ANYRUN_ENABLED`, `VIGIL_MEDIC_ENABLED` | `false` |
| E-posta | `SMTP_HOST`, `VIGIL_EMAIL_BACKEND` | boş, `console` (e-posta loga yazılır) |
| Denetim zaman damgası | `AUDIT_TSA_URL` | boş: imzalı denetim kontrol noktaları için RFC 3161 zaman damgası sunucusuna gidilmez |
| OCR verisi | `TESSDATA_PREFIX` | `eng.traineddata`'nın bulunduğu yerel dizin |
| Paket yöneticileri | `NPM_CONFIG_OFFLINE`, `UV_OFFLINE`, `PIP_NO_INDEX` | açık: MCP alt süreçleri yalnızca yerel önbellekten paket çözer |

Helm profili (`values-airgap.yaml`) ile `airgap.env`'in ortak anahtarlarının aynı
değeri taşıdığı `tests/unit/airgap` testleriyle denetlenir.

## 7. Kurulum sonrası (ilk 15 dakika)

1. Pod'lar ve model:

   ```bash
   kubectl -n autosecops get pods
   kubectl -n autosecops exec deploy/ollama -- ollama list
   ```

2. **İlk yönetici hesabı.** Varsayılan bir yönetici tohumlanmaz. Kullanıcı tablosu
   boşken giriş ekranı ilk hesabı oluşturmayı önerir (`POST /api/auth/bootstrap`);
   bu uç ilk hesap oluştuğu anda kalıcı olarak kapanır. Hemen ardından bu hesapta
   MFA'yı açın (bkz. [yönetici kılavuzu](yonetici-kilavuzu.md#kimlik-doğrulama)).
3. **Model sağlayıcısı.** Konsolda Ayarlar → AI models altında Bifrost üzerinden
   Ollama modelini (`ollama/<model>`) ekleyip varsayılan yapın. Bulut sağlayıcı
   anahtarları bu ortamda işe yaramaz ve egress politikası tarafından düşürülür.
4. **Müdahale onayını zorunlu kılın.** Düzenlenmiş sektör için önerilen ayar:
   `DAEMON_FORCE_APPROVAL=true` (Helm: `config.DAEMON_FORCE_APPROVAL`). Gerekçe ve
   ayrıntı: [yönetici kılavuzu — otonomi](yonetici-kilavuzu.md#otonomi).
5. **Güvenlik ayarlarını denetleyin:** `DEV_MODE=false` (Helm varsayılanı),
   `VIGIL_CSRF_REPORT_ONLY=false` (kodun varsayılanı yalnızca raporlamadır;
   Helm grafiği ve `env.example` `false` kullanır), `VIGIL_COOKIE_SECURE=true`, TLS'i API'nin önünde
   sonlandırın (ingress).
6. **Yedekleme**: [yönetici kılavuzu — yedekleme](yonetici-kilavuzu.md#yedekleme-ve-geri-yükleme).
7. **İsteğe bağlı:** OIDC SSO ve SIEM aktarımı
   ([yönetici kılavuzu — kimlik doğrulama](yonetici-kilavuzu.md#kimlik-doğrulama),
   [SIEM'e denetim aktarımı](yonetici-kilavuzu.md#sieme-denetim-aktarımı)). FIPS 140-3
   modu FIPS etkin ayrı bir imaj ister; imaj hazırlığı ve bilinen boşluklar
   [docs/fips.md](../fips.md)'dedir. `FIPS_MODE=true` ile FIPS sağlayıcısı olmayan
   bir imajda süreçler başlamaz (çıkış kodu 78).

## 8. Sıfır egress'i kanıtlama

Kurulumdan bağımsız olarak, ürünün air-gap profiliyle dışarı bağlanmadığı iki
katmanda test edilir ve CI'da (`.github/workflows/airgap.yml`) her PR'da koşar:

```bash
# Statik envanter: koddaki her dış bağlantı noktası listelenmiş ve profilde kapalı
pytest tests/airgap/test_egress_inventory.py --no-cov

# Çalışma zamanı: API, daemon ve LLM worker gerçek akışlarda tek bir dış bağlantı denemesi yapmıyor
pytest tests/airgap/test_runtime_egress.py --no-cov

# Tarayıcının bulduklarını görmek
python -m tests.airgap.egress_scan
```

Bu testlerin kapsamı ve sınırları (yalnızca Python soketleri; Bifrost, Node ajan
katmanı ve tarayıcı statik taranır) [tests/airgap/README.md](../../tests/airgap/README.md)
içindedir. Ağ düzeyindeki kesin önlem kümedeki NetworkPolicy'dir; müşteri ortamında
ayrıca çevre güvenlik duvarında çıkışı kapatmanızı öneririz.

Profil uygulandığında bile operatör eylemiyle dışarı çıkabilecek noktalar
(envanterde sınıflandırılmış):

- Bir entegrasyon kimlik bilgileriyle etkinleştirildiğinde onun hedefi (SIEM, EDR,
  güvenlik duvarı). Hedef küme içinde ya da `extraCIDRs`/`AIRGAP_EGRESS_ALLOWLIST`
  listesinde olmalıdır.
- Kural deposu senkronu (`git clone` / `git fetch`): yalnızca `settings.write` sahibi
  bir operatör `https://` kaynak ekler/senkronlarsa. İç ya da özel adrese çözülen
  git sunucusu reddedilir; ağ içi bir git sunucusu için
  `VIGIL_DETECTION_GIT_ALLOWED_CIDRS`'e yalnızca onun aralığını yazın. Air-gap'te
  yerel yol kaynakları kullanın.
- SIEM'e denetim aktarımı: yalnızca `settings.write` sahibi bir operatör aktarımı
  açıp bir syslog ya da HTTPS hedefi tanımlarsa. Hedef küme içinde ya da izin
  listesinde olmalıdır; metadata adresleri reddedilir.
- OIDC SSO: tanımlanmış bir sağlayıcının keşif belgesi, JWKS ve belirteç ucu API'den
  çağrılır. Air-gap'te ağ içi bir IdP kullanın ve adresini izin listesine ekleyin.
- Denetim kontrol noktası zaman damgası: yalnızca operatör `AUDIT_TSA_URL`'i
  doldurursa her kontrol noktası için bu adrese bir RFC 3161 isteği gider.
  Air-gap'te boş bırakın ya da ağ içi bir TSA verip izin listesine ekleyin.
- `tiktoken` kurulursa ilk kullanımda BPE dosyası indirme denemesi (bilinen açık,
  `known-gap`; paket gereksinimlerinde yoktur).
- `security-detections` MCP sunucusu `npx` ile başlar; paket kurulum imajında
  önbellekte olmalıdır (`NPM_CONFIG_OFFLINE=true` ağ yerine hızlı hata verir).

## 9. Güncelleme ve geri alma

- Yeni sürüm aynı yolla (yeni paket → doğrula → `install.sh install`) kurulur;
  Helm `upgrade --install` yapar.
- Geri alma: `helm rollback <release>`.
- Compose/host kurulumlarında, veritabanının sürümü yeni imajdan geride ise
  `backup-pre-upgrade` servisi kurulumdan önce otomatik bir anlık görüntü alır
  (`python -m core.backup pre-upgrade`; atlamak için `VIGIL_SKIP_PREUPGRADE_BACKUP`).
- 0.7.x sürümünden 2.0'a geçişte veritabanı `scripts/upgrade_database.py` ile
  yükseltilir (ön kontrol, `--dry-run`, `--backup`); yol CI'da gerçek bir 0.7.1
  dökümüyle sınanır. Yükseltme yalnızca ileri yönlüdür, geri dönüş yedeğin geri
  yüklenmesidir. Prosedür: [docs/upgrade-0.7-to-2.0.md](../upgrade-0.7-to-2.0.md).
- Bu sürüme yükseltirken: önceden verilmiş ve kullanılmamış parola sıfırlama
  bağlantıları geçersiz olur (imza SHA-256'ya geçti). `url_safety` artık CGNAT
  100.64.0.0/10 aralığını reddeder; şirket içi bir LLM ağ geçidi bu aralıktaysa
  (ör. Tailscale) `LLM_PROVIDER_ALLOWED_CIDRS`'e yazın.
- Helm'de db-init Job'u, hata veren bir SQL dosyasını uygulanmış saymaz; önceki
  sürümlerde uygulanmış sayılmış ama tablosu eksik kalan düzenleyici sayaç
  dosyalarını `helm upgrade` sırasında kendiliğinden yeniden uygular.

## 10. Sorun giderme

Hata iletileri ve çözümleri için [infra/airgap/README.md — Sorun giderme](../../infra/airgap/README.md#sorun-giderme).
