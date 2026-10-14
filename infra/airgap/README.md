# AutoSecOps — Air-gapped (internet erişimsiz) kurulum

Bu dizin, internete çıkışı olmayan düzenlenmiş ortamlara AutoSecOps kurmak için
gereken her şeyi içerir:

| Dosya | Görevi |
|---|---|
| `build-bundle.sh` | Ağ erişimi olan derleme makinesinde imzalı kurulum paketini üretir |
| `install.sh` | Hedef ortamda paketi **önce doğrular**, sonra imajları yükler ve Helm ile kurar |
| `airgap_images.py` | Helm grafiği + Compose + LLM yığınından imaj listesini çıkarır (ağsız) |
| `values-airgap.yaml` | Air-gap Helm profili: yerel kayıt defteri, uzak MCP/telemetri kapalı, egress yalnızca küme içi |
| `airgap.env` | Air-gap ortam profili (W3.4): host üzerinde (`start.sh`) veya Compose ile kurulumda aynı anahtarları kapatır; `tests/airgap` sıfır egress'i bununla doğrular |
| `k8s/llm-stack.yaml` | Küme içi Bifrost (LLM ağ geçidi) + Ollama (yerel model sunucusu) |

Hedef süre: paket elinizdeyken kurulum **30 dakikanın altında**.

---

## 0. Ön koşullar

**Derleme makinesi (internetli):** bash, Python 3 + PyYAML (repo venv'i yeterli),
`docker`, `openssl` (veya `cosign` / `minisign`), isteğe bağlı `helm`.

**Hedef ortam (internetsiz):**

- Kubernetes ≥ 1.25, NetworkPolicy uygulayan bir CNI (Calico, Cilium, …)
- Küme düğümlerinin çekebildiği yerel bir OCI kayıt defteri (ör. Harbor,
  `registry:2`) — ya da `--loader ctr` ile imajları her düğüme doğrudan aktarma
- Kurulum makinesinde: bash, `sha256sum`, `openssl`, `kubectl`, `helm` ve
  `--loader`'a göre `docker` veya `ctr`
- Varsayılan StorageClass (Postgres, Redis, Bifrost ve Ollama PVC'leri için)
- Ollama için yeterli disk (model boyutu + ~2 GB) ve tercihen GPU düğümü

---

## 1. İmzalama anahtarı (yalnızca sürüm mühendisi, bir kez)

Paketin tek güven kökü imzadır. Varsayılan yöntem OpenSSL Ed25519'dur:

```bash
umask 077
openssl genpkey -algorithm ed25519 -out autosecops-airgap.key   # GİZLİ
openssl pkey -in autosecops-airgap.key -pubout -out autosecops-airgap.pub
```

Anahtar işleme kuralları:

- `autosecops-airgap.key` yalnızca imzalama makinesinde (tercihen HSM/akıllı
  kart ya da şifreli kasada) durur; repoya, pakete veya CI loglarına **asla**
  girmez. Paketin içinde hiçbir anahtar yoktur.
- `autosecops-airgap.pub` müşteriye **paketten ayrı, bant dışı** bir kanaldan
  (imzalı e-posta, müşteri portalı, basılı parmak izi) verilir. Parmak izi:
  `openssl pkey -pubin -in autosecops-airgap.pub -outform DER | sha256sum`
- Anahtar sızarsa: yeni anahtar çiftini üretip yeni açık anahtarı müşterilere
  dağıtın, eski açık anahtarla doğrulanan paketleri geçersiz sayın.

Alternatifler: `cosign generate-key-pair` (cosign.key / cosign.pub, parola
`COSIGN_PASSWORD` ile) veya `minisign -G`. `--sign-method auto` anahtarın
biçiminden yöntemi seçer; seçilen araç kurulu değilse açık bir hatayla durur.
`install.sh` de yöntemi **açık anahtarın biçiminden** seçer (minisign anahtarı →
minisign, PEM Ed25519 → openssl, diğer PEM → cosign; şeffaflık günlüğü
kullanılmaz).

---

## 2. Paketi üretme (derleme makinesi, ~10–20 dk, ağ hızına bağlı)

Önce neyin pakete gireceğini görün — hiçbir şey çekilmez:

```bash
infra/airgap/build-bundle.sh --dry-run --version 2.0.0
```

Çıktı: imaj referansı, paket içindeki arşiv adı ve kaynağı (`helm:backend`,
`compose:postgres`, `llm-stack:ollama` …). İmajlar Helm grafiğinden
(`infra/helm/vigil/values.yaml` + `values-airgap.yaml` ile açık bileşenler),
Compose dosyasından (varsayılan + `daemon` profili) ve `k8s/llm-stack.yaml`
dosyasından sayılır.

Uygulama imajları (`backend`, `daemon`, `agent`): derleme makinesinde derlenmez;
`v<V>` etiketiyle `.github/workflows/release.yml`'nin yayımladığı **imzalı sürüm
imajları** kullanılır: `ghcr.io/singularityrd/autosecops-{backend,daemon,agent}:<V>`
(Helm grafiğinin ve `build-bundle.sh`'ın varsayılanı; `--image-namespace` gerekmez).
Etiket itilmeden bu imajlar yoktur ve derleme `not found` ile durur. Sıra:

1. GitHub Release'teki dosyaları (`SHA256SUMS`, `*.sigstore.json`,
   `autosecops-<V>-images.json`/`.tsv`, `verify-release.sh`, …) indirip doğrulayın:
   `sh verify-release.sh --dir release-<V> --version <V>` → `RESULT: VERIFIED`
   (ayrıntı ve internetsiz güven kökü: [docs/release/dogrulama.md](../../docs/release/dogrulama.md)).
2. Paketi aşağıdaki gibi üretin; `build-bundle.sh` imajları GHCR'dan çeker.
3. Paketi göndermeden önce çekilen her uygulama imajının imzalı listedeki imaj
   olduğunu denetleyin (etiketler değiştirilebilir, özetler değiştirilemez):

   ```bash
   for c in backend daemon agent; do
     docker image inspect --format "$c {{.Id}}" ghcr.io/singularityrd/autosecops-$c:<V>
     jq -r --arg c "$c" '.images[] | select(.component==$c) | .platforms[] | "\(.platform) \(.config_digest)"' \
       release-<V>/autosecops-<V>-images.json
   done   # her imajın Id'si makinenin mimarisindeki config_digest ile aynı olmalı
   ```

   Ayrıntı: [dogrulama.md §4.3](../../docs/release/dogrulama.md). Önceden doğrulanmış
   `docker save` arşivleriniz varsa çekmek yerine `--images-from DIR` verin.

Derleme makinesi bir vekil sunucu (proxy) arkasındaysa model indirmesi
`HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` değerlerini kapsayıcıya geçirir (döngü
adresli bir vekil için `--network host` ile); TLS denetleyen bir vekilin CA'sı
için `AIRGAP_CA_BUNDLE=/yol/ca.pem` verin. Derleme yarıda kalırsa yarım paket
dizini silinir; aynı `--out` ile yeniden çalıştırabilirsiniz.

Kural depoları: `DetectionRulesService`'in klonladığı depolar (SigmaHQ `sigma`,
Splunk `security_content`, Elastic `detection-rules`, KQL
`Hunting-Queries-Detection-Rules`) derleme makinesinde
`~/security-detections/` altında **önceden klonlanmış** olmalıdır; betik ağdan
klonlamaz, yalnızca var olanları tar'lar (yoksa uyarır ve manifest'te `file: null`).

Paketi üretin:

```bash
AIRGAP_PYTHON=/path/to/venv/bin/python \
infra/airgap/build-bundle.sh --version 2.0.0 \
  --key ~/keys/autosecops-airgap.key \
  --ollama-model llama3.1:8b \
  --out dist/airgap
```

Sık kullanılan seçenekler:

| Seçenek | Açıklama |
|---|---|
| `--images-from DIR` | `docker save` arşivlerini çekmek yerine DIR'den al (adlar `--dry-run` çıktısındaki gibi) |
| `--ollama-models-dir ~/.ollama` | Var olan Ollama model deposunu kullan |
| `--skip-ollama-model` | Model ekleme (manifest'te `name/file: null`) |
| `--compose-profiles daemon,medic` | Ek Compose profillerinin imajlarını da ekle |
| `--rules-dir DIR` | Kural klonlarının yeri (varsayılan `~/security-detections`) |
| `--no-tar` | Yalnızca dizin bırak |

Sonuç: `dist/airgap/autosecops-airgap-2.0.0/` ve `dist/airgap/autosecops-airgap-2.0.0.tar`.
İçerik: `images/`, `images.tsv`, `chart/vigil-2.0.0.tgz`, `values-airgap.yaml`,
`airgap.env`, `k8s/llm-stack.yaml`, `models/`, `rules/`, `docs/`, `install.sh`,
`manifest.json`, `SHA256SUMS`, `SHA256SUMS.sig` (veya `.minisig`).

Kural ve model tar'larına yalnızca normal dosya ve dizin girer: klon içindeki bir
dosyaya işaret eden sembolik bağ o dosyanın içeriği olarak, sabit bağlar kopya
olarak yazılır; ağacın dışına çıkan, kırık ya da bir dizine işaret eden bir
sembolik bağ derlemeyi durdurur (derleme makinesinden dosya sızmasın diye).

Tar dosyasını onaylı ortam aktarım sürecinizle (veri diyotu, onaylı medya) taşıyın.

---

## 3. Hedef ortamda doğrulama (~2–5 dk)

Dış tar henüz doğrulanmamıştır (imza içindeki `SHA256SUMS` üzerindedir). Önce
içeriğini listeleyin, sonra **yalnızca sizin yazabildiğiniz boş bir dizine**
açın — var olan bir dizine açmak, içindeki dosyaların üzerine yazılmasına veya
paket dışı dosyaların karışmasına yol açabilir:

```bash
tar -tvf autosecops-airgap-2.0.0.tar | less          # yalnızca autosecops-airgap-2.0.0/ altı,
                                                     # normal dosya (-) ve dizin (d) olmalı
install -d -m 0700 /opt/autosecops-kurulum           # yeni, boş, size ait dizin
tar -xf autosecops-airgap-2.0.0.tar -C /opt/autosecops-kurulum --no-same-owner
cd /opt/autosecops-kurulum/autosecops-airgap-2.0.0
```

Listede `autosecops-airgap-2.0.0/` dışına çıkan, mutlak ya da `..` içeren bir
yol veya bağ (`l`, `h`) görürseniz paketi kullanmayın.

**Önce yükleyicinin kendisini doğrulayın** — `install.sh` paketin içinden gelir;
ona güvenmeden önce imzayı elle kontrol edin:

```bash
openssl pkeyutl -verify -pubin -inkey /guvenli/yol/autosecops-airgap.pub \
  -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig      # "Signature Verified Successfully"
sha256sum --check --strict SHA256SUMS                # hepsi "OK"
```

Ardından tam doğrulama:

```bash
./install.sh verify --pubkey /guvenli/yol/autosecops-airgap.pub
```

`install.sh` paket dizinini yerinde kullanmaz: her dosyayı önce `$TMPDIR`
altında yeni, yalnızca kendisinin okuyabildiği (`mktemp -d`, 0700) bir hazırlık
dizinine kopyalar, imzayı ve özetleri **bu kopya üzerinde** doğrular ve imajları,
grafiği, kuralları ve modeli **yalnızca bu kopyadan** yükler. "bundle verified"
mesajından sonra paket dizininde yapılan bir değişiklik kuruluma yansımaz.
`$TMPDIR`'de paketin bir kopyası kadar boş yer olmalıdır (gerekirse
`TMPDIR=/buyuk/disk ./install.sh ...`); kopya çıkışta silinir.

`install.sh` aşağıdakilerden **herhangi biri** olursa sıfırdan farklı kodla
(`REFUSED: ...`) durur ve hiçbir `docker`/`ctr`/`kubectl`/`helm` komutu çalıştırmaz:

- `SHA256SUMS` imzası yok ya da verilen açık anahtarla doğrulanmıyor
- bir dosyanın SHA-256'sı tutmuyor, dosya eksik, güvensiz yol (`..`, mutlak yol) var
- paket dizininde `SHA256SUMS`'ta olmayan herhangi bir şey var: listelenmemiş
  dosya, sembolik bağ, FIFO, soket, aygıt dosyası ya da boş/listelenmemiş dizin
- `manifest.json` veya `images.tsv`, `SHA256SUMS` ile çelişiyor
- kural (`rules/*.tar.gz`) veya model (`models/*.tar`) arşivinde normal dosya ve
  dizin dışında bir üye (sembolik/sabit bağ, aygıt) ya da güvensiz üye adı var

> Paketin içinde bir açık anahtar olsa bile **kullanılmaz**; yalnızca
> `--pubkey` ile verdiğiniz, bant dışı aldığınız anahtar geçerlidir.

---

## 4. Kurulum (~10 dk)

Yerel kayıt defterine iterek (varsayılan `--loader registry`, `docker` gerekir):

```bash
./install.sh install \
  --pubkey /guvenli/yol/autosecops-airgap.pub \
  --registry harbor.musteri.local/autosecops \
  --namespace autosecops --release autosecops \
  --rules-into-backend
```

Önce ne yapılacağını görmek için `--dry-run` ekleyin (doğrulama yine yapılır,
komutlar yalnızca yazdırılır).

Adımlar, doğrulamadan sonra sırasıyla:

1. Her imaj `docker load` → `docker tag <REG>/<yol>` → `docker push`.
   Eşleme: kayıt defteri adı atılır, tek bileşenli adlar `library/` alır
   (`ghcr.io/singularityrd/autosecops-backend:2.0.0` → `REG/singularityrd/autosecops-backend:2.0.0`,
   `postgres:16-alpine` → `REG/library/postgres:16-alpine`).
   - `--loader ctr`: kayıt defteri yoksa, **her düğümde** çalıştırın
     (`ctr -n k8s.io images import` + `tag`).
   - `--loader docker`: tek düğümlü docker tabanlı ortamlar için (push yok).
2. `values-airgap.yaml` ve `k8s/llm-stack.yaml` içindeki imajlar `--registry`'ye
   yönlendirilir; ad alanı oluşturulur, Bifrost + Ollama uygulanır.
3. Pakette model varsa Ollama hazır olunca `models/ollama-models.tar` pod'un
   `/root/.ollama` dizinine açılır (`--skip-model` ile atlanır).
4. `helm upgrade --install <release> chart/vigil-<V>.tgz -f values-airgap.yaml --wait`.
   `--` sonrasındaki argümanlar helm'e geçer (ör. `-- -f musteri-values.yaml`).
5. Kural depoları: `--rules-into-backend` backend pod'unun
   `~/security-detections` dizinine açar; `--rules-dir DIR` ise bir host
   dizinine (hostPath / Compose kurulumu) açar.
   Not: backend pod'unun ev dizini kalıcı değilse pod yeniden başladığında bu
   adımı tekrarlayın veya `--rules-dir` ile kalıcı bir birime açın.

---

## 5. Kurulum sonrası (~5 dk)

```bash
kubectl -n autosecops get pods
kubectl -n autosecops exec deploy/ollama -- ollama list      # model görünmeli
```

- Sırları (JWT, Postgres parolası vb.) chart README'deki gibi verin
  (`existingSecret` / ExternalSecret önerilir).
- LLM sağlayıcısı: arayüzde **Ayarlar → LLM Sağlayıcıları** altında Bifrost
  üzerinden Ollama modelini (`ollama/<model>`) ekleyip varsayılan yapın. Bulut
  sağlayıcı anahtarları air-gap ortamında işe yaramaz ve egress politikası
  tarafından zaten engellenir.
- Host üzerinde (`start.sh`) veya Compose ile çalışan bileşenler için aynı
  kapatmalar paketteki `airgap.env` dosyasındadır (W3.4):
  `set -a; . ./airgap.env; set +a` ya da Compose servislerinde
  `env_file: [airgap.env]`. Helm kurulumunda `values-airgap.yaml` aynı
  anahtarları aynı değerlerle verir (testlerle eşitliği denetlenir).
- Ek dış hedefler (şirket içi SIEM/EDR, NodeLocal DNS gibi pod olmayan
  adresler) gerekiyorsa `networkPolicies.egress.extraCIDRs` listesine ekleyin.

---

## `values-airgap.yaml` ne kapatır?

| Alan | Değer | Neden |
|---|---|---|
| `global.imageRegistry` + bileşen imajları | yerel kayıt defteri | Hiçbir genel kayıt defteri adı geçmez |
| `MCP_AUTO_CONNECT_ON_STARTUP` | `false` | Uzak MCP sunucularına açılışta bağlanılmaz |
| `VIGIL_MCP_ENABLED` | `false` | AutoSecOps'un kendi MCP yüzeyi kapalı |
| `VIGIL_OTEL_ENABLED`, `otelCollector`, `serviceMonitor` | kapalı | Telemetri yok |
| Slack/PagerDuty/sandbox (Joe, CAPE, Hybrid Analysis, ANY.RUN) | `false` | Dış bildirim/analiz servisleri yok |
| `networkPolicies.enabled` + `egress.inClusterOnly` | `true` | Pod çıkışı yalnızca küme içi (+ `extraCIDRs`) |
| Kafka, Darktrace, daemon eskalasyonu, Medic (`*_ENABLED`), `DEMO_MODE` | `false` | `airgap.env` ile aynı: dış satıcı/servis çağrısı yok |
| `VIGIL_EMAIL_BACKEND` | `console` | E-posta SMTP'ye değil loga gider |
| `medic`, `splunk`, `pgadmin`, Bitnami alt grafikleri | kapalı | İmajları pakette değil |

Uygulamada ayrı bir "güncelleme kontrolü" yoktur; kapatılamayan her dış istek
egress NetworkPolicy tarafından düşürülür. `k8s/llm-stack.yaml` Bifrost ve
Ollama için de aynı küme-içi kuralını uygular.

---

## Sorun giderme

| Belirti | Çözüm |
|---|---|
| `REFUSED: ... signature ... does not verify` | Yanlış açık anahtar ya da paket değiştirilmiş. Paketi yeniden aktarın; anahtarın parmak izini sürüm mühendisiyle doğrulayın. |
| `REFUSED: checksum mismatch` / `missing file` | Aktarım bozuk veya eksik; tar'ı yeniden taşıyın. |
| `REFUSED: ... not listed` / `non-regular file` / `directory not listed` | Paket dizinine sonradan bir şey eklenmiş; tar'ı boş bir dizine yeniden açın. |
| `No space left on device` (doğrulama sırasında) | Hazırlık kopyası için yer yok; `TMPDIR`'i büyük bir diske yönlendirin. |
| `minisign/cosign is not installed` | Açık anahtar o araca ait; aracı kurun ya da OpenSSL anahtarıyla imzalanmış paket isteyin. |
| `ImagePullBackOff` | `--registry` düğümlerden erişilebilir mi, TLS/güven ayarları doğru mu? `--loader ctr` ile her düğüme aktarmayı deneyin. |
| Pod dışarı bağlanamıyor (beklenen) | Gerçekten gerekli bir şirket içi hedefse `networkPolicies.egress.extraCIDRs` ile izin verin. |
| DNS çalışmıyor | NodeLocal DNSCache kullanıyorsanız adresini (ör. `169.254.20.10/32`) `extraCIDRs`'e ekleyin. |

Geri alma: `helm rollback <release>` ya da egress'i eski haline döndürmek için
`helm upgrade ... --set networkPolicies.egress.inClusterOnly=false`.
