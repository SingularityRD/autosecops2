# AutoSecOps sürümünü doğrulama (internetsiz ortam dahil)

Bu belge, bir AutoSecOps sürümünü (ör. `2.0.0`) kurmadan önce imzalarını, SBOM'larını
ve imajlarını **internete bağlı olmayan** (air-gap) bir ortamda nasıl doğrulayacağınızı
anlatır. Bağlantılı bir makinede yalnızca indirme yapılır; doğrulamanın kendisi ağ
gerektirmez.

## 1. Ne imzalanır, kim imzalar

Sürümler `SingularityRD/autosecops2` deposundaki `.github/workflows/release.yml` iş
akışı tarafından, `v<sürüm>` etiketi itildiğinde üretilir. İmzalar **anahtarsızdır**
(Sigstore / cosign): kalıcı bir özel anahtar yoktur; her imza, GitHub'ın OIDC kimliğiyle
Sigstore Fulcio'dan alınan kısa ömürlü bir sertifikaya dayanır ve Sigstore Rekor
şeffaflık kaydına yazılır. Doğrularken iki değeri **birebir** beklersiniz:

| Alan | Beklenen değer (`2.0.0` için) |
|---|---|
| Sertifika kimliği (`--certificate-identity`) | `https://github.com/SingularityRD/autosecops2/.github/workflows/release.yml@refs/tags/v2.0.0` |
| OIDC yayıncısı (`--certificate-oidc-issuer`) | `https://token.actions.githubusercontent.com` |

Kimlik; deponun, iş akışı dosyasının ve etiketin üçünü birden sabitler. Başka bir
depodan, başka bir iş akışından veya başka bir etiketten gelen imza reddedilir.

GitHub Release'teki dosyalar (`<V>` = sürüm):

| Dosya | İçerik | İmza |
|---|---|---|
| `SHA256SUMS` | Aşağıdaki tüm dosyaların SHA-256 özetleri | `SHA256SUMS.sigstore.json` |
| `autosecops-<V>-images.json` / `.tsv` | Her imajın index özeti, platform (amd64/arm64) manifest özetleri ve **config özeti** | `<dosya>.sigstore.json` |
| `autosecops-<V>-python.cdx.json` | `requirements.lock`'tan CycloneDX 1.6 SBOM | `<dosya>.sigstore.json` |
| `autosecops-<V>-node-{web,agent,mcp-packages,desktop}.cdx.json` | `package-lock.json` dosyalarından CycloneDX SBOM'lar | `<dosya>.sigstore.json` |
| `autosecops-<V>-image-<bileşen>-<mimari>.cdx.json` | Her imaj platformunun syft ile çıkarılmış CycloneDX SBOM'u | `<dosya>.sigstore.json` + imaja eklenmiş attestation |
| `autosecops-<V>-image-<bileşen>.provenance.json` | SLSA v1 provenance (hangi commit, hangi iş akışı, hangi çalıştırma) | `<dosya>.sigstore.json` + imaja eklenmiş attestation |
| `autosecops-<V>-image-<bileşen>[-<mimari>].sig.sigstore.json` | İmaj imzası bundle'ı | — |
| `autosecops-<V>-image-<bileşen>.provenance.att.sigstore.json` | Index özetine bağlı SLSA provenance attestation'ı | — |
| `autosecops-<V>-image-<bileşen>-<mimari>.sbom.att.sigstore.json` | Platform özetine bağlı CycloneDX attestation'ı | — |
| `autosecops-<V>-web.tar.gz` | Web konsolunun statik dosyaları (backend imajındakiyle aynı) | `<dosya>.sigstore.json` |
| `autosecops-<V>-desktop-mac-{arm64,x64}[-unsigned].dmg`, `autosecops-<V>-desktop-linux-x86_64.AppImage`, `autosecops-<V>-desktop-win-x64[-unsigned].exe` | Masaüstü uygulaması kurulum dosyaları; `-unsigned` olanlar Apple Developer ID / Authenticode imzası taşımaz (bkz. [yönetici kılavuzu](../guide/yonetici-kilavuzu.md#masaüstü-uygulaması)) | `<dosya>.sigstore.json` |
| `verify-release.sh` | Bu belgedeki adımları uygulayan betik | `<dosya>.sigstore.json` |
| `trusted_root.json` | Sürüm anındaki Sigstore güven kökü (**kolaylık kopyası**, bkz. §3) | — |
| `vigil-support-<V>.tar.gz` (+ `.sha256`) | Destek aracı; **imzalı küme dışında**, yalnızca `.sha256` ile | — |

`<bileşen>`: `backend`, `daemon`, `agent`. İmajlar:
`ghcr.io/singularityrd/autosecops-<bileşen>:<V>`.

## 2. Gerekenler

- `cosign` **3.x** (sürüm iş akışı `v3.0.6` kullanır). İkiliyi
  <https://github.com/sigstore/cosign/releases> adresinden indirin ve yayınlanan
  `cosign_checksums.txt` ile özetini karşılaştırın.
- `sha256sum` (Linux) veya `shasum -a 256` (macOS), POSIX `sh`.
- İmajları yüklemek için `docker` (veya `skopeo`/`crane`); isteğe bağlı `jq`.

## 3. Bağlantılı makinede hazırlık

```sh
V=2.0.0
mkdir autosecops-$V && cd autosecops-$V
# Release dosyalarını indirin (GitHub arayüzünden veya gh ile):
gh release download "v$V" -R SingularityRD/autosecops2
```

**Güven kökü (trusted root).** Çevrimdışı doğrulama, Sigstore'un genel güven kökünü
(Fulcio kök sertifikaları, Rekor ve CT log açık anahtarları) içeren bir
`trusted_root.json` ister. Release'teki `trusted_root.json` bir kolaylık kopyasıdır ve
imzaladığı şeyle aynı yerden geldiği için tek başına güven çapası **değildir**. Bağımsız
bir kopya alın ve karşılaştırın:

```sh
# cosign, gömülü TUF kökünden başlayarak güncel güven kökünü indirir ve doğrular
cosign initialize
ROOT=$(find "$HOME/.sigstore" -name trusted_root.json -type f | head -n 1)
cp "$ROOT" ./trusted_root.independent.json
sha256sum trusted_root.json trusted_root.independent.json   # aynı olmalı
```

Özetler farklıysa Sigstore anahtar rotasyonu olmuş olabilir; bağımsız kopyayı kullanın
ve doğrulama başarılıysa devam edin. Ardından şunları air-gap ortama taşıyın:
release dizini, `trusted_root.independent.json`, `cosign` ikilisi ve imaj arşivleri
(ör. W3.3 air-gap paketi: `infra/airgap/build-bundle.sh --version $V --image-namespace singularityrd/autosecops`).

## 4. Air-gap ortamda doğrulama

### 4.1 Tek komutla

```sh
sh verify-release.sh --dir . --version 2.0.0 --trusted-root trusted_root.independent.json
```

Betik sırasıyla şunları yapar ve hepsi geçerse `RESULT: VERIFIED` yazar:

1. `SHA256SUMS`'taki her dosyanın özetini kontrol eder (dizin dışına işaret eden satırları reddeder).
2. `SHA256SUMS`'ın imzasını beklenen kimlik ve yayıncıyla doğrular.
3. Her SBOM, provenance, imaj listesi ve web paketinin kendi imzasını doğrular.
4. `autosecops-<V>-images.tsv`'deki her imaj özeti için SLSA provenance (index) ve
   CycloneDX SBOM (her platform) attestation'larını doğrular.

`--trusted-root` verildiğinde hiçbir ağ bağlantısı açılmaz. Betiği kullanmadan önce
kendi imzasını da (adım 4.2'deki gibi `verify-release.sh.sigstore.json` ile) doğrulayın.

### 4.2 Adım adım (betik olmadan)

```sh
V=2.0.0
ID="https://github.com/SingularityRD/autosecops2/.github/workflows/release.yml@refs/tags/v$V"
ISS="https://token.actions.githubusercontent.com"
TR=trusted_root.independent.json

# 1) Özetler
sha256sum -c SHA256SUMS

# 2) SHA256SUMS imzası
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "$ID" --certificate-oidc-issuer "$ISS" \
  --trusted-root "$TR" SHA256SUMS

# 3) Tek bir SBOM'un imzası (her dosya için aynı kalıp)
cosign verify-blob --bundle autosecops-$V-python.cdx.json.sigstore.json \
  --certificate-identity "$ID" --certificate-oidc-issuer "$ISS" \
  --trusted-root "$TR" autosecops-$V-python.cdx.json

# 4) Bir imajın provenance'ı (index özeti images.tsv'den)
DIGEST=$(awk -F'\t' '$1=="backend" && $2=="index" {sub(/.*@sha256:/,"",$3); print $3}' autosecops-$V-images.tsv)
cosign verify-blob-attestation --type slsaprovenance1 \
  --bundle autosecops-$V-image-backend.provenance.att.sigstore.json \
  --digest "$DIGEST" --digestAlg sha256 \
  --certificate-identity "$ID" --certificate-oidc-issuer "$ISS" --trusted-root "$TR"

# 5) Bir imaj platformunun SBOM attestation'ı
DIGEST=$(awk -F'\t' '$1=="backend" && $2=="amd64" {sub(/.*@sha256:/,"",$3); print $3}' autosecops-$V-images.tsv)
cosign verify-blob-attestation --type cyclonedx \
  --bundle autosecops-$V-image-backend-amd64.sbom.att.sigstore.json \
  --digest "$DIGEST" --digestAlg sha256 \
  --certificate-identity "$ID" --certificate-oidc-issuer "$ISS" --trusted-root "$TR"
```

### 4.3 Yüklediğiniz imajı imzalı listeye bağlama

İmzalar imaj **özetlerine** bağlıdır; etiketler değiştirilebilir. Elinizdeki imajın
imzalanan imaj olduğunu göstermek için:

- **`docker save` / `docker load` ile taşındıysa** (W3.3 air-gap paketi böyle taşır):
  manifest özeti yeniden paketlemede değişebilir, ama **config özeti** (imaj kimliği)
  değişmez. İmzalı `images.json`'daki `config_digest` ile karşılaştırın:

  ```sh
  docker image inspect --format '{{.Id}}' ghcr.io/singularityrd/autosecops-backend:2.0.0
  jq -r '.images[] | select(.component=="backend") | .platforms[] | "\(.platform) \(.config_digest)"' \
    autosecops-2.0.0-images.json
  ```

  Çıkan `sha256:…` değeri, makinenizin mimarisine ait `config_digest` ile aynı olmalıdır.

- **Özetleri koruyarak kopyalandıysa** (ör. `skopeo copy --all --preserve-digests`,
  `oras cp -r`, `crane copy`): yerel kayıt defterindeki index özeti `images.json`'daki
  `index_digest` ile aynı olmalıdır (`skopeo inspect --raw docker://<kayıt>/autosecops-backend:2.0.0 | sha256sum`).
  İmzalar ve attestation'lar da kopyalandıysa doğrudan kayıt defterine karşı
  doğrulayabilirsiniz:

  ```sh
  cosign verify --certificate-identity "$ID" --certificate-oidc-issuer "$ISS" \
    --trusted-root "$TR" <kayıt>/autosecops-backend@sha256:<index_digest>
  ```

Kubernetes'te imajı **özetle** (`image: …@sha256:…`) çekmeniz, etiketin sonradan
değiştirilmesine karşı korur.

## 5. SBOM'ları kullanma

SBOM'lar CycloneDX 1.6 JSON'dur ve imzaları doğrulandıktan sonra tarayıcılara
(ör. çevrimdışı veritabanıyla `grype sbom:autosecops-2.0.0-image-backend-amd64.cdx.json`,
Dependency-Track) verilebilir. Lockfile SBOM'larında geliştirme bağımlılıkları
`"scope": "excluded"` ile işaretlidir; çalışma zamanı içeriği için imaj SBOM'larını esas alın.

```sh
jq -r '.components[] | "\(.name) \(.version)"' autosecops-2.0.0-python.cdx.json | head
```

## 6. Bağlantılı ortamda ek doğrulamalar

- İmaj imzası: `cosign verify --certificate-identity "$ID" --certificate-oidc-issuer "$ISS" ghcr.io/singularityrd/autosecops-backend@sha256:<index_digest>`
- Attestation: `cosign verify-attestation --type cyclonedx …` / `--type slsaprovenance1 …`
- Depo değişkeni `RELEASE_GITHUB_ATTESTATIONS=true` iken GitHub attestation'ları da
  üretilir: `gh attestation verify oci://ghcr.io/singularityrd/autosecops-backend@sha256:<index_digest> -R SingularityRD/autosecops2`.
  Çevrimdışı kullanım için `gh attestation download` ve `gh attestation trusted-root`
  çıktıları `--bundle` / `--custom-trusted-root` ile verilebilir.

## 7. Neyi kanıtlar, neyi kanıtlamaz

- **Kanıtlar:** dosyalar ve imajlar, `SingularityRD/autosecops2` deposunda belirtilen
  etiketle çalışan `release.yml` iş akışı tarafından üretildi ve sonra değiştirilmedi;
  provenance hangi commit'ten (`resolvedDependencies[].digest.gitCommit`) ve hangi
  çalıştırmadan (`runDetails.metadata.invocationId`) üretildiğini söyler.
- **Kanıtlamaz:** kaynak kodun güvenli olduğunu, bağımlılıklarda açık bulunmadığını
  (bunun için SBOM'u tarayın) veya derlemenin tekrarlanabilir (reproducible) olduğunu.
  Provenance, iş akışının kendisi tarafından yazılır ve iş akışının kimliğiyle
  imzalanır (SLSA Build L2 düzeyine karşılık gelir).

## 8. Gizlilik notu

Anahtarsız imzalama, imzalayan sertifikayı herkese açık Sigstore Rekor kaydına yazar.
Sertifika depo adını (`SingularityRD/autosecops2`), iş akışı yolunu, etiketi ve commit
özetini içerir. Kaynak kodu veya sürüm dosyaları kayda **yazılmaz**, yalnızca özetleri
ve imzalar yazılır.

## 9. Sorun giderme

| Belirti | Olası neden |
|---|---|
| `none of the expected identities matched` | `--certificate-identity`'deki etiket veya depo yanlış; `v` önekini unutmayın |
| `checksum mismatch` | Dosya aktarımda bozuldu veya değiştirildi; yeniden indirin, **kurmayın** |
| `error verifying bundle … trusted root` | Eski/yanlış `trusted_root.json`; §3'teki bağımsız kopyayı kullanın |
| `docker image inspect` Id hiçbir `config_digest` ile eşleşmiyor | Farklı mimari veya farklı imaj; kurmayın |
