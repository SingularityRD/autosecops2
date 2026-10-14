# CI (AutoSecOps)

CI, GitHub Actions ile `SingularityRD/autosecops2` deposunda çalışır. Vigil'den
gelen iş akışları `github.repository == 'SingularityRD/autosecops2'` koşuluyla
sınırlıdır; başka bir fork'ta atlanır (başarısız olmaz). Hiçbir iş akışı yeni bir
secret gerektirmez.

## İş akışları

| Dosya | Ne zaman | Not |
|---|---|---|
| `ci-cd.yml` | `main`/`develop` push, PR, elle | Ana kapı. Lint, tip, birim/entegrasyon testleri. |
| `helm-chart.yml` | `infra/helm/**` değişince | Yol filtreli. |
| `medic.yml`, `medic-helm.yml` | Medic dosyaları değişince | Yol filtreli. |
| `nightly.yml` | Her gün 02:00 UTC | Actions dakikası harcar. |
| `release-please.yml`, `release.yml` | — | **Kapalı.** Upstream'e (`ghcr.io/vigil-soc/*`) yayın yapar; koşul hâlâ `Vigil-SOC/vigil`, burada asla çalışmaz. |

`ci-cd.yml` hiçbir registry'ye imaj itmez; imajları yalnızca `release.yml` bir
etikette yayımlar (imza, SBOM, provenance). Eskiden `if: false` ile kapalı duran
ve ghcr'a iten `build-images` / `scan-images` işleri W0.22'de kaldırıldı.

## İmaj taraması (etiketten önce)

`Agent Image` ve `Service Image (backend)` / `Service Image (daemon)` işleri her
PR'da ve `main` push'unda imajı yerelde derler (`push: false`, `load: true`),
Trivy ile HIGH/CRITICAL bulguları raporlar, **düzeltmesi olan** bir CRITICAL
zafiyette düşer ve imajın içinde uygulamanın içe aktarıldığını doğrulayan bir
duman testi çalıştırır. Servis imajı işleri yalnızca `contents: read` izniyle
çalışır, secret kullanmaz; eylemler commit SHA'sıyla, Trivy sürümü açıkça
sabitlenmiştir (`tests/unit/release/test_ci_image_scan.py`).

## `main` için zorunlu (required) kontroller

Branch protection'da şu `ci-cd.yml` işlerini zorunlu işaretleyin (GitHub'da
görünen adlarıyla):

- `Lint Backend`
- `Lint Frontend` (ESLint hatası işi düşürür; uyarılar düşürmez)
- `Generated API Types`
- `Lint Dockerfiles`
- `Agent Image`
- `Service Image (backend)`, `Service Image (daemon)`
- `Unit Tests - Backend`
- `Unit Tests - Backend (DB-backed)`
- `Unit Tests - Frontend`
- `Unit Tests - Agent Layer`
- `Integration Tests`
- `Helm Install Schema`
- `Build Frontend` (tek `tsc` kontrolü)
- `Security Scan - Python` (Bandit)
- `Setup Path (ubuntu-latest)`, `Setup Path (macos-latest)`

Zorunlu **yapmayın**: `Schema Snapshot Patch Gate` (yalnız PR'da, çoğu zaman
atlanır), `Security Scan - NPM` (`npm audit`: yeni bir advisory ilgisiz PR'ları
da düşürür; uyarı olarak izleyin),
yol filtreli iş akışları (Helm, Medic: ilgisiz PR'larda hiç çalışmaz ve PR'ı
sonsuza dek bekletir).

## Yerelde çalıştırma

Web istemcisi (`clients/web`):

```bash
cd clients/web
npm ci
npm run lint        # 0 hata olmalı
npx tsc --noEmit    # Build Frontend'deki tip kontrolü
npm run test:run    # vitest
```

Ajan katmanı (`services/agent`):

```bash
cd services/agent
npm ci
npm run typecheck
npm test            # DB testleri için PostgreSQL gerekir, bkz. ci-cd.yml
```

Backend (repo kökü, Python ortamı kurulu):

```bash
flake8 services/ core/
black --check --extend-exclude '^/services/medic/contracts/' services/ core/
isort --check-only services/ core/
lint-imports
pytest tests/unit/ tests/security/ -m "not external_service"
```

İş akışı dosyaları:

```bash
actionlint          # .github/actionlint.yaml yapılandırmasını kullanır
```
