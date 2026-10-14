# Vigil SOC Helm chart

Production chart for the Vigil API, daemon, workers, and optional in-cluster
Postgres/Redis.

Full install, values, and troubleshooting:
<https://vigilsoc.org/docs/helm-chart/>

## FIPS modu

`config.FIPS_MODE: "true"` AutoSecOps'u FIPS 140-3 modunda çalıştırır: OpenSSL 3
FIPS sağlayıcısı etkin değilse API, daemon ve worker pod'ları başlangıçta 78 koduyla
çıkar; yeni parola hash'leri PBKDF2-HMAC-SHA256 olur ve eski bcrypt hash'leri ilk
girişte yeniden yazılır. Standart imajlar FIPS sağlayıcısı içermez; FIPS etkin bir
taban imaj (ör. UBI 9 + `cryptography`'nin sistem OpenSSL'ine karşı kaynaktan
derlenmesi) gerekir ve `backend.image.repository` / `daemon.image.repository` onu
göstermelidir. Ayrıntılar, OpenSSL yapılandırması ve göç adımları:
[`docs/fips.md`](../../../docs/fips.md).

## Daemon hot standby and database backups

- `daemon.leaderElection.enabled` (default `true`) runs two daemon pods: a
  Postgres advisory lock picks the leader, the other waits as a healthy
  standby and takes over when the leader dies (needs PostgreSQL 14+). Set it
  to `false` for a single pod.
- `backup.enabled` adds a CronJob that takes a verified `pg_dump` to a PVC
  (keep-last / max-age retention) and optionally copies it to an
  S3-compatible bucket.

Targets, failover timings and the restore procedure:
[docs/operations/rpo-rto.md](../../../docs/operations/rpo-rto.md).

## Upgrade notes

- **CSRF is enforced by default** (`config.VIGIL_CSRF_REPORT_ONLY: "false"`,
  previously `"true"`). The web console already sends the `X-CSRF-Token`
  header on every state-changing request. A script or integration that
  calls a non-exempt `POST`/`PUT`/`PATCH`/`DELETE` path with a Bearer token
  and no cookies will now get `403 CSRF token missing or invalid`: send a
  `csrf_token` cookie with an equal `X-CSRF-Token` header (any random value;
  the medic gateway does this), or add the path prefix to
  `VIGIL_CSRF_EXEMPT_PATHS`. Webhooks, `/api/ingest/`, `/mcp` and
  `/internal/` stay exempt. To roll out gradually, set the value back to
  `"true"` and watch the API logs for `CSRF violation` before enforcing.
