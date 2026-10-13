# Vigil SOC Helm chart

Production chart for the Vigil API, daemon, workers, and optional in-cluster
Postgres/Redis.

Full install, values, and troubleshooting:
<https://vigilsoc.org/docs/helm-chart/>

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
