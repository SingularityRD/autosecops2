# Redis start wrapper (W0.38). Redis 7.4 (the old floating redis:7-alpine)
# writes RDB format 12, which the pinned BSD 7.2 cannot read: it would refuse to
# start. Such data is moved aside (kept, so a rollback can use it) and Redis
# starts empty, with revocation_epoch set before any client can connect: the
# API rejects every token issued before it, because the logouts and cutoffs
# Redis held are gone. Otherwise this is plain `redis-server "$@"`.
# $0 is how to start the server: docker-entrypoint.sh (Compose: the image's
# entrypoint drops to the redis user, as before) or redis-server (Helm, whose
# `command` replaces the entrypoint, as before). Kept identical in the Helm
# chart and both Compose files (tests/unit/_ratchets/test_licences_and_pins.py).
launch() {
  if [ "$0" = docker-entrypoint.sh ]; then docker-entrypoint.sh redis-server "$@"; else redis-server "$@"; fi
}
old=""
for f in /data/dump.rdb /data/appendonlydir/*.base.rdb; do
  [ -f "$f" ] || continue
  v=$(head -c 9 "$f" | sed -n 's/^REDIS0*\([0-9][0-9]*\)$/\1/p')
  if [ -n "$v" ] && [ "$v" -gt 11 ]; then old=1; fi
done
if [ -n "$old" ]; then
  keep="/data/redis-7.4-data-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$keep"
  for p in /data/dump.rdb /data/appendonlydir; do
    if [ -e "$p" ]; then mv "$p" "$keep/"; fi
  done
  echo "autosecops: Redis 7.4 data moved to $keep; starting empty. Queued jobs and sessions start over; every earlier login is revoked." >&2
  sock=/tmp/redis-epoch.sock
  launch "$@" --port 0 --unixsocket "$sock" --requirepass "" &
  pid=$!
  until redis-cli -s "$sock" ping >/dev/null 2>&1; do
    kill -0 "$pid" 2>/dev/null || exit 1
    sleep 1
  done
  redis-cli -s "$sock" set revocation_epoch "$(date +%s)" >/dev/null
  redis-cli -s "$sock" shutdown save >/dev/null 2>&1
  wait "$pid"
fi
if [ "$0" = docker-entrypoint.sh ]; then exec docker-entrypoint.sh redis-server "$@"; fi
exec redis-server "$@"
