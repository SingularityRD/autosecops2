# Outbound webhooks

AutoSecOps can POST case events to HTTP endpoints you register. Every request
is signed, retried on failure, and only ever sent to addresses that pass the
SSRF check.

## Managing endpoints

All routes need the `settings.write` permission (Manager and Admin roles).

| Method | Path | What it does |
|---|---|---|
| `GET` | `/api/webhook-endpoints` | List endpoints and the event types you can subscribe to |
| `POST` | `/api/webhook-endpoints` | Create one: `{"name", "url", "event_types": [], "enabled": true, "secret"?}` |
| `GET` | `/api/webhook-endpoints/{id}` | Read one |
| `PATCH` | `/api/webhook-endpoints/{id}` | Change name, url, event types, enabled, or set a new secret |
| `DELETE` | `/api/webhook-endpoints/{id}` | Delete it, its delivery history and its secret |
| `POST` | `/api/webhook-endpoints/{id}/test` | Send a signed `webhook.test` event now and report the result |
| `GET` | `/api/webhook-endpoints/{id}/deliveries?status=&limit=` | Delivery history |
| `POST` | `/api/webhook-endpoints/{id}/deliveries/{delivery_id}/retry` | Requeue a `failed` or `dead` delivery |

If you omit `secret` on create, one is generated and returned **once** in the
create response. Store it then: it is kept in the secrets store, not the
database, and no route returns it again. To rotate, `PATCH` a new `secret`.

`event_types` empty means every type. Current types:

| Type | Sent when |
|---|---|
| `case.sla_warning` | A case reaches 75%, 90% or 100% of its response or resolution SLA (each threshold once) |
| `case.stale_case` | An open case has had no activity for 7 days (at most once a day) |
| `webhook.test` | Only from the test route |

Events for canary cases (synthetic known-answer cases) are never sent.

## The request

```
POST <your url>
Content-Type: application/json
User-Agent: AutoSecOps-Webhooks/1
X-AutoSecOps-Event: case.sla_warning
X-AutoSecOps-Event-Id: sla:CASE-123:response:90
X-AutoSecOps-Delivery: 4711
X-AutoSecOps-Signature: t=1760261000,v1=5f2c...e9

{"created_at":"...","data":{...},"id":"sla:CASE-123:response:90","tenant_id":"default","type":"case.sla_warning"}
```

`data` holds `notification_type`, `title`, `message`, `priority`, `details`
and `case` (`case_id`, `title`, `status`, `priority`, `assignee`).

Answer with any `2xx` to acknowledge. Redirects are not followed.

## Verifying the signature

`v1` is the hex HMAC-SHA256 of `"<t>.<raw body>"` keyed with the endpoint's
secret, where `<t>` is the `t=` value (Unix seconds at the moment of the
attempt). To verify:

1. Split the header on `,`; take `t` and every `v1`.
2. Compute `HMAC_SHA256(secret, t + "." + raw_body)` over the **raw bytes** you
   received (not re-serialized JSON).
3. Compare in constant time against each `v1`; one match is enough (this lets
   a sender sign with two secrets during a rotation).
4. Reject if `|now - t|` is more than 300 seconds.

```python
import hashlib, hmac, time

def verify(secret: str, header: str, body: bytes, tolerance: int = 300) -> bool:
    parts = [p.split("=", 1) for p in header.split(",") if "=" in p]
    t = next((v for k, v in parts if k == "t"), None)
    sigs = [v for k, v in parts if k == "v1"]
    if t is None or not sigs or abs(time.time() - int(t)) > tolerance:
        return False
    expected = hmac.new(secret.encode(), f"{t}.".encode() + body, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, s) for s in sigs)
```

`core.integrations.outbound_webhooks.verify_signature` is the reference
implementation.

## Replay protection

The timestamp is inside the signed message, so an attacker who captured a
request cannot re-date it; the 300-second window bounds how long a captured
request stays valid. Within that window, de-duplicate on
`X-AutoSecOps-Event-Id`: keep the ids you have processed for at least the
tolerance window (longer is fine) and ignore repeats. The same id also arrives
again legitimately when a delivery is retried after your endpoint timed out or
answered an error, so processing must be idempotent per event id anyway.

## Delivery and retries

- `2xx`: `delivered`.
- Network error, timeout (10 s), `408`, `429`, `5xx`: retried with exponential
  backoff (30 s, 60 s, 120 s ... capped at 1 h between attempts) until
  `WEBHOOK_MAX_ATTEMPTS` (default 8) attempts, then `dead`.
- Any other `4xx`, a `3xx`, a refused target, a missing secret or a disabled
  endpoint: `failed` at once.

`failed` and `dead` deliveries stay in the history and can be requeued with the
retry route. Each event is queued once per endpoint (unique on endpoint and
event id), so an event raised twice is still one delivery.

## Where it runs

Deliveries are sent by the case automation component of the **daemon**
(`services/daemon/main.py`), together with the SLA monitor, the stale-case
detector, the daily digest and the notification dispatcher. The API process
never runs these loops. Set `CASE_AUTOMATION_ENABLED=false` to stop them; queued
deliveries wait in the database. Deliveries are claimed with
`FOR UPDATE SKIP LOCKED` and a lease, so even two daemons by mistake would not
send one delivery twice.

## SSRF protection

When an endpoint is saved and again before every attempt, the host is resolved
and **every** address it resolves to must be public. Loopback, private
(RFC 1918, ULA), link-local, multicast, reserved and unspecified addresses are
refused, as is any host whose answer mixes public and internal addresses. The
request then connects only to the addresses that were checked (no second DNS
lookup, so DNS rebinding cannot redirect it), does not follow redirects and
ignores `HTTP(S)_PROXY`.

To deliver to an internal receiver on purpose, an administrator lists its
network in `WEBHOOK_ALLOWED_CIDRS` (comma-separated CIDRs, e.g.
`10.20.0.0/16`). The cloud-metadata address (`169.254.169.254`,
`fd00:ec2::254`) is refused even inside an allowed network. A malformed value
allows nothing and is logged.

## Case notifications

The same daemon component sends the case notifications the platform writes:

- **Broadcast** events (`sla_warning`, `stale_case`) go to subscribed webhook
  endpoints and, with `CASE_NOTIFY_SLACK_ENABLED=true`, once to the Slack
  integration's default channel.
- **Personal** notifications go by email when their channel is `email` or their
  priority is listed in `CASE_NOTIFY_EMAIL_PRIORITIES` (uses
  `VIGIL_EMAIL_BACKEND` / `SMTP_*`), and to Slack when their channel is `slack`.

Email and Slack are tried once; the outcome is recorded on the notification.
Notifications older than 24 hours when the dispatcher first sees them are
marked sent without being sent, so enabling it does not replay a backlog.
