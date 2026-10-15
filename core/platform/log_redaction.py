"""Redaction for values that must be named in a log line but never spelled out."""

import logging
import re
from urllib.parse import urlsplit, urlunsplit


def redact_url(url: str) -> str:
    """The URL with any userinfo (``user:password@``) removed.

    Scheme, host, port and path are kept, so the line still says where a client
    connected. A string that does not parse as a URL is replaced outright rather
    than echoed, since it may be a bare credential.
    """
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if ":" in host:  # IPv6 literal lost its brackets in .hostname
            host = f"[{host}]"
        netloc = f"{host}:{parts.port}" if parts.port else host
    except ValueError:
        return "<unparseable url>"
    if not parts.scheme or not netloc:
        return "<unparseable url>"
    # Query and fragment can carry tokens too (e.g. ?password=...).
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def mask_email(address: str) -> str:
    """``alice@example.com`` -> ``a***@example.com``: enough to tell addresses apart in ops."""
    local, sep, domain = address.partition("@")
    if not sep or not local:
        return "***"
    return f"{local[0]}***@{domain}"


# Query parameters whose value is a credential or one-time secret: a reset
# token, an OAuth code/state, a password, an API key. Matched as a substring of
# the parameter name, case-insensitively (``token``, ``access_token``,
# ``api_key``, ``reset``, ...).
SENSITIVE_QUERY_PARTS = ("token", "code", "state", "password", "secret", "key", "reset")

_SENSITIVE_QUERY = re.compile(
    r"(?P<name>(?:^|(?<=[?&;#]))[^=&;#\s?]*(?:"
    + "|".join(SENSITIVE_QUERY_PARTS)
    + r")[^=&;#\s]*=)(?P<value>[^&;#\s\"]*)",
    re.IGNORECASE,
)


def redact_query_secrets(target: str) -> str:
    """``target`` (a request path with query, or a URL) with the value of every
    sensitive query parameter replaced by ``[REDACTED]``.

    ``/reset-password?token=abc&lang=en`` -> ``/reset-password?token=[REDACTED]&lang=en``.
    Only the part after the first ``?`` is touched, so a path segment that
    merely contains ``key=`` stays as it is.
    """
    if not isinstance(target, str) or "?" not in target:
        return target
    path, _, query = target.partition("?")
    return path + "?" + _SENSITIVE_QUERY.sub(r"\g<name>[REDACTED]", query)


class SensitiveQueryFilter(logging.Filter):
    """Redacts sensitive query values in uvicorn's access log records.

    uvicorn logs ``'%s - "%s %s HTTP/%s" %d'`` on ``uvicorn.access`` with the
    full path (query included) as the third argument. The record is rewritten,
    never dropped, so the access log keeps every request.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            args = record.args
            if isinstance(args, tuple) and args:
                record.args = tuple(redact_query_secrets(a) for a in args)
            elif isinstance(record.msg, str) and not args:
                record.msg = redact_query_secrets(record.msg)
        except Exception:  # noqa: BLE001 - a log filter must never raise
            pass
        return True


ACCESS_LOGGERS = ("uvicorn.access", "gunicorn.access")


def install_access_log_redaction() -> None:
    """Attach :class:`SensitiveQueryFilter` to the HTTP access loggers (and
    their current handlers), once. Idempotent."""
    for name in ACCESS_LOGGERS:
        target = logging.getLogger(name)
        for obj in (target, *target.handlers):
            if not any(isinstance(f, SensitiveQueryFilter) for f in obj.filters):
                obj.addFilter(SensitiveQueryFilter())
