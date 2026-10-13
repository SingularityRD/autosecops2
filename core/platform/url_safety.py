from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Iterable, Tuple
from urllib.parse import urlparse, urlunparse

# Hosts we trust unconditionally — official public LLM provider APIs.
# Anything not in this set is treated as a custom URL and is only
# allowed when ``allow_custom=True`` AND none of its resolved IPs are
# in a blocked range.
DEFAULT_ALLOWED_PROVIDER_HOSTS = frozenset(
    {
        "api.openai.com",
        "api.anthropic.com",
        "generativelanguage.googleapis.com",
    }
)


# Instance-metadata endpoints. Refused even inside an administrator's allowed
# networks and even with ``allow_loopback``: they hand out cloud credentials.
CLOUD_METADATA_ADDRESSES = frozenset(
    {
        "169.254.169.254",  # AWS, GCP, Azure, OpenStack, DigitalOcean, ...
        "169.254.170.2",  # AWS ECS task metadata / credentials
        "fd00:ec2::254",  # AWS IMDS over IPv6
        "100.100.100.200",  # Alibaba Cloud
        "168.63.129.16",  # Azure WireServer
    }
)


class UrlSafetyError(ValueError):
    """Raised when a URL fails safety validation."""


@dataclass(frozen=True)
class SafeUrl:
    """A URL that has passed validation.

    ``sanitized`` is the URL with userinfo, query string, and fragment
    stripped — callers should use this rather than the original. The
    caller is still responsible for appending fixed paths (e.g.
    ``/models``) on top of ``sanitized``.

    ``is_allowlisted_host`` lets the caller decide whether to forward
    sensitive headers (e.g. a bearer token): only forward to known
    hosts so user-supplied credentials never leak to attacker-chosen
    destinations.
    """

    sanitized: str
    host: str
    port: int
    scheme: str
    is_allowlisted_host: bool


def _resolve_host(host: str) -> Iterable[str]:
    """Resolve a hostname (or IP literal) to one or more IPs.

    Returns an iterable of stringified addresses. Raises
    ``UrlSafetyError`` if the host cannot be resolved.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise UrlSafetyError(f"could not resolve host: {host}") from exc
    seen: set[str] = set()
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.add(addr)
            yield addr


def _is_blocked_ip(ip_str: str) -> Tuple[bool, str]:
    """Return ``(blocked, reason)``.

    Blocks all loopback / private / link-local / multicast / reserved /
    unspecified ranges plus the AWS/GCP/Azure metadata service IP.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True, f"unparseable IP: {ip_str}"

    # Collapse an IPv4-mapped IPv6 literal (e.g. ::ffff:169.254.169.254) to
    # its embedded IPv4 before classifying: on Linux it connects as real
    # IPv4, so it must face the same range/metadata checks as the bare v4.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped

    if str(ip) in CLOUD_METADATA_ADDRESSES:
        return True, "cloud metadata address"
    if ip.is_loopback:
        return True, "loopback address"
    if ip.is_private:
        return True, "private address"
    if ip.is_link_local:
        return True, "link-local address"
    if ip.is_multicast:
        return True, "multicast address"
    if ip.is_reserved:
        return True, "reserved address"
    if ip.is_unspecified:
        return True, "unspecified address"
    # Anything else that is not globally routable: carrier-grade NAT
    # (100.64.0.0/10, where Alibaba's metadata service and many VPN overlays
    # live), benchmarking 198.18.0.0/15, IETF 192.0.0.0/24 and the like.
    # ``is_private`` does not cover CGNAT.
    if not ip.is_global:
        return True, "non-global address"
    return False, ""


def blocked_reason(ip_str: str) -> str | None:
    """Why ``ip_str`` is refused by default (``None`` if it is not)."""
    blocked, reason = _is_blocked_ip(ip_str)
    return reason if blocked else None


class UnresolvableHostError(UrlSafetyError):
    """The host did not resolve. Transient, unlike a refused address."""


def parse_networks(
    raw: str,
) -> Tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """Parse a comma-separated CIDR list (``"10.0.0.0/8, 127.0.0.1/32"``).

    Raises ``ValueError`` on an entry that is not a network, so a typo in an
    allow-list fails loudly instead of quietly allowing nothing.
    """
    networks = []
    for part in (raw or "").split(","):
        part = part.strip()
        if part:
            networks.append(ipaddress.ip_network(part, strict=False))
    return tuple(networks)


def ip_in_networks(ip_str: str, networks: Iterable) -> bool:
    """Whether ``ip_str`` (an IPv4-mapped v6 counts as its v4) is in ``networks``."""
    return _in_networks(ip_str, networks)


def _in_networks(ip_str: str, networks: Iterable) -> bool:
    ip = ipaddress.ip_address(ip_str)
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return any(ip.version == net.version and ip in net for net in networks)


def resolve_allowed_addresses(
    host: str, port: int, *, allowed_networks: Iterable = ()
) -> list[str]:
    """Resolve ``host`` and return its addresses, refusing any blocked one.

    For a caller that then connects to exactly these addresses (resolve, check,
    connect to what was checked), so a second DNS answer cannot swap in an
    internal address between the check and the connection.

    Every address must pass: one blocked address in the answer refuses the
    host, rather than connecting to whichever one happens to be tried first.
    ``allowed_networks`` lets an administrator reach a private range on
    purpose; the cloud-metadata address stays refused even then.
    """
    networks = tuple(allowed_networks)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise UnresolvableHostError(f"could not resolve host: {host}") from exc
    addresses: list[str] = []
    for info in infos:
        addr = str(info[4][0]).split("%", 1)[0]  # drop an IPv6 zone id
        if addr in addresses:
            continue
        blocked, reason = _is_blocked_ip(addr)
        if (
            blocked
            and reason != "cloud metadata address"
            and _in_networks(addr, networks)
        ):
            blocked = False
        if blocked:
            raise UrlSafetyError(f"resolved address {addr} is disallowed: {reason}")
        addresses.append(addr)
    if not addresses:
        raise UnresolvableHostError(f"could not resolve host: {host}")
    return addresses


def validate_provider_url(
    url: str,
    *,
    allow_custom: bool = True,
    allow_loopback: bool = False,
    allowed_hosts: Iterable[str] = DEFAULT_ALLOWED_PROVIDER_HOSTS,
    allowed_schemes: Iterable[str] = ("http", "https"),
) -> SafeUrl:
    """Validate a user-supplied provider URL and return a sanitized form.

    Raises ``UrlSafetyError`` if the URL is malformed, uses a disallowed
    scheme, contains userinfo or a fragment, resolves to a blocked IP
    range, or (when ``allow_custom=False``) is not in ``allowed_hosts``.

    The returned ``sanitized`` URL has its userinfo, query string, and
    fragment removed. Callers should append fixed provider paths
    (``/models``, ``/api/tags``, ...) onto ``sanitized`` rather than
    onto the original input.

    ``allow_loopback=True`` permits a self-hosted provider on a
    loopback/private/link-local address (the cloud-metadata IP stays
    blocked). Pass it only for an admin-gated, provider-type-scoped call.
    """
    if not url or not isinstance(url, str):
        raise UrlSafetyError("url is required")

    parsed = urlparse(url.strip())

    if parsed.scheme not in set(allowed_schemes):
        raise UrlSafetyError(f"scheme not allowed: {parsed.scheme or '(missing)'}")

    if not parsed.hostname:
        raise UrlSafetyError("url is missing a host")

    if parsed.username or parsed.password:
        raise UrlSafetyError("url must not include userinfo")

    if parsed.fragment:
        raise UrlSafetyError("url must not include a fragment")

    host = parsed.hostname.lower()
    allowed_set = {h.lower() for h in allowed_hosts}
    is_allowlisted = host in allowed_set

    # Public-allowlist hosts skip DNS-based blocking — the host name
    # itself is the trust anchor. (We still strip userinfo and query
    # string below.) Anything else requires both ``allow_custom`` and
    # passing the IP-range check.
    if not is_allowlisted:
        if not allow_custom:
            raise UrlSafetyError(f"host not in allowlist: {host}")

        for addr in _resolve_host(host):
            blocked, reason = _is_blocked_ip(addr)
            # allow_loopback opts a self-hosted provider (Ollama, vLLM,
            # LM Studio on localhost / the LAN) past the loopback/private/
            # link-local block, but the cloud-metadata address — the actual
            # SSRF target — stays blocked regardless.
            if blocked and allow_loopback and reason != "cloud metadata address":
                continue
            if blocked:
                raise UrlSafetyError(f"resolved address {addr} is disallowed: {reason}")

    # Reconstruct a sanitized URL (no userinfo, no query, no fragment).
    # Keep the path so the caller can use the original base path; we
    # strip the query string explicitly because the disclosure showed
    # that ``base_url=http://x/foo?proof=`` produced a request to
    # ``/foo?proof=/models`` after the appended ``/models``.
    sanitized = urlunparse(
        (
            parsed.scheme,
            parsed.netloc.split("@")[-1],  # drop userinfo if anything slipped through
            parsed.path or "",
            "",  # params
            "",  # query
            "",  # fragment
        )
    )

    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    return SafeUrl(
        sanitized=sanitized,
        host=host,
        port=port,
        scheme=parsed.scheme,
        is_allowlisted_host=is_allowlisted,
    )
