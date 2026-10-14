"""Optional RFC 3161 timestamp for a checkpoint. Off unless AUDIT_TSA_URL is set.

The request is a DER ``TimeStampReq`` over the SHA-256 of the checkpoint body,
built here by hand (it is five fixed fields). The response is stored as
returned, base64, after checking only that its PKIStatus is granted (0) or
grantedWithMods (1): validating the token's CMS signature needs the TSA's
certificate chain, which is the auditor's job, not this process's.

A failure never blocks the checkpoint; the caller stores it without a token.
"""

from __future__ import annotations

import logging
import secrets
from typing import Callable, Optional, Tuple
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

# id-sha256, 2.16.840.1.101.3.4.2.1
_SHA256_OID = bytes.fromhex("0609608648016503040201")
_TIMEOUT_SECONDS = 10.0

# (url, body, timeout) -> (status_code, content)
Poster = Callable[[str, bytes, float], Tuple[int, bytes]]


def _der_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(value)) + value


def _der_integer(n: int) -> bytes:
    raw = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _tlv(0x02, raw)


def build_request(digest: bytes, nonce: Optional[int] = None) -> bytes:
    """DER TimeStampReq v1 for a SHA-256 digest, with a nonce and certReq."""
    if len(digest) != 32:
        raise ValueError("a SHA-256 digest is 32 bytes")
    if nonce is None:
        nonce = secrets.randbits(63)
    algorithm = _tlv(0x30, _SHA256_OID + b"\x05\x00")
    imprint = _tlv(0x30, algorithm + _tlv(0x04, digest))
    return _tlv(
        0x30,
        _der_integer(1) + imprint + _der_integer(nonce) + _tlv(0x01, b"\xff"),
    )


def _read_tlv(data: bytes, offset: int) -> Tuple[int, int, int]:
    """(tag, value start, value end) of the element at offset."""
    tag = data[offset]
    length = data[offset + 1]
    start = offset + 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4:
            raise ValueError("unsupported DER length")
        length = int.from_bytes(data[start : start + count], "big")
        start += count
    end = start + length
    if end > len(data):
        raise ValueError("truncated DER")
    return tag, start, end


def response_status(response: bytes) -> int:
    """The PKIStatus of a DER TimeStampResp."""
    tag, start, _ = _read_tlv(response, 0)
    if tag != 0x30:
        raise ValueError("TimeStampResp is not a SEQUENCE")
    tag, info_start, _ = _read_tlv(response, start)
    if tag != 0x30:
        raise ValueError("PKIStatusInfo is not a SEQUENCE")
    tag, value_start, value_end = _read_tlv(response, info_start)
    if tag != 0x02:
        raise ValueError("PKIStatus is not an INTEGER")
    return int.from_bytes(response[value_start:value_end], "big", signed=True)


def _httpx_post(url: str, body: bytes, timeout: float) -> Tuple[int, bytes]:
    import httpx

    response = httpx.post(
        url,
        content=body,
        headers={"Content-Type": "application/timestamp-query"},
        timeout=timeout,
    )
    return response.status_code, response.content


def request_timestamp(
    url: str, digest: bytes, *, post: Optional[Poster] = None
) -> Optional[bytes]:
    """The TSA's TimeStampResp for digest, or None (logged) on any failure."""
    if urlsplit(url).scheme not in ("http", "https"):
        logger.warning(
            "AUDIT_TSA_URL must be an http(s) URL; checkpoint not timestamped"
        )
        return None
    sender = post if post is not None else _httpx_post
    try:
        status_code, content = sender(url, build_request(digest), _TIMEOUT_SECONDS)
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "Timestamp authority unreachable, checkpoint not timestamped: %s",
            type(e).__name__,
        )
        return None
    if status_code != 200:
        logger.warning(
            "Timestamp authority answered HTTP %s; checkpoint not timestamped",
            status_code,
        )
        return None
    try:
        status = response_status(content)
    except (ValueError, IndexError):
        logger.warning(
            "Timestamp authority sent an unreadable response; checkpoint not timestamped"
        )
        return None
    if status not in (0, 1):
        logger.warning("Timestamp authority refused the request (PKIStatus %s)", status)
        return None
    return content
