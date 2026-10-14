"""Key formats, signing and the RFC 3161 request, with no database or network."""

from __future__ import annotations

import base64
import hashlib

import pytest
from cryptography.hazmat.primitives import serialization

from core.audit import checkpoint, tsa

pytestmark = pytest.mark.unit


def test_key_formats_load_to_the_same_key():
    seed, public = checkpoint.generate_key()
    raw = bytes.fromhex(seed)
    private = checkpoint.load_private_key(seed)
    pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    for value in (seed, base64.b64encode(raw).decode(), pem):
        key = checkpoint.load_private_key(value)
        assert checkpoint.public_hex(key.public_key()) == public
    pub_pem = (
        private.public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode()
    )
    for value in (public, base64.b64encode(bytes.fromhex(public)).decode(), pub_pem):
        assert checkpoint.public_hex(checkpoint.load_public_key(value)) == public
    assert checkpoint.key_id(private.public_key()) == (
        hashlib.sha256(bytes.fromhex(public)).hexdigest()[:16]
    )


@pytest.mark.parametrize(
    "value", ["", "zz", "a" * 63, base64.b64encode(b"x" * 31).decode()]
)
def test_bad_keys_are_refused(value):
    with pytest.raises(ValueError):
        checkpoint.load_private_key(value)


def test_missing_secret_skips_the_job(monkeypatch, caplog):
    monkeypatch.setattr(checkpoint, "get_secret", lambda name, default=None: None)
    with caplog.at_level("WARNING"):
        assert checkpoint.run_checkpoint(engine=None) is None
    assert checkpoint.SIGNING_KEY_SECRET in caplog.text


def _signed(key, body):
    return base64.b64encode(key.sign(body.encode())).decode()


def test_signature_check():
    key = checkpoint.load_private_key(checkpoint.generate_key()[0])
    public = key.public_key()
    kid = checkpoint.key_id(public)
    body = checkpoint.canonical_json({"key_id": kid, "prev": "", "v": 1})
    digest = hashlib.sha256(body.encode()).hexdigest()
    args = (kid, checkpoint.public_hex(public), body, digest, "", _signed(key, body))
    assert checkpoint._check_one(public, "s", *args, expected_prev="") is None
    tampered = body.replace('"v":1', '"v":2')
    bad = (
        kid,
        args[1],
        tampered,
        hashlib.sha256(tampered.encode()).hexdigest(),
        "",
        args[5],
    )
    found = checkpoint._check_one(public, "s", *bad, expected_prev="")
    assert found.reason == "checkpoint_signature"


def test_timestamp_request_is_der():
    digest = hashlib.sha256(b"body").digest()
    request = tsa.build_request(digest, nonce=0x80)
    # SEQUENCE { INTEGER 1, SEQUENCE { SEQUENCE { OID sha256, NULL },
    #   OCTET STRING digest }, INTEGER nonce, BOOLEAN TRUE }
    expected = (
        bytes.fromhex("303d" "020101" "3031" "300d0609608648016503040201" "0500" "0420")
        + digest
        + bytes.fromhex("02020080" "0101ff")
    )
    assert request == expected


@pytest.mark.parametrize(
    "response, status",
    [
        ("30053003020100", 0),  # granted
        ("30053003020101", 1),  # grantedWithMods
        ("30053003020102", 2),  # rejection
    ],
)
def test_response_status(response, status):
    assert tsa.response_status(bytes.fromhex(response)) == status


def test_request_timestamp_never_raises():
    digest = hashlib.sha256(b"x").digest()
    url = "https://tsa.invalid/"

    def refused(u, b, t):
        return 200, bytes.fromhex("30053003020102")

    def http_error(u, b, t):
        return 500, b""

    def unreachable(u, b, t):
        raise OSError("no network in tests")

    def garbage(u, b, t):
        return 200, b"\x01"

    for poster in (refused, http_error, unreachable, garbage):
        assert tsa.request_timestamp(url, digest, post=poster) is None
    assert tsa.request_timestamp("file:///etc/passwd", digest, post=refused) is None
    granted = bytes.fromhex("30053003020100")
    assert (
        tsa.request_timestamp(url, digest, post=lambda u, b, t: (200, granted))
        == granted
    )
