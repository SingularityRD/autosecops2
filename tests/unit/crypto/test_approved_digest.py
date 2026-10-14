"""core.crypto.fips.approved_digest: the runtime gate for digest names that are
only known at runtime (W3.10 round 6; the inventory ratchet accepts a
non-literal ``hashlib.new`` name only when it comes through here)."""

import hashlib

import pytest

from core.crypto.fips import APPROVED_DIGESTS, approved_digest

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("sha256", "sha256"),
        ("SHA-256", "sha256"),
        (" SHA384 ", "sha384"),
        ("SHA3-256", "sha3_256"),
        ("sha3_512", "sha3_512"),
        ("SHA-512/256", "sha512_256"),
        ("shake_128", "shake_128"),
    ],
)
def test_approved_names_are_normalised(name, expected):
    assert approved_digest(name) == expected


@pytest.mark.parametrize(
    "name",
    ["md5", "MD5", "sha1", "SHA-1", "blake2b", "sm3", "ripemd160", "", "sha3256"],
)
def test_non_approved_names_raise(name):
    with pytest.raises(ValueError, match="not FIPS-approved"):
        approved_digest(name)


@pytest.mark.parametrize("name", sorted(APPROVED_DIGESTS))
def test_every_approved_name_is_a_hashlib_algorithm(name):
    assert hashlib.new(name).name == name
