"""Checkpoint signature algorithm choice: Ed25519 by default, ECDSA P-256 under FIPS."""

import pytest

from core.crypto import signing

pytestmark = pytest.mark.unit

MESSAGE = b'{"chain":"approvals","head":"ab12","seq":42}'


def test_fips_mode_selects_ecdsa_p256_and_default_ed25519():
    assert signing.checkpoint_algorithm(fips_mode=True) == "ecdsa-p256"
    assert signing.checkpoint_algorithm(fips_mode=False) == "ed25519"


def test_algorithm_follows_settings(monkeypatch):
    import core.config as config_module

    settings = config_module.get_settings().model_copy(update={"fips_mode": True})
    monkeypatch.setattr(config_module, "get_settings", lambda: settings)
    assert signing.checkpoint_algorithm() == "ecdsa-p256"


@pytest.mark.parametrize("alg", signing.ALGORITHMS)
def test_sign_verify_round_trip_through_pem(alg):
    key = signing.generate_private_key(alg)
    reloaded = signing.load_private_key(signing.private_key_pem(key), alg)
    public = signing.load_public_key(signing.public_key_pem(reloaded), alg)

    got_alg, signature = signing.sign(reloaded, MESSAGE)

    assert got_alg == alg
    assert signing.verify(public, alg, MESSAGE, signature)
    assert not signing.verify(public, alg, MESSAGE + b" ", signature)
    assert not signing.verify(public, alg, MESSAGE, "not base64!")


def test_algorithm_label_must_match_key():
    ec_key = signing.generate_private_key("ecdsa-p256")
    _, signature = signing.sign(ec_key, MESSAGE)
    public = signing.load_public_key(signing.public_key_pem(ec_key))
    assert not signing.verify(public, "ed25519", MESSAGE, signature)


def test_wrong_key_does_not_verify():
    a = signing.generate_private_key("ecdsa-p256")
    b = signing.generate_private_key("ecdsa-p256")
    _, signature = signing.sign(a, MESSAGE)
    assert not signing.verify(b.public_key(), "ecdsa-p256", MESSAGE, signature)


def test_loading_a_key_of_the_other_algorithm_is_refused():
    ed_pem = signing.private_key_pem(signing.generate_private_key("ed25519"))
    with pytest.raises(signing.SigningKeyError, match="expected ecdsa-p256"):
        signing.load_private_key(ed_pem, "ecdsa-p256")
    with pytest.raises(signing.SigningKeyError):
        signing.load_public_key("garbage")


def test_other_curves_are_refused():
    from cryptography.hazmat.primitives.asymmetric import ec

    with pytest.raises(signing.SigningKeyError, match="secp384r1"):
        signing.algorithm_of(ec.generate_private_key(ec.SECP384R1()))


def test_unknown_algorithm_is_refused():
    with pytest.raises(signing.SigningKeyError):
        signing.generate_private_key("rsa")  # type: ignore[arg-type]


def test_unsupported_algorithm_from_the_backend_is_a_false_not_a_raise(monkeypatch):
    """A FIPS-only OpenSSL raises UnsupportedAlgorithm for Ed25519; verify()
    must answer False rather than 500 the caller."""
    from cryptography.exceptions import UnsupportedAlgorithm

    key = signing.generate_private_key("ed25519")
    _, signature = signing.sign(key, MESSAGE)

    class _Refusing:
        def __init__(self, inner):
            self._inner = inner

        def verify(self, *_a, **_k):
            raise UnsupportedAlgorithm("ed25519 not available in FIPS provider")

    public = key.public_key()
    monkeypatch.setattr(signing, "algorithm_of", lambda _k: "ed25519")
    assert not signing.verify(_Refusing(public), "ed25519", MESSAGE, signature)
