"""Keeper-compatible hybrid ECDH + ML-KEM request-envelope encryption.

This module deliberately contains no HTTP, endpoint selection, retry, or
configuration logic.  Those concerns belong to ``KeeperEndpoint``.
"""

from __future__ import annotations

import functools
from typing import Tuple

import attrs
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256, Hash
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ... import crypto

QRC_MESSAGE_VERSION = 1
MLKEM_1024_PUBLIC_KEY_SIZE = 1568
MLKEM_1024_CIPHERTEXT_SIZE = 1568
QRC_CIPHER_SUITE = "HPKE_ML-KEM-1024_ECDH-P256_HKDF-SHA256_AES-GCM-256"


@attrs.define(frozen=True, slots=True)
class QrcMessage:
    """Wire fields required by ``Authentication.QrcMessageKey``."""

    client_ec_public_key: bytes
    mlkem_encapsulated_key: bytes
    encrypted_transmission_key: bytes
    message_version: int = QRC_MESSAGE_VERSION


def _mlkem_encapsulation(server_public_key: bytes) -> Tuple[bytes, bytes]:
    if len(server_public_key) != MLKEM_1024_PUBLIC_KEY_SIZE:
        raise ValueError(
            f"Invalid ML-KEM-1024 public key size: {len(server_public_key)}"
        )

    try:
        from mlkem import MLKEM_1024_PARAMETERS, ML_KEM
    except ImportError as exc:
        raise RuntimeError("keeper-mlkem is not available") from exc

    try:
        shared_secret, encapsulated_key = ML_KEM(MLKEM_1024_PARAMETERS).encaps(
            server_public_key
        )
    except Exception as exc:
        raise RuntimeError("ML-KEM encapsulation failed") from exc

    if len(encapsulated_key) != MLKEM_1024_CIPHERTEXT_SIZE:
        raise ValueError(
            f"Invalid ML-KEM-1024 ciphertext size: {len(encapsulated_key)}"
        )
    return shared_secret, encapsulated_key


def _derive_key(
    ec_secret: bytes,
    mlkem_secret: bytes,
    server_ec_public_key: bytes,
    client_ec_public_key: bytes,
    mlkem_encapsulated_key: bytes,
) -> bytes:
    digest = Hash(SHA256(), backend=crypto._CRYPTO_BACKEND)
    digest.update(mlkem_encapsulated_key)
    ciphertext_hash = digest.finalize()

    context = (
        QRC_CIPHER_SUITE.encode("utf-8")
        + server_ec_public_key
        + client_ec_public_key
        + ciphertext_hash
        + QRC_MESSAGE_VERSION.to_bytes(1, "big")
    )
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=b"\x00" * 32,
        info=context,
        backend=crypto._CRYPTO_BACKEND,
    ).derive(ec_secret + mlkem_secret)


@functools.lru_cache(maxsize=None)
def is_available() -> bool:
    """Return whether the optional ML-KEM implementation can be imported (checked once)."""
    try:
        import mlkem  # noqa: F401
    except ImportError:
        return False
    return True


def encrypt_transmission_key(
    transmission_key: bytes,
    client_ec_private_key: ec.EllipticCurvePrivateKey,
    server_ec_public_key: ec.EllipticCurvePublicKey,
    server_mlkem_public_key: bytes,
) -> QrcMessage:
    """Create a Commander-compatible QRC message.

    The returned encrypted value protects the original AES transmission key;
    the API payload continues to be encrypted with that original key.
    """
    ec_secret = client_ec_private_key.exchange(ec.ECDH(), server_ec_public_key)
    mlkem_secret, encapsulated_key = _mlkem_encapsulation(server_mlkem_public_key)
    client_public = crypto.unload_ec_public_key(client_ec_private_key.public_key())
    server_public = crypto.unload_ec_public_key(server_ec_public_key)
    hybrid_key = _derive_key(
        ec_secret, mlkem_secret, server_public, client_public, encapsulated_key
    )
    return QrcMessage(
        client_ec_public_key=client_public,
        mlkem_encapsulated_key=encapsulated_key,
        encrypted_transmission_key=crypto.encrypt_aes_v2(transmission_key, hybrid_key),
    )
