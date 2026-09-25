"""Shared cryptographic helpers.

Security notes
--------------
* SHA-256 is used only as an *integrity fingerprint*. A hash on its own proves
  nothing about who produced a file: an attacker who can replace the file can
  usually replace the published hash as well (exactly the Codecov situation).
* Authenticity comes from Ed25519 signatures (RFC 8032) made with a private key
  that never leaves the signing service.
* Every signature uses a domain-separation prefix so that a signature produced
  for one purpose (e.g. a manifest) can never be replayed as a signature for
  another purpose (e.g. a raw artifact or a trust policy).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Domain-separation contexts (prefixed to the signed message).
CTX_ARTIFACT = b"SSCS-v1/artifact\n"
CTX_MANIFEST = b"SSCS-v1/manifest\n"
CTX_TRUST_POLICY = b"SSCS-v1/trust-policy\n"

HASH_CHUNK = 64 * 1024


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    """Stream a file through SHA-256 so large artifacts do not need to fit in memory."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(HASH_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def digests_equal(a: str, b: str) -> bool:
    """Constant-time comparison of two hex digests."""
    return hmac.compare_digest(a.encode(), b.encode())


def canonical_json(obj) -> bytes:
    """Deterministic JSON encoding: the exact bytes that get signed."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def utc_now_iso() -> str:
    return utc_now().isoformat().replace("+00:00", "Z")


def parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


# --------------------------------------------------------------------------- keys

def public_key_raw(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id_for(public_key: Ed25519PublicKey) -> str:
    """Key identifier = first 16 hex chars of SHA-256(raw public key)."""
    return "ed25519:" + sha256_bytes(public_key_raw(public_key))[:16]


def public_key_to_pem(public_key: Ed25519PublicKey) -> str:
    return public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")


def load_public_key_pem(pem: str | bytes) -> Ed25519PublicKey:
    if isinstance(pem, str):
        pem = pem.encode("ascii")
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("only Ed25519 public keys are accepted")
    return key


def sign(private_key: Ed25519PrivateKey, context: bytes, message: bytes) -> str:
    return b64e(private_key.sign(context + message))


def verify(public_key: Ed25519PublicKey, context: bytes, message: bytes, signature_b64: str) -> bool:
    try:
        public_key.verify(b64d(signature_b64), context + message)
        return True
    except (InvalidSignature, ValueError):
        return False
