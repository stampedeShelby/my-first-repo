"""Small cryptographic helpers used by every SignGate component.

Algorithms
- SHA-256 (FIPS 180-4)  : artifact fingerprint / integrity
- Ed25519 (RFC 8032)    : digital signatures (authenticity + non-repudiation)
- PKCS#8 + AES-256      : private keys encrypted at rest with a passphrase
"""
import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical(obj) -> bytes:
    """Deterministic JSON so the same data always produces the same signature."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def unb64(text: str) -> bytes:
    return base64.b64decode(text)


# ---------- keys ----------

def new_keypair():
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def public_raw(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def public_from_b64(text: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(unb64(text))


def key_id(pub: Ed25519PublicKey) -> str:
    """Short fingerprint of a public key (first 16 hex chars of SHA-256)."""
    return sha256_bytes(public_raw(pub))[:16]


def save_private(priv: Ed25519PrivateKey, path, passphrase: bytes):
    pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase),
    )
    with open(path, "wb") as f:
        f.write(pem)


def load_private(path, passphrase: bytes) -> Ed25519PrivateKey:
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=passphrase)


# ---------- sign / verify ----------

def sign(priv: Ed25519PrivateKey, obj) -> str:
    return b64(priv.sign(canonical(obj)))


def verify(pub: Ed25519PublicKey, obj, signature_b64: str) -> bool:
    try:
        pub.verify(unb64(signature_b64), canonical(obj))
        return True
    except (InvalidSignature, ValueError):
        return False
