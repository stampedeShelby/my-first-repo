"""Scenario 3 – signing with an untrusted, impersonated or stolen/revoked key.

(a) attacker signs with their own Ed25519 key          -> UNAUTHORIZED_KEY
(b) attacker claims the vendor's key_id but signs with  -> INVALID_SIGNATURE
    their own key (impersonation)
(c) attacker steals the real release key and signs a    -> passes crypto checks
    malicious build; vendor detects it in the audit log    until the key is
    and revokes the key                                     revoked -> REVOKED
"""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from attack_simulation.tamper import inject_codecov_style_payload
from common.crypto_utils import CTX_ARTIFACT, CTX_MANIFEST, canonical_json, key_id_for, sha256_bytes, sign
from common.workspace import write_json


def resign_manifest(manifest: Path, artifact: Path, private_key: Ed25519PrivateKey,
                    claimed_key_id: str | None = None) -> None:
    """Rewrite the manifest for the (tampered) artifact and sign it with `private_key`."""
    env = json.loads(manifest.read_text())
    m = env["manifest"]
    data = artifact.read_bytes()
    key_id = claimed_key_id or key_id_for(private_key.public_key())
    m["sha256"] = sha256_bytes(data)
    m["size"] = len(data)
    m["key_id"] = key_id
    m["provenance"]["artifact_sha256"] = m["sha256"]
    m["provenance_sha256"] = sha256_bytes(canonical_json(m["provenance"]))
    m["artifact_signature"] = sign(private_key, CTX_ARTIFACT, data)
    env["signatures"] = [{"key_id": key_id, "sig": sign(private_key, CTX_MANIFEST, canonical_json(m))}]
    write_json(manifest, env)


def attacker_signs_with_own_key(artifact: Path, manifest: Path) -> str:
    inject_codecov_style_payload(artifact)
    attacker = Ed25519PrivateKey.generate()
    resign_manifest(manifest, artifact, attacker)
    return key_id_for(attacker.public_key())


def attacker_impersonates_vendor_key(artifact: Path, manifest: Path) -> None:
    vendor_key_id = json.loads(manifest.read_text())["manifest"]["key_id"]
    inject_codecov_style_payload(artifact)
    resign_manifest(manifest, artifact, Ed25519PrivateKey.generate(), claimed_key_id=vendor_key_id)


def attacker_uses_stolen_key(artifact: Path, manifest: Path, stolen_key: Ed25519PrivateKey) -> None:
    inject_codecov_style_payload(artifact)
    resign_manifest(manifest, artifact, stolen_key)
