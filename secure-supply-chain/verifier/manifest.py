"""Signed-manifest parsing and schema validation.

The manifest binds together, under ONE signature:
artifact name + version + SHA-256 + detached artifact signature + signer key ID
+ timestamp + provenance. Changing any field (e.g. swapping in the hash of a
malicious file, or relabelling an old version as new) invalidates the
signature, which is what makes the release traceable and non-repudiable.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

REQUIRED_FIELDS = {
    "artifact": str, "version": str, "filename": str, "size": int, "sha256": str,
    "algorithm": str, "signature_algorithm": str, "signer": str, "key_id": str,
    "timestamp": str, "artifact_signature": str, "provenance": dict, "provenance_sha256": str,
}
REQUIRED_PROVENANCE = {
    "source_repository": str, "commit_id": str, "build_id": str, "build_timestamp": str,
    "builder_identity": str, "dependencies": list, "security_tests": dict, "artifact_sha256": str,
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ManifestError(Exception):
    pass


def load_envelope(path: str | Path) -> dict:
    try:
        env = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read manifest: {exc}") from exc
    validate_envelope(env)
    return env


def validate_envelope(env: dict) -> None:
    if not isinstance(env, dict) or not isinstance(env.get("manifest"), dict):
        raise ManifestError("missing 'manifest' object")
    sigs = env.get("signatures")
    if not isinstance(sigs, list) or not sigs or not all(
            isinstance(s, dict) and isinstance(s.get("key_id"), str) and isinstance(s.get("sig"), str)
            for s in sigs):
        raise ManifestError("missing or malformed 'signatures'")
    m = env["manifest"]
    for field, typ in REQUIRED_FIELDS.items():
        if not isinstance(m.get(field), typ):
            raise ManifestError(f"field '{field}' missing or not {typ.__name__}")
    for field, typ in REQUIRED_PROVENANCE.items():
        if not isinstance(m["provenance"].get(field), typ):
            raise ManifestError(f"provenance field '{field}' missing or not {typ.__name__}")
    for field in ("sha256", "provenance_sha256"):
        if not HEX64.match(m[field]):
            raise ManifestError(f"'{field}' is not a SHA-256 hex digest")
    if sigs[0]["key_id"] != m["key_id"]:
        raise ManifestError("envelope key_id does not match manifest key_id")
