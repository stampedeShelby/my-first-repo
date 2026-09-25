"""Customer-side policies.

* :class:`TrustPolicy` – the vendor's root-signed list of release keys and
  revocations. It is only accepted if the signature verifies against the
  root public key the customer pinned out-of-band, it has not expired, and
  its version is not older than one already seen (prevents an attacker on
  the registry from replaying an old policy in which a stolen key was still
  active – a "freeze"/rollback attack).
* :class:`CustomerPolicy` – local deployment rules (approved builders, source
  repositories, algorithms, anti-rollback, maximum manifest age ...).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from common.crypto_utils import CTX_TRUST_POLICY, canonical_json, key_id_for, load_public_key_pem, parse_iso, utc_now, verify
from common.workspace import read_json


class TrustPolicyError(Exception):
    pass


@dataclass
class TrustPolicy:
    version: int
    keys: dict
    revoked_artifacts: list
    minimum_versions: dict
    expires_at: str

    @classmethod
    def load(cls, policy_path: Path, trusted_root_path: Path, min_version_seen: int = 0) -> "TrustPolicy":
        if not trusted_root_path.exists():
            raise TrustPolicyError("no pinned root public key (trust anchor) configured")
        root = load_public_key_pem(trusted_root_path.read_text())
        env = read_json(policy_path)
        if not env or "policy" not in env or "signature" not in env:
            raise TrustPolicyError("trust policy missing or malformed")
        policy = env["policy"]
        if env.get("signed_by") != key_id_for(root) or policy.get("root_key_id") != key_id_for(root):
            raise TrustPolicyError("trust policy not signed by the pinned root key")
        if not verify(root, CTX_TRUST_POLICY, canonical_json(policy), env["signature"]):
            raise TrustPolicyError("trust policy signature INVALID (tampered or forged)")
        if parse_iso(policy["expires_at"]) < utc_now():
            raise TrustPolicyError("trust policy expired (possible freeze attack)")
        if policy["version"] < min_version_seen:
            raise TrustPolicyError(
                f"trust policy rollback: version {policy['version']} < previously seen {min_version_seen}")
        return cls(policy["version"], policy["keys"], policy["revoked_artifacts"],
                   policy["minimum_versions"], policy["expires_at"])

    def is_artifact_revoked(self, artifact: str, version: str) -> str | None:
        for r in self.revoked_artifacts:
            if r["artifact"] == artifact and r["version"] == version:
                return r.get("reason", "revoked")
        return None


@dataclass
class CustomerPolicy:
    allowed_hash_algorithms: list = field(default_factory=lambda: ["SHA-256"])
    allowed_signature_algorithms: list = field(default_factory=lambda: ["Ed25519"])
    allow_retired_keys_for_old_releases: bool = True
    approved_builders: list = field(default_factory=list)
    approved_source_repositories: list = field(default_factory=list)
    anti_rollback: bool = True
    max_manifest_age_days: int = 365
    require_provenance: bool = True
    require_security_tests_passed: bool = True
    scan_artifact_content: bool = True

    @classmethod
    def load(cls, path: Path) -> "CustomerPolicy":
        data = {k: v for k, v in (read_json(path, {}) or {}).items() if not k.startswith("_")}
        return cls(**data)
