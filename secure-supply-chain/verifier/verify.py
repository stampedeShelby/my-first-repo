"""Customer verification engine.

A customer accepts an artifact only if it can prove BOTH:

1. **Integrity** – the bytes are exactly the ones the vendor built
   (SHA-256 recomputed locally == SHA-256 inside the signed manifest, and the
   detached Ed25519 artifact signature verifies).
2. **Authenticity / authorisation** – the manifest was signed by a release key
   that the vendor's root-signed trust policy lists as valid, which is not
   revoked, for a version that is not revoked or rolled back, built by an
   approved builder from an approved repository.

All checks are always evaluated (no short-circuit) so the report shows every
problem; the *primary* status is the first failing check in the order below.
"""

from __future__ import annotations

import argparse
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from enum import Enum
from pathlib import Path

from common.crypto_utils import (
    CTX_ARTIFACT, CTX_MANIFEST, canonical_json, digests_equal, load_public_key_pem, parse_iso,
    sha256_bytes, utc_now, verify,
)
from common.security_rules import run_security_tests
from common.workspace import Workspace, parse_version, read_json
from verifier.manifest import ManifestError, load_envelope
from verifier.policy import CustomerPolicy, TrustPolicy, TrustPolicyError


class Status(str, Enum):
    PASS = "PASS"
    INVALID_TRUST_POLICY = "INVALID_TRUST_POLICY"
    INVALID_MANIFEST = "INVALID_MANIFEST"
    UNAUTHORIZED_KEY = "UNAUTHORIZED_KEY"
    REVOKED = "REVOKED"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    HASH_MISMATCH = "HASH_MISMATCH"
    REPLAY_BLOCKED = "REPLAY_BLOCKED"
    INVALID_PROVENANCE = "INVALID_PROVENANCE"
    POLICY_VIOLATION = "POLICY_VIOLATION"


@dataclass
class Check:
    name: str
    passed: bool
    status: Status
    detail: str


@dataclass
class VerificationResult:
    artifact: str | None = None
    version: str | None = None
    key_id: str | None = None
    expected_sha256: str | None = None
    actual_sha256: str | None = None
    trust_policy_version: int | None = None
    checks: list[Check] = field(default_factory=list)
    elapsed_ms: float = 0.0

    @property
    def passed(self) -> bool:
        return bool(self.checks) and all(c.passed for c in self.checks)

    @property
    def status(self) -> Status:
        for c in self.checks:
            if not c.passed:
                return c.status
        return Status.PASS if self.checks else Status.INVALID_MANIFEST

    @property
    def reasons(self) -> list[str]:
        return [f"{c.name}: {c.detail}" for c in self.checks if not c.passed]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        d["passed"] = self.passed
        for c in d["checks"]:
            c["status"] = c["status"].value
        return d


class Verifier:
    def __init__(self, ws: Workspace):
        self.ws = ws
        self.policy = CustomerPolicy.load(ws.customer_policy)

    def _state(self) -> dict:
        return read_json(self.ws.customer_state, {"trust_policy_version_seen": 0, "deployed": {}})

    def verify(self, artifact_path: str | Path, manifest_path: str | Path) -> VerificationResult:
        t0 = time.perf_counter()
        res = VerificationResult()
        add = lambda name, ok, st, detail: res.checks.append(Check(name, ok, st, detail))  # noqa: E731
        state = self._state()

        # 1. trust policy (root of trust) -----------------------------------------
        try:
            trust = TrustPolicy.load(self.ws.trust_policy, self.ws.trusted_root,
                                     state.get("trust_policy_version_seen", 0))
            res.trust_policy_version = trust.version
            add("trust_policy", True, Status.PASS, f"root signature valid, policy v{trust.version}")
        except (TrustPolicyError, ValueError, KeyError) as exc:
            add("trust_policy", False, Status.INVALID_TRUST_POLICY, str(exc))
            res.elapsed_ms = (time.perf_counter() - t0) * 1000
            return res

        # 2. manifest schema ------------------------------------------------------
        try:
            env = load_envelope(manifest_path)
            m = env["manifest"]
            add("manifest_schema", True, Status.PASS, "all required fields present")
        except ManifestError as exc:
            add("manifest_schema", False, Status.INVALID_MANIFEST, str(exc))
            res.elapsed_ms = (time.perf_counter() - t0) * 1000
            return res
        res.artifact, res.version, res.key_id, res.expected_sha256 = (
            m["artifact"], m["version"], m["key_id"], m["sha256"])

        # 3. signer authorised (key known to the trust policy) ---------------------
        key_meta = trust.keys.get(m["key_id"])
        public_key = None
        if key_meta is None:
            add("signer_authorized", False, Status.UNAUTHORIZED_KEY,
                f"key {m['key_id']} is not in the vendor trust policy")
        else:
            public_key = load_public_key_pem(key_meta["public_key"])
            add("signer_authorized", True, Status.PASS, f"key {m['key_id']} is a vendor release key")

        # 4. key status (revocation / old-key invalidation) ------------------------
        if key_meta is not None:
            st = key_meta["status"]
            if st == "active":
                add("key_status", True, Status.PASS, "signing key is active")
            elif st == "retired" and self.policy.allow_retired_keys_for_old_releases and \
                    parse_iso(m["timestamp"]) <= parse_iso(key_meta["retired_at"]):
                add("key_status", True, Status.PASS, "retired key, but release predates rotation")
            elif st == "retired":
                add("key_status", False, Status.REVOKED, "retired key used after its retirement")
            else:
                add("key_status", False, Status.REVOKED,
                    f"signing key REVOKED at {key_meta.get('revoked_at')} "
                    f"({key_meta.get('revocation_reason', 'no reason')})")

        # 5. manifest signature ------------------------------------------------------
        if public_key is not None:
            ok = verify(public_key, CTX_MANIFEST, canonical_json(m), env["signatures"][0]["sig"])
            add("manifest_signature", ok, Status.PASS if ok else Status.INVALID_SIGNATURE,
                "Ed25519 manifest signature valid" if ok else "manifest signature INVALID (manifest modified or forged)")

        # 6. SHA-256 integrity -------------------------------------------------------
        try:
            data = Path(artifact_path).read_bytes()
        except OSError as exc:
            add("sha256", False, Status.HASH_MISMATCH, f"artifact unreadable: {exc}")
            data = None
        if data is not None:
            res.actual_sha256 = sha256_bytes(data)
            ok = digests_equal(res.actual_sha256, m["sha256"])
            add("sha256", ok, Status.PASS if ok else Status.HASH_MISMATCH,
                "digest matches signed manifest" if ok else
                f"expected {m['sha256'][:16]}... got {res.actual_sha256[:16]}...")

        # 7. detached artifact signature --------------------------------------------
            if public_key is not None:
                ok = verify(public_key, CTX_ARTIFACT, data, m["artifact_signature"])
                add("artifact_signature", ok, Status.PASS if ok else Status.INVALID_SIGNATURE,
                    "Ed25519 artifact signature valid" if ok else "artifact signature INVALID (content modified)")

        # 8. artifact / version status (revocation + anti-rollback / replay) ------
        reason = trust.is_artifact_revoked(m["artifact"], m["version"])
        min_v = trust.minimum_versions.get(m["artifact"])
        deployed = state["deployed"].get(m["artifact"])
        try:
            ver = parse_version(m["version"])
            if reason:
                add("artifact_status", False, Status.REVOKED, f"version {m['version']} revoked by vendor: {reason}")
            elif min_v and ver < parse_version(min_v):
                add("artifact_status", False, Status.REPLAY_BLOCKED,
                    f"version {m['version']} below vendor minimum {min_v}")
            elif self.policy.anti_rollback and deployed and ver < parse_version(deployed["version"]):
                add("artifact_status", False, Status.REPLAY_BLOCKED,
                    f"rollback: {m['version']} older than deployed {deployed['version']}")
            elif deployed and ver == parse_version(deployed["version"]) and deployed["sha256"] != m["sha256"]:
                add("artifact_status", False, Status.POLICY_VIOLATION,
                    "same version previously deployed with a different digest (equivocation)")
            else:
                add("artifact_status", True, Status.PASS, "version not revoked, no rollback")
        except ValueError as exc:
            add("artifact_status", False, Status.INVALID_MANIFEST, str(exc))

        # 9. provenance -------------------------------------------------------------
        p = m["provenance"]
        problems = []
        if not digests_equal(sha256_bytes(canonical_json(p)), m["provenance_sha256"]):
            problems.append("provenance digest mismatch")
        if p["artifact_sha256"] != m["sha256"]:
            problems.append("provenance describes a different artifact")
        if self.policy.approved_builders and p["builder_identity"] not in self.policy.approved_builders:
            problems.append(f"builder '{p['builder_identity']}' not approved")
        if self.policy.approved_source_repositories and \
                p["source_repository"] not in self.policy.approved_source_repositories:
            problems.append(f"source repository '{p['source_repository']}' not approved")
        if self.policy.require_provenance:
            add("provenance", not problems, Status.PASS if not problems else Status.INVALID_PROVENANCE,
                "approved builder + repository, provenance bound to artifact" if not problems else "; ".join(problems))

        # 10. security policy --------------------------------------------------------
        violations = []
        if m["algorithm"] not in self.policy.allowed_hash_algorithms:
            violations.append(f"hash algorithm {m['algorithm']} not allowed")
        if m["signature_algorithm"] not in self.policy.allowed_signature_algorithms:
            violations.append(f"signature algorithm {m['signature_algorithm']} not allowed")
        if self.policy.require_security_tests_passed and not p["security_tests"].get("passed"):
            violations.append("vendor security tests did not pass")
        if self.policy.scan_artifact_content and data is not None:
            scan = run_security_tests(data.decode("utf-8", errors="replace"))
            if not scan["passed"]:
                rules = sorted({f["rule"] for f in scan["findings"]})
                violations.append(f"content scan found exfiltration pattern(s): {', '.join(rules)}")
        try:
            if utc_now() - parse_iso(m["timestamp"]) > timedelta(days=self.policy.max_manifest_age_days):
                violations.append("manifest older than allowed maximum age")
        except ValueError:
            violations.append("invalid manifest timestamp")
        add("security_policy", not violations, Status.PASS if not violations else Status.POLICY_VIOLATION,
            "all policy rules satisfied" if not violations else "; ".join(violations))

        res.elapsed_ms = (time.perf_counter() - t0) * 1000
        return res


def print_result(res: VerificationResult) -> None:
    from common.console import bold, green, red

    print(bold(f"\nVerification report: {res.artifact}@{res.version}  (key {res.key_id})"))
    if res.expected_sha256:
        print(f"  expected SHA-256 : {res.expected_sha256}")
    if res.actual_sha256:
        same = res.actual_sha256 == res.expected_sha256
        print(f"  actual   SHA-256 : " + (green(res.actual_sha256) if same else red(res.actual_sha256)))
    for c in res.checks:
        tag = green("  PASS ") if c.passed else red(f"  FAIL ")
        print(f"{tag} {c.name:20} {c.detail}")
    verdict = green("PASS") if res.passed else red(res.status.value)
    print(bold(f"  RESULT: {verdict}   ({res.elapsed_ms:.2f} ms)"))


def main() -> None:
    ap = argparse.ArgumentParser(description="Verify a downloaded artifact against its signed manifest")
    ap.add_argument("--artifact", required=True)
    ap.add_argument("--manifest", required=True)
    args = ap.parse_args()
    res = Verifier(Workspace.default()).verify(args.artifact, args.manifest)
    print_result(res)
    sys.exit(0 if res.passed else 1)


if __name__ == "__main__":
    main()
