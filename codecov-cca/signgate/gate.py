"""SignGate - the verify-before-execute gate that runs inside the customer's CI.

Instead of `curl https://codecov.io/bash | bash`, the pipeline runs
`python -m signgate.cli run --bucket ... --policy policy.json`.
Nothing is executed unless ALL checks pass, and even then the uploader only
sees the environment variables it actually needs.
"""
import json
import os
import subprocess
import time

from . import crypto_utils as cu
from . import pki
from .tlog import TransparencyLog, check_log


def _load(path):
    with open(path) as f:
        return json.load(f)


def _ver(v):
    return tuple(int(x) for x in v.split("."))


def verify(bucket, policy, state=None):
    """Runs every check in order. Returns (allowed: bool, report: list)."""
    if state is None:
        state = {}
    report = []

    def step(name, ok, reason):
        report.append({"check": name, "ok": ok, "reason": reason})
        return ok

    root_pub = cu.public_from_b64(policy["root_public_key"])  # pinned, never downloaded
    log_pub = cu.public_from_b64(policy["log_public_key"])
    artifact = f"{bucket}/codecov-uploader.sh"
    manifest = _load(f"{bucket}/manifest.json")
    body = manifest["body"]

    # 1. Is the signing key vouched for by the pinned root?
    ok, why, release_pub = pki.check_key_certificate(manifest["key_certificate"], root_pub)
    if not step("1. Key certificate (PKI)", ok, why):
        return False, report
    if not step("   key_id matches manifest", body["key_id"] == cu.key_id(release_pub),
                "manifest key_id vs certified key"):
        return False, report

    # 2. Has the key or artifact been revoked?
    ok, why = pki.check_revocation(_load(f"{bucket}/crl.json"), root_pub,
                                   body["key_id"], body["sha256"])
    if not step("2. Revocation list", ok, why):
        return False, report

    # 3. Authenticity: manifest signed by the certified release key?
    ok = cu.verify(release_pub, body, manifest["signature"])
    if not step("3. Ed25519 signature", ok,
                "manifest signature valid" if ok else "manifest signature INVALID (forged/edited)"):
        return False, report

    # 4. Integrity: does the downloaded file match the signed SHA-256?
    actual = cu.sha256_file(artifact)
    ok = actual == body["sha256"] and os.path.getsize(artifact) == body["size"]
    if not step("4. SHA-256 integrity", ok,
                "artifact hash matches signed manifest" if ok
                else f"HASH MISMATCH: expected {body['sha256'][:12]}.. got {actual[:12]}.."):
        return False, report

    # 5. Anti-rollback: no downgrade to an older (possibly vulnerable) release
    floor = max(_ver(policy.get("min_version", "0.0.0")), _ver(state.get("last_version", "0.0.0")))
    ok = _ver(body["version"]) >= floor
    if not step("5. Anti-rollback", ok,
                f"version {body['version']} is current" if ok
                else f"version {body['version']} older than {'.'.join(map(str, floor))} (downgrade)"):
        return False, report

    # 6. Transparency: every legitimate release is publicly logged
    log = TransparencyLog(f"{bucket}/tlog.json")
    ok, why = check_log(log, _load(f"{bucket}/tlog_head.json"), log_pub, body,
                        state.get("last_log_size", 0))
    if not step("6. Transparency log", ok, why):
        return False, report

    state["last_version"] = body["version"]
    state["last_log_size"] = len(log.entries)
    return True, report


def minimal_env(allowlist):
    """Least privilege: pass only the variables the uploader genuinely needs."""
    return {k: v for k, v in os.environ.items() if k in allowlist}


def run(bucket, policy, state=None, extra_env=None):
    """Verify, then execute with a reduced environment. Returns (allowed, report, output)."""
    t0 = time.perf_counter()
    allowed, report = verify(bucket, policy, state)
    ms = (time.perf_counter() - t0) * 1000
    if not allowed:
        return False, report, f"BLOCKED before execution ({ms:.1f} ms)"
    env = minimal_env(policy.get("env_allowlist", []))
    env.update(extra_env or {})
    out = subprocess.run(["bash", f"{bucket}/codecov-uploader.sh"], env=env,
                         capture_output=True, text=True, timeout=30)
    return True, report, out.stdout + out.stderr


def print_report(report):
    for r in report:
        print(f"  [{'PASS' if r['ok'] else 'FAIL'}] {r['check']:<28} {r['reason']}")
