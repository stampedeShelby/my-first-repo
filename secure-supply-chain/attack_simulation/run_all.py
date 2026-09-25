"""Run every attack scenario in a fresh, isolated workspace and print a summary.

    python -m attack_simulation.run_all

Scenarios
  1  Legitimate artifact                        -> DEPLOY
  2  Tampered artifact (Codecov-style line)     -> BLOCK  HASH_MISMATCH + INVALID_SIGNATURE
  2b Tampered artifact + forged manifest hash   -> BLOCK  INVALID_SIGNATURE
  3a Attacker's own signing key                 -> BLOCK  UNAUTHORIZED_KEY
  3b Attacker impersonates vendor key ID        -> BLOCK  INVALID_SIGNATURE
  3c Stolen vendor key, key then revoked        -> BLOCK  REVOKED
  3d Unauthorized signing attempt (RBAC/MFA)    -> BLOCK  UNAUTHORIZED_SIGNER
  4  Replay of an old / revoked version         -> BLOCK  REVOKED / REPLAY_BLOCKED
  5  Compromised registry replaces trust policy -> BLOCK  INVALID_TRUST_POLICY
  6  Restore legitimate artifact                -> DEPLOY
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from attack_simulation.revoked_key_test import (
    attacker_impersonates_vendor_key, attacker_signs_with_own_key, attacker_uses_stolen_key,
)
from attack_simulation.tamper import forge_manifest_hash, inject_codecov_style_payload
from bootstrap import bootstrap
from ci.security_gate import SecurityGate
from common.console import banner, bold, green, red
from common.workspace import PROJECT_ROOT, Workspace, write_json
from vendor.access_control import AccessDenied
from vendor.build import build
from vendor.key_manager import KeyManager
from vendor.sign import SigningService, publish, release


def _copy_release(ws: Workspace, reg_a: Path, reg_m: Path, tag: str) -> tuple[Path, Path]:
    """Customer-side working copy of a published release (so scenarios do not interfere)."""
    d = ws.downloads_dir / tag
    d.mkdir(parents=True, exist_ok=True)
    return Path(shutil.copy2(reg_a, d / reg_a.name)), Path(shutil.copy2(reg_m, d / reg_m.name))


def run(ws: Workspace) -> list[dict]:
    bootstrap(ws, reset=True)
    gate = SecurityGate(ws)
    rows: list[dict] = []

    def record(sid, name, expected, decision, status, detail=""):
        ok = decision == expected
        rows.append({"id": sid, "scenario": name, "expected": expected, "actual": decision,
                     "status_code": status, "result": "PASS" if ok else "FAIL", "detail": detail})
        print(f"  {sid:3} {name:48} expected {expected:6} got {decision:6} "
              f"{status:22} {green('OK') if ok else red('UNEXPECTED')}")

    # 1 legitimate release 1.0.0
    _, _, a100, m100 = release(ws, "1.0.0")
    a, m = _copy_release(ws, a100, m100, "s1")
    d = gate.evaluate(a, m)
    record("1", "Legitimate artifact v1.0.0", "DEPLOY", d.decision, d.result.status.value)

    # 2 tampered artifact
    a, m = _copy_release(ws, a100, m100, "s2")
    inject_codecov_style_payload(a)
    d = gate.evaluate(a, m, deploy=False)
    fails = ",".join(c.name for c in d.result.checks if not c.passed)
    record("2", "Tampered artifact (1 line added)", "BLOCK", d.decision, d.result.status.value, fails)

    # 2b tampered + manifest hash forged
    a, m = _copy_release(ws, a100, m100, "s2b")
    forge_manifest_hash(m, inject_codecov_style_payload(a))
    d = gate.evaluate(a, m, deploy=False)
    record("2b", "Tampered artifact + forged manifest hash", "BLOCK", d.decision, d.result.status.value)

    # 3a attacker key
    a, m = _copy_release(ws, a100, m100, "s3a")
    attacker_signs_with_own_key(a, m)
    d = gate.evaluate(a, m, deploy=False)
    record("3a", "Signed with attacker's own key", "BLOCK", d.decision, d.result.status.value)

    # 3b impersonation
    a, m = _copy_release(ws, a100, m100, "s3b")
    attacker_impersonates_vendor_key(a, m)
    d = gate.evaluate(a, m, deploy=False)
    record("3b", "Attacker claims vendor key ID", "BLOCK", d.decision, d.result.status.value)

    # 3d unauthorized signing attempt (developer role / wrong MFA)
    svc = SigningService(ws)
    b = build(ws, "1.0.1")
    try:
        svc.sign_release(user="bob", otp=svc.acl.current_otp("bob"), artifact_path=b.artifact_path,
                         version="1.0.1", provenance=b.provenance)
        decision, status = "DEPLOY", "SIGNED"
    except AccessDenied:
        decision, status = "BLOCK", "UNAUTHORIZED_SIGNER"
    record("3d", "Unauthorized signing attempt (bob, developer)", "BLOCK", decision, status)
    try:
        svc.sign_release(user="alice", otp="000000", artifact_path=b.artifact_path, version="1.0.1",
                         provenance=b.provenance)
        decision, status = "DEPLOY", "SIGNED"
    except AccessDenied:
        decision, status = "BLOCK", "UNAUTHORIZED_SIGNER"
    record("3e", "Release manager with wrong MFA code", "BLOCK", decision, status)

    # 3c stolen key -> revoked
    km = KeyManager(ws)
    stolen_id = km.active_key_id()
    stolen = km.load_private_key(stolen_id)  # simulates exfiltration of the key file + passphrase
    a, m = _copy_release(ws, a100, m100, "s3c")
    attacker_uses_stolen_key(a, m, stolen)
    d_before = gate.evaluate(a, m, deploy=False)
    record("3c-", "Stolen key BEFORE revocation (content scan)", "BLOCK", d_before.decision,
           d_before.result.status.value, "signatures valid; blocked only by customer-side content scan")
    km.revoke(stolen_id, "key compromise detected in audit log")
    d = gate.evaluate(a, m, deploy=False)
    record("3c", "Stolen key AFTER revocation", "BLOCK", d.decision, d.result.status.value)

    # new legitimate releases signed with the fresh key
    _, _, a101, m101 = release(ws, "1.0.1")
    a, m = _copy_release(ws, a101, m101, "s-new")
    d = gate.evaluate(a, m)
    record("9", "Valid new release v1.0.1 (new key)", "DEPLOY", d.decision, d.result.status.value)

    # 4 replay: old v1.0.0 (signed by now-revoked key) and a rollback of a valid old version
    a, m = _copy_release(ws, a100, m100, "s4")
    d = gate.evaluate(a, m, deploy=False)
    record("4a", "Replay old v1.0.0 (revoked signing key)", "BLOCK", d.decision, d.result.status.value)
    _, _, a102, m102 = release(ws, "1.0.2")
    gate.evaluate(*_copy_release(ws, a102, m102, "s4-102"))
    km.revoke_artifact("secure-uploader", "1.0.1", "vulnerable release (CVE simulation)")
    km.set_minimum_version("secure-uploader", "1.0.2")
    a, m = _copy_release(ws, a101, m101, "s4b")
    d = gate.evaluate(a, m, deploy=False)
    record("4b", "Replay revoked v1.0.1 (valid signature)", "BLOCK", d.decision, d.result.status.value)

    # 5 compromised registry: attacker edits the trust policy to trust their key
    policy_backup = ws.trust_policy.read_bytes()
    env = json.loads(policy_backup)
    env["policy"]["keys"]["ed25519:attacker0000000"] = {"status": "active", "public_key": "x"}
    write_json(ws.trust_policy, env)
    a, m = _copy_release(ws, a102, m102, "s5")
    d = gate.evaluate(a, m, deploy=False)
    record("5", "Registry trust policy modified", "BLOCK", d.decision, d.result.status.value)
    ws.trust_policy.write_bytes(policy_backup)

    # 6 restore
    d = gate.evaluate(a, m)
    record("6", "Legitimate artifact restored (v1.0.2)", "DEPLOY", d.decision, d.result.status.value)
    return rows


def main() -> None:
    banner("Codecov-style supply-chain attack simulation (local, safe)")
    with tempfile.TemporaryDirectory(prefix="sscs-attacks-") as tmp:
        rows = run(Workspace(Path(tmp)))
    out = PROJECT_ROOT / "docs" / "results" / "attack_results.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rows, indent=2))
    ok = all(r["result"] == "PASS" for r in rows)
    print(bold(f"\n{sum(r['result'] == 'PASS' for r in rows)}/{len(rows)} scenarios behaved as expected"),
          green("ALL OK") if ok else red("CHECK FAILURES"))
    print(f"results written to {out}")


if __name__ == "__main__":
    main()
