"""Unit tests: python -m unittest discover -s tests -v"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "demo"))

import attack_demo as d  # noqa: E402
from signgate import crypto_utils as cu  # noqa: E402
from signgate.tlog import TransparencyLog  # noqa: E402


def stopped_by(report):
    return next(r["check"].strip() for r in report if not r["ok"])


class CryptoPrimitives(unittest.TestCase):
    def test_signature_roundtrip_and_tamper(self):
        priv, pub = cu.new_keypair()
        sig = cu.sign(priv, {"v": 1})
        self.assertTrue(cu.verify(pub, {"v": 1}, sig))
        self.assertFalse(cu.verify(pub, {"v": 2}, sig))

    def test_one_byte_changes_hash(self):
        self.assertNotEqual(cu.sha256_bytes(b"uploader"), cu.sha256_bytes(b"uploadEr"))

    def test_encrypted_key_needs_passphrase(self):
        w = d.World()
        with self.assertRaises(Exception):
            cu.load_private(f"{w.vault}/root.key", b"wrong")

    def test_log_detects_history_edit(self):
        w = d.World(); w.release("1.3.0"); w.release("1.4.0")
        log = TransparencyLog(f"{w.bucket}/tlog.json")
        self.assertTrue(log.chain_is_valid())
        log.entries[0]["manifest_sha256"] = "f" * 64
        self.assertFalse(log.chain_is_valid())


class AttackScenarios(unittest.TestCase):
    def test_s1_legitimate_runs(self):
        allowed, report, out = d.s1_legitimate()
        self.assertTrue(allowed)
        self.assertIn("Codecov uploader v1.4.0", out)

    def test_s2_codecov_attack_blocked_by_hash(self):
        allowed, report, _ = d.s2_codecov_attack()
        self.assertFalse(allowed)
        self.assertEqual(stopped_by(report), "4. SHA-256 integrity")

    def test_s3_rewritten_hash_blocked_by_signature(self):
        allowed, report, _ = d.s3_attacker_updates_hash()
        self.assertFalse(allowed)
        self.assertEqual(stopped_by(report), "3. Ed25519 signature")

    def test_s4_attacker_key_blocked_by_pki(self):
        allowed, report, _ = d.s4_attacker_own_key()
        self.assertFalse(allowed)
        self.assertEqual(stopped_by(report), "1. Key certificate (PKI)")

    def test_s5_unlogged_release_blocked(self):
        allowed, report, _ = d.s5_stolen_key_unlogged()
        self.assertFalse(allowed)
        self.assertEqual(stopped_by(report), "6. Transparency log")

    def test_s6_revoked_key_blocked(self):
        allowed, report, out = d.s6_stolen_key_revoked()
        self.assertFalse(allowed)
        self.assertEqual(stopped_by(report), "2. Revocation list")
        self.assertIn("unknown release", out)

    def test_s7_rollback_blocked(self):
        allowed, report, _ = d.s7_rollback()
        self.assertFalse(allowed)
        self.assertEqual(stopped_by(report), "5. Anti-rollback")

    def test_s8_allowlist_limits_exposure(self):
        old, new = d.s8_assume_breach()
        self.assertEqual(len(old), len(d.CI_SECRETS))
        self.assertEqual(new, ["CODECOV_TOKEN"])

    def test_s9_monitor_alerts_on_tamper(self):
        before, after = d.s9_monitor_detects_tamper()
        self.assertEqual(before, [])
        self.assertTrue(after and after[0].startswith("ALERT"))


if __name__ == "__main__":
    unittest.main()
