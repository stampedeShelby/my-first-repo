"""
CI/CD Automated Security Gate.
Simulates a zero-trust customer deployment pipeline gate that evaluates downloaded artifacts
against cryptographic rules before allowing execution or deployment.
"""

import sys
import os
import argparse
import json

# Ensure project imports resolve
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from verifier.verify import ArtifactVerifier
from verifier.policy import SecurityPolicy

def run_security_gate(artifact_path: str, manifest_path: str, strict: bool = True) -> int:
    print("=" * 70)
    print(" [CI/CD ZERO-TRUST SECURITY ADMISSION GATE] ")
    print(" Enforcing Cryptographic Supply Chain Verification")
    print("=" * 70)
    print(f"[*] Target Artifact: {artifact_path}")
    print(f"[*] Release Manifest: {manifest_path}")

    verifier = ArtifactVerifier()
    result = verifier.verify(artifact_path, manifest_path, user_process="Production-CI-Gate")

    print("\n[+] Verification Telemetry:")
    print(f"    - Execution Time: {result.get('time_ms', 0):.2f} ms")
    print(f"    - Status Code:   {result.get('status_code')}")
    print(f"    - Reason:        {result.get('message')}")

    if result.get("verdict") == "PASS":
        print("\n" + "=" * 70)
        print(" [GATE DECISION: ALLOWED / DEPLOY] ")
        print(" Cryptographic proof verified: Artifact is authentic and untampered.")
        print(" Proceeding with container build, test execution, or deployment.")
        print("=" * 70)
        return 0
    else:
        print("\n" + "!" * 70)
        print(" [GATE DECISION: BLOCKED / ABORT] ")
        print(" SECURITY ALERT: Supply chain policy violation detected!")
        print(" Aborting deployment pipeline immediately.")
        print(f" Violation Details: {result.get('message')}")
        print(" Security event logged to persistent audit database.")
        print("!" * 70)
        return 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CI/CD Supply Chain Security Gate")
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    default_artifact = os.path.join(base_dir, "artifacts", "uploader.sh")
    default_manifest = os.path.join(base_dir, "artifacts", "uploader.sh.manifest.json")

    parser.add_argument("--artifact", default=default_artifact, help="Path to software artifact")
    parser.add_argument("--manifest", default=default_manifest, help="Path to signed manifest")
    args = parser.parse_args()

    exit_code = run_security_gate(args.artifact, args.manifest)
    sys.exit(exit_code)
