"""
Unauthorized Key and Replay Attack Simulator.
Simulates Scenarios 3 and 4:
- Scenario 3: Signing attempts with untrusted/rogue keys or revoked keys.
- Scenario 4: Replay or downgrade attacks using deprecated/revoked software versions.
"""

import os
import json
import copy
import sys

# Ensure project imports resolve
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vendor.key_manager import KeyManager
from vendor.sign import ArtifactSigner
from verifier.verify import ArtifactVerifier
from verifier.policy import SecurityPolicy

def run_unauthorized_and_replay_tests():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target_artifact = os.path.join(base_dir, "artifacts", "uploader.sh")
    target_manifest = os.path.join(base_dir, "artifacts", "uploader.sh.manifest.json")
    km = KeyManager()

    print("=" * 75)
    print(" [ATTACK SIMULATION: SCENARIOS 3 & 4 - ROGUE KEYS & VERSION REPLAY] ")
    print("=" * 75)

    # ---------------------------------------------------------
    # Scenario 3A: Signing with an Unauthorized Rogue Key
    # ---------------------------------------------------------
    print("\n--- Scenario 3A: Attacker signs modified code with their own Rogue Key ---")
    rogue_priv, rogue_pub = km.generate_keypair("attacker_rogue_key")
    signer = ArtifactSigner(km)

    rogue_manifest_path = target_artifact + ".rogue_manifest.json"
    rogue_manifest = signer.sign_artifact(
        artifact_path=target_artifact,
        version="1.0.0",
        key_id="attacker_rogue_key",
        priv_key_path=rogue_priv,
        signer_name="Attacker Impersonator"
    )
    with open(rogue_manifest_path, "w", encoding="utf-8") as f:
        json.dump(rogue_manifest, f, indent=2)

    verifier = ArtifactVerifier()
    res3a = verifier.verify(target_artifact, rogue_manifest_path, user_process="Gate-RogueKey-Test")
    print(f"[*] Gate Verdict:     {res3a.get('verdict')}")
    print(f"[*] Status Code:      {res3a.get('status_code')}")
    print(f"[*] Alert Message:    {res3a.get('message')}")
    assert res3a.get("verdict") == "BLOCKED"
    print(">>> SUCCESS: Rogue key rejected by customer security policy! <<<")

    # ---------------------------------------------------------
    # Scenario 3B: Signing with a Revoked Key
    # ---------------------------------------------------------
    print("\n--- Scenario 3B: Using a Compromised/Revoked Vendor Key ---")
    revoked_key_id = "vendor_compromised_2025"
    rev_priv, rev_pub = km.generate_keypair(revoked_key_id)
    km.revoke_key(revoked_key_id, reason="Emergency revocation: Private key leaked in git commit")

    revoked_manifest_path = target_artifact + ".revoked_manifest.json"
    try:
        signer.sign_artifact(
            artifact_path=target_artifact,
            version="1.0.0",
            key_id=revoked_key_id,
            priv_key_path=rev_priv
        )
    except ValueError as e:
        print(f"[+] Signer preemptively prevented release: {e}")

    # Manually craft a manifest claiming the revoked key to test verifier gate
    with open(target_manifest, "r", encoding="utf-8") as f:
        crafted_manifest = json.load(f)
    crafted_manifest["key_id"] = revoked_key_id
    with open(revoked_manifest_path, "w", encoding="utf-8") as f:
        json.dump(crafted_manifest, f, indent=2)

    res3b = verifier.verify(target_artifact, revoked_manifest_path, user_process="Gate-RevokedKey-Test")
    print(f"[*] Gate Verdict:     {res3b.get('verdict')}")
    print(f"[*] Status Code:      {res3b.get('status_code')}")
    print(f"[*] Alert Message:    {res3b.get('message')}")
    assert res3b.get("verdict") == "BLOCKED"
    print(">>> SUCCESS: Revoked key blocked by Key Revocation List (CRL)! <<<")

    # ---------------------------------------------------------
    # Scenario 4: Replay Attack (Deprecated / Revoked Artifact Version)
    # ---------------------------------------------------------
    print("\n--- Scenario 4: Replaying a Deprecated/Revoked Version ---")
    replay_manifest_path = target_artifact + ".replay_manifest.json"
    replay_manifest = copy.deepcopy(crafted_manifest)
    replay_manifest["key_id"] = "vendor_primary_v1"
    replay_manifest["version"] = "0.8.0"  # blacklisted old version in policy
    with open(replay_manifest_path, "w", encoding="utf-8") as f:
        json.dump(replay_manifest, f, indent=2)

    res4 = verifier.verify(target_artifact, replay_manifest_path, user_process="Gate-Replay-Test")
    print(f"[*] Gate Verdict:     {res4.get('verdict')}")
    print(f"[*] Status Code:      {res4.get('status_code')}")
    print(f"[*] Alert Message:    {res4.get('message')}")
    assert res4.get("verdict") == "BLOCKED"
    print(">>> SUCCESS: Replay of deprecated/revoked version blocked by Security Policy! <<<")

    # Clean up test artifacts
    for p in [rogue_manifest_path, revoked_manifest_path, replay_manifest_path]:
        if os.path.exists(p):
            os.remove(p)

if __name__ == "__main__":
    run_unauthorized_and_replay_tests()
