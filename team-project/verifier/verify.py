"""
Customer-Side Verification Engine.
Performs full cryptographical verification: SHA-256 integrity, Ed25519 digital signature,
Key Revocation List (CRL) inspection, SLSA provenance check, and admission policy evaluation.
"""

import os
import json
import base64
import hashlib
import time
from typing import Dict, Any, Optional, Tuple
import sys

# Ensure project imports resolve
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vendor.key_manager import KeyManager
from verifier.manifest import ManifestValidator
from verifier.policy import SecurityPolicy
from audit.audit_logger import AuditLogger

class ArtifactVerifier:
    def __init__(
        self,
        trusted_keys_dir: Optional[str] = None,
        policy: Optional[SecurityPolicy] = None,
        key_manager: Optional[KeyManager] = None,
        audit_logger: Optional[AuditLogger] = None
    ):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.keys_dir = trusted_keys_dir or os.path.join(base_dir, "keys")
        self.km = key_manager or KeyManager(self.keys_dir)
        self.policy = policy or SecurityPolicy()
        self.audit = audit_logger or AuditLogger()

    def calculate_file_sha256(self, file_path: str) -> str:
        """Calculates deterministic SHA-256 digest of given file."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    def verify(
        self,
        artifact_path: str,
        manifest_path: str,
        user_process: str = "Customer-CI-Gate"
    ) -> Dict[str, Any]:
        """
        Executes complete verification pipeline.
        Returns a structured dictionary with verdict and detailed telemetry.
        """
        start_time = time.perf_counter()
        artifact_name = os.path.basename(artifact_path)

        # 1. Check if files exist
        if not os.path.exists(artifact_path):
            result = {
                "verdict": "BLOCKED",
                "status_code": "FILE_NOT_FOUND",
                "message": f"Artifact file '{artifact_path}' does not exist",
                "time_ms": (time.perf_counter() - start_time) * 1000
            }
            self.audit.log_event(
                artifact=artifact_name, version="UNKNOWN", sha256="",
                key_id="UNKNOWN", verification_result="BLOCKED",
                user_process=user_process, action="BLOCK", rejection_reason=result["message"]
            )
            return result

        if not os.path.exists(manifest_path):
            result = {
                "verdict": "BLOCKED",
                "status_code": "MANIFEST_NOT_FOUND",
                "message": f"Manifest file '{manifest_path}' does not exist",
                "time_ms": (time.perf_counter() - start_time) * 1000
            }
            self.audit.log_event(
                artifact=artifact_name, version="UNKNOWN", sha256="",
                key_id="UNKNOWN", verification_result="BLOCKED",
                user_process=user_process, action="BLOCK", rejection_reason=result["message"]
            )
            return result

        # 2. Manifest Schema & Syntax Validation
        valid_schema, manifest_data, schema_err = ManifestValidator.load_and_validate(manifest_path)
        if not valid_schema:
            result = {
                "verdict": "BLOCKED",
                "status_code": "INVALID_MANIFEST",
                "message": f"Manifest validation failed: {schema_err}",
                "time_ms": (time.perf_counter() - start_time) * 1000
            }
            self.audit.log_event(
                artifact=artifact_name, version="UNKNOWN", sha256="",
                key_id="UNKNOWN", verification_result="BLOCKED",
                user_process=user_process, action="BLOCK", rejection_reason=result["message"]
            )
            return result

        version = manifest_data.get("version", "UNKNOWN")
        expected_sha256 = manifest_data.get("sha256", "")
        key_id = manifest_data.get("key_id", "UNKNOWN")
        raw_sig_b64 = manifest_data.get("signature", "")

        # 3. Provenance loading (if referenced)
        prov_data = None
        prov_ref = manifest_data.get("provenance_ref")
        if prov_ref:
            prov_file = os.path.join(os.path.dirname(manifest_path), prov_ref)
            if os.path.exists(prov_file):
                try:
                    with open(prov_file, "r", encoding="utf-8") as pf:
                        prov_data = json.load(pf)
                except Exception:
                    pass

        # 4. Check Key Status in Revocation List (CRL)
        if self.km.is_key_revoked(key_id):
            result = {
                "verdict": "BLOCKED",
                "status_code": "REVOKED",
                "message": f"Signing Key ID '{key_id}' has been REVOKED in the vendor CRL",
                "time_ms": (time.perf_counter() - start_time) * 1000
            }
            self.audit.log_event(
                artifact=artifact_name, version=version, sha256=expected_sha256,
                key_id=key_id, verification_result="REVOKED",
                user_process=user_process, action="BLOCK", rejection_reason=result["message"]
            )
            return result

        # 5. Security Policy Evaluation (Signer trust, Allowed Keys, Version check)
        policy_ok, policy_msg = self.policy.validate_policy_rules(manifest_data, prov_data)
        if not policy_ok:
            # Distinguish unauthorized key vs other policy failures
            status_code = "UNAUTHORIZED_KEY" if "Unauthorized Key" in policy_msg or "Unauthorized Signer" in policy_msg else "BLOCKED"
            result = {
                "verdict": "BLOCKED",
                "status_code": status_code,
                "message": f"Security policy check failed: {policy_msg}",
                "time_ms": (time.perf_counter() - start_time) * 1000
            }
            self.audit.log_event(
                artifact=artifact_name, version=version, sha256=expected_sha256,
                key_id=key_id, verification_result=status_code,
                user_process=user_process, action="BLOCK", rejection_reason=result["message"]
            )
            return result

        # 6. Verify Ed25519 Asymmetric Digital Signature over Canonical Manifest
        pub_key_path = os.path.join(self.keys_dir, f"{key_id}_pub.pem")
        if not os.path.exists(pub_key_path):
            result = {
                "verdict": "BLOCKED",
                "status_code": "UNAUTHORIZED_KEY",
                "message": f"Public key for key_id '{key_id}' not found in trusted keystore",
                "time_ms": (time.perf_counter() - start_time) * 1000
            }
            self.audit.log_event(
                artifact=artifact_name, version=version, sha256=expected_sha256,
                key_id=key_id, verification_result="UNAUTHORIZED_KEY",
                user_process=user_process, action="BLOCK", rejection_reason=result["message"]
            )
            return result

        try:
            pub_key = self.km.load_public_key(pub_key_path)
            canonical_bytes = ManifestValidator.get_canonical_bytes(manifest_data)
            raw_sig = base64.b64decode(raw_sig_b64)
            pub_key.verify(raw_sig, canonical_bytes)
        except Exception as e:
            result = {
                "verdict": "BLOCKED",
                "status_code": "INVALID_SIGNATURE",
                "message": f"Cryptographic signature verification failed: {str(e)}",
                "time_ms": (time.perf_counter() - start_time) * 1000
            }
            self.audit.log_event(
                artifact=artifact_name, version=version, sha256=expected_sha256,
                key_id=key_id, verification_result="INVALID_SIGNATURE",
                user_process=user_process, action="BLOCK", rejection_reason=result["message"]
            )
            return result

        # 7. Recalculate Artifact SHA-256 Digest and Detect Modification
        actual_sha256 = self.calculate_file_sha256(artifact_path)
        if actual_sha256.lower() != expected_sha256.lower():
            result = {
                "verdict": "BLOCKED",
                "status_code": "HASH_MISMATCH",
                "message": f"Tamper detected! Expected SHA-256 '{expected_sha256}', but computed '{actual_sha256}'",
                "actual_sha256": actual_sha256,
                "expected_sha256": expected_sha256,
                "time_ms": (time.perf_counter() - start_time) * 1000
            }
            self.audit.log_event(
                artifact=artifact_name, version=version, sha256=actual_sha256,
                key_id=key_id, verification_result="HASH_MISMATCH",
                user_process=user_process, action="BLOCK", rejection_reason=result["message"]
            )
            return result

        # 8. Provenance Hash Integrity (confirm artifact matches provenance record)
        if prov_data:
            prov_hash = prov_data.get("artifact_sha256", "")
            if prov_hash and prov_hash.lower() != actual_sha256.lower():
                result = {
                    "verdict": "BLOCKED",
                    "status_code": "PROVENANCE_MISMATCH",
                    "message": "SLSA provenance digest mismatch with verified artifact",
                    "time_ms": (time.perf_counter() - start_time) * 1000
                }
                self.audit.log_event(
                    artifact=artifact_name, version=version, sha256=actual_sha256,
                    key_id=key_id, verification_result="BLOCKED",
                    user_process=user_process, action="BLOCK", rejection_reason=result["message"]
                )
                return result

        # All checks passed!
        elapsed = (time.perf_counter() - start_time) * 1000
        result = {
            "verdict": "PASS",
            "status_code": "PASS",
            "message": "Artifact integrity and authenticity successfully verified against vendor root of trust",
            "artifact": artifact_name,
            "version": version,
            "sha256": actual_sha256,
            "key_id": key_id,
            "time_ms": elapsed
        }
        self.audit.log_event(
            artifact=artifact_name, version=version, sha256=actual_sha256,
            key_id=key_id, verification_result="PASS",
            user_process=user_process, action="DEPLOY", rejection_reason=None
        )
        return result

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target_artifact = os.path.join(base_dir, "artifacts", "uploader.sh")
    target_manifest = os.path.join(base_dir, "artifacts", "uploader.sh.manifest.json")

    verifier = ArtifactVerifier()
    res = verifier.verify(target_artifact, target_manifest)
    print("\n[=== Verification Result ===]")
    print(json.dumps(res, indent=2))
