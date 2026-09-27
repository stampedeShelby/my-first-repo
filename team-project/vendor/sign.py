"""
Signing Engine Component.
Signs the release manifest using Ed25519 asymmetric cryptography and creates
tamper-evident signed release bundles with SLSA provenance links.
"""

import os
import json
import base64
import datetime
import hashlib
from typing import Dict, Any, Optional
import sys

# Ensure local imports work across package roots
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vendor.key_manager import KeyManager
from audit.audit_logger import AuditLogger

class ArtifactSigner:
    def __init__(self, key_manager: Optional[KeyManager] = None, audit_logger: Optional[AuditLogger] = None):
        self.km = key_manager or KeyManager()
        self.audit = audit_logger or AuditLogger()

    @staticmethod
    def canonical_json_bytes(data: Dict[str, Any]) -> bytes:
        """
        Produces deterministic, canonical JSON representation (RFC 8785 style)
        to prevent signature invalidation due to formatting/whitespace differences.
        Excludes existing signature field if present.
        """
        clean_data = {k: v for k, v in data.items() if k != "signature"}
        return json.dumps(clean_data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign_artifact(
        self,
        artifact_path: str,
        version: str,
        key_id: str,
        priv_key_path: str,
        passphrase: Optional[str] = None,
        signer_name: str = "Vendor Release Server"
    ) -> Dict[str, Any]:
        """
        Computes artifact hash, builds canonical manifest, signs with Ed25519 private key,
        and records the signing action in the audit log.
        """
        if not os.path.exists(artifact_path):
            raise FileNotFoundError(f"Artifact not found: {artifact_path}")

        # Recalculate artifact SHA-256
        hasher = hashlib.sha256()
        with open(artifact_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        artifact_hash = hasher.hexdigest()

        # Check if signing key is revoked in CRL
        if self.km.is_key_revoked(key_id):
            self.audit.log_event(
                artifact=os.path.basename(artifact_path),
                version=version,
                sha256=artifact_hash,
                key_id=key_id,
                verification_result="REVOKED",
                user_process="ArtifactSigner",
                action="SIGNING_BLOCKED",
                rejection_reason="Attempted to sign release with a revoked key"
            )
            raise ValueError(f"Security Alert: Signing key {key_id} is marked REVOKED in CRL!")

        # Construct release manifest complying with assessment requirements
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        manifest = {
            "artifact": os.path.basename(artifact_path),
            "version": version,
            "sha256": artifact_hash,
            "algorithm": "SHA-256",
            "signature_algorithm": "Ed25519",
            "signer": signer_name,
            "key_id": key_id,
            "timestamp": timestamp,
            "provenance_ref": os.path.basename(artifact_path) + ".provenance.json"
        }

        # Canonicalize and sign
        canonical_bytes = self.canonical_json_bytes(manifest)
        priv_key = self.km.load_private_key(priv_key_path, passphrase)
        raw_signature = priv_key.sign(canonical_bytes)
        sig_b64 = base64.b64encode(raw_signature).decode("ascii")

        # Complete signed manifest envelope
        signed_manifest = dict(manifest)
        signed_manifest["signature"] = sig_b64

        # Persist manifest to disk
        manifest_path = artifact_path + ".manifest.json"
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(signed_manifest, f, indent=2)

        # Audit log the successful release signing
        self.audit.log_event(
            artifact=os.path.basename(artifact_path),
            version=version,
            sha256=artifact_hash,
            key_id=key_id,
            verification_result="PASS",
            user_process="Vendor-Sign-Service",
            action="SIGN_RELEASE",
            rejection_reason=None
        )

        return signed_manifest

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target = os.path.join(base_dir, "artifacts", "uploader.sh")
    priv_key_p = os.path.join(base_dir, "keys", "vendor_primary_v1_priv.pem")

    signer = ArtifactSigner()
    signed_m = signer.sign_artifact(
        artifact_path=target,
        version="1.0.0",
        key_id="vendor_primary_v1",
        priv_key_path=priv_key_p
    )
    print(f"[+] Successfully signed release manifest for {signed_m['artifact']}")
    print(json.dumps(signed_m, indent=2))
