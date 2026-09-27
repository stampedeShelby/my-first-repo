"""
Manifest Parser and Schema Validator.
Validates the structure, required fields, and canonical formatting of signed manifests.
"""

import json
from typing import Dict, Any, Tuple

REQUIRED_MANIFEST_FIELDS = {
    "artifact": str,
    "version": str,
    "sha256": str,
    "algorithm": str,
    "signature_algorithm": str,
    "signer": str,
    "key_id": str,
    "timestamp": str,
    "signature": str
}

class ManifestValidator:
    @staticmethod
    def load_and_validate(manifest_path: str) -> Tuple[bool, Optional_Dict := Dict[str, Any], Optional_Error := str]:
        """
        Loads manifest JSON and validates schema conformity.
        Returns (is_valid, manifest_dict, error_message).
        """
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            return False, {}, f"Failed to parse manifest JSON: {str(e)}"

        for field, field_type in REQUIRED_MANIFEST_FIELDS.items():
            if field not in data:
                return False, data, f"Missing mandatory manifest field: '{field}'"
            if not isinstance(data[field], field_type):
                return False, data, f"Field '{field}' has invalid type; expected {field_type.__name__}"

        if data["algorithm"] != "SHA-256":
            return False, data, f"Unsupported digest algorithm: {data['algorithm']}"

        if data["signature_algorithm"] != "Ed25519":
            return False, data, f"Unsupported signature algorithm: {data['signature_algorithm']}"

        return True, data, ""

    @staticmethod
    def get_canonical_bytes(manifest: Dict[str, Any]) -> bytes:
        """Extracts canonical bytes for cryptographic verification."""
        clean = {k: v for k, v in manifest.items() if k != "signature"}
        return json.dumps(clean, sort_keys=True, separators=(",", ":")).encode("utf-8")

if __name__ == "__main__":
    import os
    sample_p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "artifacts", "uploader.sh.manifest.json")
    valid, m, err = ManifestValidator.load_and_validate(sample_p)
    print(f"Validation result: valid={valid}, err={err}")
    if valid:
        print(f"Canonical payload: {ManifestValidator.get_canonical_bytes(m).decode('utf-8')}")
