"""
Security Policy Definition for Customer CI/CD Verification Gate.
Enforces zero-trust admission control for incoming software artifacts.
"""

from typing import List, Dict, Any, Optional

class SecurityPolicy:
    def __init__(
        self,
        trusted_signers: Optional[List[str]] = None,
        allowed_key_ids: Optional[List[str]] = None,
        min_allowed_version: str = "1.0.0",
        revoked_versions: Optional[List[str]] = None,
        require_provenance: bool = True,
        allowed_source_repos: Optional[List[str]] = None
    ):
        self.trusted_signers = trusted_signers or ["Vendor Release Server"]
        self.allowed_key_ids = allowed_key_ids or ["vendor_primary_v1", "vendor_primary_v2"]
        self.min_allowed_version = min_allowed_version
        self.revoked_versions = revoked_versions or ["0.8.0", "0.9.0-vulnerable"]
        self.require_provenance = require_provenance
        self.allowed_source_repos = allowed_source_repos or [
            "https://github.com/vendor/secure-uploader.git"
        ]

    def validate_policy_rules(self, manifest: Dict[str, Any], provenance: Optional[Dict[str, Any]] = None) -> (bool, str):
        """
        Evaluates policy constraints against manifest metadata and provenance.
        """
        # 1. Signer Identity
        signer = manifest.get("signer")
        if signer not in self.trusted_signers:
            return False, f"Unauthorized Signer: '{signer}' is not in trusted signers list"

        # 2. Key ID authorization
        key_id = manifest.get("key_id")
        if key_id not in self.allowed_key_ids:
            return False, f"Unauthorized Key ID: '{key_id}' is not in allowed keys policy"

        # 3. Version checks (Revoked version list)
        version = manifest.get("version", "0.0.0")
        if version in self.revoked_versions:
            return False, f"Revoked Artifact Version: version '{version}' has been blacklisted"

        # Simple semantic version minimum check
        try:
            v_parts = [int(p) for p in version.split("-")[0].split(".")]
            min_parts = [int(p) for p in self.min_allowed_version.split("-")[0].split(".")]
            if v_parts < min_parts:
                return False, f"Version Downgrade Rejected: version '{version}' < required minimum '{self.min_allowed_version}'"
        except Exception:
            pass  # Fall back to string comparison if irregular versioning

        # 4. Provenance checks if required
        if self.require_provenance:
            if not provenance:
                return False, "Missing mandatory SLSA build provenance metadata"
            
            repo = provenance.get("source_repository")
            if repo not in self.allowed_source_repos:
                return False, f"Untrusted Source Repository: '{repo}' is not permitted"

            if not provenance.get("security_tests_passed", False):
                return False, "Provenance indicates automated security tests failed during build"

        return True, "Policy checks passed successfully"
