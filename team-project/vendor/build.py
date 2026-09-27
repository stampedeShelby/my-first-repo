"""
Build Pipeline Component.
Simulates a secure build system that hashes artifacts and produces SLSA Level 2+ provenance.
"""

import os
import hashlib
import json
import datetime
from typing import Dict, Any

class SecureBuilder:
    def __init__(self, artifact_path: str, version: str = "1.0.0"):
        self.artifact_path = artifact_path
        self.version = version

    def compute_sha256(self) -> str:
        """Calculates deterministic SHA-256 digest of the artifact binary/script."""
        hasher = hashlib.sha256()
        with open(self.artifact_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    def generate_provenance(self) -> Dict[str, Any]:
        """
        Generates comprehensive provenance metadata adhering to SLSA / in-toto specs.
        Links the artifact to its source code, builder, commit, and dependencies.
        """
        artifact_hash = self.compute_sha256()
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        provenance = {
            "schema_version": "https://slsa.dev/provenance/v1",
            "artifact_name": os.path.basename(self.artifact_path),
            "version": self.version,
            "artifact_sha256": artifact_hash,
            "source_repository": "https://github.com/vendor/secure-uploader.git",
            "commit_id": "7f8b91a2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8",
            "build_id": f"BUILD-{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d%H%M%S')}-PROD",
            "build_timestamp": timestamp,
            "builder_identity": "Vendor Secure Build Cluster Worker #08 (Isolated Enclave)",
            "dependencies": [
                {
                    "name": "bash",
                    "version": "5.1.16",
                    "hash": "b2c01990479fdfa76cb58a0ebc89dffec9f44b413158b0abf1947fc9ec4bbd41"
                },
                {
                    "name": "curl",
                    "version": "7.81.0",
                    "hash": "a4d3bfdc24e12c1b9b5f54360e513813ff255fc7bca609a5c48b11116b3f71c4"
                }
            ],
            "security_tests_passed": True
        }
        return provenance

    def run_build(self) -> Dict[str, Any]:
        """Executes the build stage and exports provenance file."""
        if not os.path.exists(self.artifact_path):
            raise FileNotFoundError(f"Source artifact not found: {self.artifact_path}")

        print(f"[*] Building artifact: {self.artifact_path}")
        sha256_hash = self.compute_sha256()
        print(f"[+] Computed SHA-256: {sha256_hash}")

        prov = self.generate_provenance()
        prov_path = self.artifact_path + ".provenance.json"
        with open(prov_path, "w", encoding="utf-8") as f:
            json.dump(prov, f, indent=2)

        print(f"[+] Provenance descriptor generated: {prov_path}")
        return prov

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target = os.path.join(base_dir, "artifacts", "uploader.sh")
    builder = SecureBuilder(target, version="1.0.0")
    prov = builder.run_build()
    print("[+] Build step completed successfully.")
