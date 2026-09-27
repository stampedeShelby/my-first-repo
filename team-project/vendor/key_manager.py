"""
Key Manager for Cryptographically Verified Software Supply Chain.
Handles Ed25519 keypair generation, secure PEM export/import, Key ID calculation,
key rotation, and Key Revocation Lists (CRL).
"""

import os
import json
import base64
import hashlib
from typing import Tuple, Dict, Any, Optional
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

KEYS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "keys")
CRL_PATH = os.path.join(KEYS_DIR, "revoked_keys.json")

class KeyManager:
    def __init__(self, keys_dir: str = KEYS_DIR):
        self.keys_dir = keys_dir
        os.makedirs(self.keys_dir, exist_ok=True)
        self.crl_file = os.path.join(self.keys_dir, "revoked_keys.json")
        self._init_crl()

    def _init_crl(self):
        """Initializes empty Certificate/Key Revocation List if missing."""
        if not os.path.exists(self.crl_file):
            with open(self.crl_file, "w", encoding="utf-8") as f:
                json.dump({"revoked_keys": []}, f, indent=2)

    def generate_keypair(self, key_id: str, passphrase: Optional[str] = None) -> Tuple[str, str]:
        """
        Generates an Ed25519 asymmetric key pair.
        Saves private key (optionally encrypted with BestAvailableEncryption) and public key.
        Returns paths to (private_key_path, public_key_path).
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Determine encryption algorithm
        if passphrase:
            enc_algo = serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
        else:
            enc_algo = serialization.NoEncryption()

        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc_algo
        )

        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        priv_path = os.path.join(self.keys_dir, f"{key_id}_priv.pem")
        pub_path = os.path.join(self.keys_dir, f"{key_id}_pub.pem")

        with open(priv_path, "wb") as f:
            f.write(priv_pem)
        with open(pub_path, "wb") as f:
            f.write(pub_pem)

        return priv_path, pub_path

    def load_private_key(self, priv_path: str, passphrase: Optional[str] = None) -> ed25519.Ed25519PrivateKey:
        """Loads Ed25519 private key from PEM file."""
        with open(priv_path, "rb") as f:
            data = f.read()
        pw = passphrase.encode("utf-8") if passphrase else None
        return serialization.load_pem_private_key(data, password=pw)

    def load_public_key(self, pub_path: str) -> ed25519.Ed25519PublicKey:
        """Loads Ed25519 public key from PEM file."""
        with open(pub_path, "rb") as f:
            data = f.read()
        return serialization.load_pem_public_key(data)

    def compute_key_fingerprint(self, pub_path: str) -> str:
        """Computes SHA-256 fingerprint of the SubjectPublicKeyInfo raw bytes."""
        with open(pub_path, "rb") as f:
            data = f.read()
        return hashlib.sha256(data).hexdigest()

    def revoke_key(self, key_id: str, reason: str = "Key compromise or decommissioned"):
        """Adds a key identifier to the local Key Revocation List (CRL)."""
        with open(self.crl_file, "r", encoding="utf-8") as f:
            crl_data = json.load(f)

        for entry in crl_data.get("revoked_keys", []):
            if entry["key_id"] == key_id:
                return  # already revoked

        crl_data["revoked_keys"].append({
            "key_id": key_id,
            "reason": reason,
            "revocation_time": "2026-09-26T15:30:00Z"
        })

        with open(self.crl_file, "w", encoding="utf-8") as f:
            json.dump(crl_data, f, indent=2)

    def is_key_revoked(self, key_id: str) -> bool:
        """Checks if a key has been revoked in the CRL."""
        if not os.path.exists(self.crl_file):
            return False
        with open(self.crl_file, "r", encoding="utf-8") as f:
            crl_data = json.load(f)
        for entry in crl_data.get("revoked_keys", []):
            if entry["key_id"] == key_id:
                return True
        return False

    def rotate_key(self, old_key_id: str, new_key_id: str, passphrase: Optional[str] = None) -> Tuple[str, str]:
        """
        Executes key rotation: generates new key pair and marks old key as rotated/retired in CRL.
        """
        priv, pub = self.generate_keypair(new_key_id, passphrase)
        self.revoke_key(old_key_id, reason=f"Rotated in favor of {new_key_id}")
        return priv, pub

if __name__ == "__main__":
    km = KeyManager()
    print("[*] Generating primary vendor signing key...")
    priv_p, pub_p = km.generate_keypair("vendor_primary_v1")
    print(f"[+] Primary private key: {priv_p}")
    print(f"[+] Primary public key: {pub_p}")
    fp = km.compute_key_fingerprint(pub_p)
    print(f"[+] Key Fingerprint (SHA-256): {fp}")

    print("\n[*] Simulating key revocation...")
    km.revoke_key("vendor_revoked_test_key", reason="Simulated unauthorized key leakage")
    print(f"[+] Is vendor_revoked_test_key revoked? {km.is_key_revoked('vendor_revoked_test_key')}")
    print(f"[+] Is vendor_primary_v1 revoked? {km.is_key_revoked('vendor_primary_v1')}")
