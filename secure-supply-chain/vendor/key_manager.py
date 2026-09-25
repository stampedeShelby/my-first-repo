"""Vendor key management: generation, protection, rotation, revocation and
publication of the root-signed trust policy.

Two-tier key hierarchy (inspired by TUF / PKI):

* **Root key** – the offline root of trust. Its public key is pinned by every
  customer out-of-band (shipped with onboarding docs / package manager). It
  only signs the *trust policy*; it never signs artifacts.
* **Release signing keys** – online Ed25519 keys used by the signing service.
  They can be rotated or revoked at any time by publishing a new trust policy.

The trust policy (``registry/trust_policy.json``) lists every release key with
its status (active / retired / revoked), revoked artifact versions and the
minimum acceptable version of each artifact. Because it is signed by the root
key, an attacker who compromises the registry cannot add their own key,
"un-revoke" a key or roll the policy back to an older version.

Prototype vs production: private keys are stored PKCS#8-encrypted with a
passphrase (AES-256 via ``BestAvailableEncryption``) and file mode 0600. A
production deployment would generate and keep them inside an HSM or cloud KMS
(AWS KMS, GCP Cloud KMS, Azure Key Vault) where they are non-exportable.
"""

from __future__ import annotations

import argparse
import os
from datetime import timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit.audit_logger import AuditLog
from common.crypto_utils import (
    CTX_TRUST_POLICY, canonical_json, key_id_for, public_key_to_pem, sign, utc_now, utc_now_iso,
)
from common.workspace import Workspace, parse_version, read_json, write_json

DEMO_PASSPHRASE = "demo-only-change-me"  # never used when SSCS_KEY_PASSPHRASE is set
TRUST_POLICY_VALIDITY_DAYS = 30

ACTIVE, RETIRED, REVOKED = "active", "retired", "revoked"


class KeyManagementError(Exception):
    pass


class KeyManager:
    def __init__(self, ws: Workspace, passphrase: str | None = None, actor: str = "key-admin"):
        self.ws = ws.ensure()
        self.actor = actor
        self._passphrase = (passphrase or os.environ.get("SSCS_KEY_PASSPHRASE") or DEMO_PASSPHRASE).encode()
        self.audit = AuditLog.for_workspace(ws)

    # ------------------------------------------------------------------ storage
    def _registry(self) -> dict:
        return read_json(self.ws.key_registry, {
            "root_key_id": None, "keys": {}, "revoked_artifacts": [],
            "minimum_versions": {}, "policy_version": 0,
        })

    def _save_registry(self, reg: dict) -> None:
        write_json(self.ws.key_registry, reg)

    def _key_path(self, key_id: str) -> Path:
        return self.ws.private_keys_dir / (key_id.replace(":", "_") + ".pem")

    def _store_private_key(self, key: Ed25519PrivateKey, key_id: str) -> None:
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(self._passphrase),
        )
        path = self._key_path(key_id)
        # create with 0600 from the start: no window where the key is world-readable
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)

    def load_private_key(self, key_id: str) -> Ed25519PrivateKey:
        """Only the signing service (vendor/sign.py) should call this."""
        path = self._key_path(key_id)
        if not path.exists():
            raise KeyManagementError(f"no private key for {key_id}")
        key = serialization.load_pem_private_key(path.read_bytes(), password=self._passphrase)
        if not isinstance(key, Ed25519PrivateKey):
            raise KeyManagementError("unexpected key type")
        return key

    # ------------------------------------------------------------------ lifecycle
    def init(self) -> dict:
        """Create the root key and the first release signing key, then publish the trust policy."""
        reg = self._registry()
        if reg["root_key_id"]:
            raise KeyManagementError("key store already initialised")
        root = Ed25519PrivateKey.generate()
        root_id = key_id_for(root.public_key())
        self._store_private_key(root, root_id)
        reg["root_key_id"] = root_id
        reg["root_public_key"] = public_key_to_pem(root.public_key())
        self._save_registry(reg)
        self.audit.log(actor=self.actor, action="ROOT_KEY_CREATE", result="OK", key_id=root_id)
        release_id = self.generate_release_key()
        return {"root_key_id": root_id, "release_key_id": release_id}

    def generate_release_key(self) -> str:
        reg = self._registry()
        key = Ed25519PrivateKey.generate()
        key_id = key_id_for(key.public_key())
        self._store_private_key(key, key_id)
        reg["keys"][key_id] = {
            "public_key": public_key_to_pem(key.public_key()),
            "algorithm": "Ed25519",
            "role": "release-signing",
            "status": ACTIVE,
            "created_at": utc_now_iso(),
        }
        self._save_registry(reg)
        self.audit.log(actor=self.actor, action="KEY_GENERATE", result="OK", key_id=key_id)
        self.publish_trust_policy()
        return key_id

    def active_key_id(self) -> str:
        active = [k for k, v in self._registry()["keys"].items() if v["status"] == ACTIVE]
        if len(active) != 1:
            raise KeyManagementError(f"expected exactly one active release key, found {len(active)}")
        return active[0]

    def rotate(self) -> tuple[str, str]:
        """Retire the current key (old releases stay verifiable) and activate a new one."""
        old = self.active_key_id()
        reg = self._registry()
        reg["keys"][old]["status"] = RETIRED
        reg["keys"][old]["retired_at"] = utc_now_iso()
        self._save_registry(reg)
        self.audit.log(actor=self.actor, action="KEY_ROTATE", result="OK", key_id=old,
                       details={"old_status": RETIRED})
        new = self.generate_release_key()
        return old, new

    def revoke(self, key_id: str, reason: str) -> None:
        """Revoke a (possibly stolen) key: every artifact it signed is rejected."""
        reg = self._registry()
        if key_id not in reg["keys"]:
            raise KeyManagementError(f"unknown key {key_id}")
        was_active = reg["keys"][key_id]["status"] == ACTIVE
        reg["keys"][key_id].update(status=REVOKED, revoked_at=utc_now_iso(), revocation_reason=reason)
        # destroy the private key material so it can never sign again
        path = self._key_path(key_id)
        if path.exists():
            path.unlink()
        self._save_registry(reg)
        self.audit.log(actor=self.actor, action="KEY_REVOKE", result="REVOKED", key_id=key_id, reason=reason)
        if was_active:
            self.generate_release_key()  # keep releases flowing with a fresh key
        else:
            self.publish_trust_policy()

    def revoke_artifact(self, artifact: str, version: str, reason: str) -> None:
        reg = self._registry()
        reg["revoked_artifacts"].append({"artifact": artifact, "version": version,
                                         "reason": reason, "revoked_at": utc_now_iso()})
        self._save_registry(reg)
        self.audit.log(actor=self.actor, action="ARTIFACT_REVOKE", result="REVOKED",
                       artifact=artifact, version=version, reason=reason)
        self.publish_trust_policy()

    def set_minimum_version(self, artifact: str, version: str) -> None:
        parse_version(version)
        reg = self._registry()
        reg["minimum_versions"][artifact] = version
        self._save_registry(reg)
        self.audit.log(actor=self.actor, action="SET_MIN_VERSION", result="OK",
                       artifact=artifact, version=version)
        self.publish_trust_policy()

    # ------------------------------------------------------------------ trust policy
    def publish_trust_policy(self) -> Path:
        """Sign the current key/revocation state with the root key and publish it to the registry."""
        reg = self._registry()
        reg["policy_version"] += 1
        self._save_registry(reg)
        now = utc_now()
        policy = {
            "type": "sscs-trust-policy",
            "version": reg["policy_version"],
            "issued_at": now.isoformat().replace("+00:00", "Z"),
            "expires_at": (now + timedelta(days=TRUST_POLICY_VALIDITY_DAYS)).isoformat().replace("+00:00", "Z"),
            "root_key_id": reg["root_key_id"],
            "keys": reg["keys"],  # public keys + status only; private keys never leave keys/private
            "revoked_artifacts": reg["revoked_artifacts"],
            "minimum_versions": reg["minimum_versions"],
        }
        root = self.load_private_key(reg["root_key_id"])
        envelope = {"policy": policy, "signature": sign(root, CTX_TRUST_POLICY, canonical_json(policy)),
                    "signed_by": reg["root_key_id"]}
        write_json(self.ws.trust_policy, envelope)
        self.audit.log(actor=self.actor, action="TRUST_POLICY_PUBLISH", result="OK",
                       key_id=reg["root_key_id"], details={"policy_version": policy["version"]})
        return self.ws.trust_policy

    def export_root_public_key(self, dest: Path | None = None) -> Path:
        """Out-of-band distribution of the root public key to customers (pinning)."""
        dest = dest or self.ws.trusted_root
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(self._registry()["root_public_key"])
        return dest

    def list_keys(self) -> dict:
        return self._registry()["keys"]


def main() -> None:
    ap = argparse.ArgumentParser(description="Vendor key management")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="create root + first release key, publish trust policy")
    sub.add_parser("list")
    sub.add_parser("rotate")
    r = sub.add_parser("revoke"); r.add_argument("key_id"); r.add_argument("--reason", required=True)
    ra = sub.add_parser("revoke-artifact"); ra.add_argument("artifact"); ra.add_argument("version")
    ra.add_argument("--reason", required=True)
    mv = sub.add_parser("min-version"); mv.add_argument("artifact"); mv.add_argument("version")
    sub.add_parser("export-root", help="write the root public key into the customer trust anchor")
    args = ap.parse_args()

    km = KeyManager(Workspace.default())
    if args.cmd == "init":
        print(km.init()); km.export_root_public_key()
    elif args.cmd == "list":
        for kid, meta in km.list_keys().items():
            print(f"{kid}  {meta['status']:8}  created {meta['created_at']}")
    elif args.cmd == "rotate":
        old, new = km.rotate(); print(f"retired {old}; new active key {new}")
    elif args.cmd == "revoke":
        km.revoke(args.key_id, args.reason); print(f"revoked {args.key_id}")
    elif args.cmd == "revoke-artifact":
        km.revoke_artifact(args.artifact, args.version, args.reason)
    elif args.cmd == "min-version":
        km.set_minimum_version(args.artifact, args.version)
    elif args.cmd == "export-root":
        print(km.export_root_public_key())


if __name__ == "__main__":
    main()
