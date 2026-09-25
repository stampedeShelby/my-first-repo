"""Signing service (the HSM/KMS stand-in) and signed-manifest creation.

Vendor flow::

    artifact --SHA-256--> digest ─┐
    artifact --Ed25519(sk)--> artifact_signature ─┤
    provenance --SHA-256--> provenance_sha256 ─┤
                                              └─> manifest --Ed25519(sk)--> manifest signature

The private key is loaded only inside :class:`SigningService`, only after the
caller passes RBAC + MFA, and every signing operation is written to the
hash-chained audit log. Callers receive signatures, never key material –
the same contract an HSM or cloud KMS ``Sign`` API offers.
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from audit.audit_logger import AuditLog
from common.crypto_utils import (
    CTX_ARTIFACT, CTX_MANIFEST, canonical_json, sha256_bytes, sha256_file, sign, utc_now_iso,
)
from common.workspace import Workspace, write_json
from vendor.access_control import AccessControl, AccessDenied
from vendor.build import ARTIFACT_NAME, BuildResult, build
from vendor.key_manager import KeyManager

SIGNER_NAME = "Vendor Release Server"
MANIFEST_TYPE = "application/vnd.sscs.manifest.v1+json"


class SigningService:
    def __init__(self, ws: Workspace, key_manager: KeyManager | None = None):
        self.ws = ws.ensure()
        self.km = key_manager or KeyManager(ws)
        self.acl = AccessControl(ws)
        self.audit = AuditLog.for_workspace(ws)

    def sign_release(self, *, user: str, otp: str | None, artifact_path: Path, version: str,
                     provenance: dict, artifact_name: str = ARTIFACT_NAME) -> Path:
        artifact_path = Path(artifact_path)
        try:
            self.acl.authorize(user, otp, "sign_release")
        except AccessDenied as exc:
            self.audit.log(actor=user, action="SIGN_RELEASE", result="UNAUTHORIZED_SIGNER",
                           artifact=artifact_name, version=version, reason=str(exc))
            raise

        key_id = self.km.active_key_id()
        sk = self.km.load_private_key(key_id)
        data = artifact_path.read_bytes()
        digest = sha256_bytes(data)
        if digest != provenance.get("artifact_sha256"):
            self.audit.log(actor=user, action="SIGN_RELEASE", result="BLOCKED", artifact=artifact_name,
                           version=version, sha256=digest, reason="artifact differs from built artifact")
            raise ValueError("artifact hash does not match build provenance - refusing to sign")

        manifest = {
            "artifact": artifact_name,
            "version": version,
            "filename": artifact_path.name,
            "size": len(data),
            "sha256": digest,
            "algorithm": "SHA-256",
            "signature_algorithm": "Ed25519",
            "signer": SIGNER_NAME,
            "key_id": key_id,
            "timestamp": utc_now_iso(),
            "artifact_signature": sign(sk, CTX_ARTIFACT, data),
            "provenance": provenance,
            "provenance_sha256": sha256_bytes(canonical_json(provenance)),
        }
        envelope = {
            "payload_type": MANIFEST_TYPE,
            "manifest": manifest,
            "signatures": [{"key_id": key_id, "sig": sign(sk, CTX_MANIFEST, canonical_json(manifest))}],
        }
        del sk
        out = artifact_path.with_name(artifact_path.name + ".manifest.json")
        write_json(out, envelope)
        self.audit.log(actor=user, action="SIGN_RELEASE", result="OK", artifact=artifact_name,
                       version=version, sha256=digest, key_id=key_id,
                       details={"build_id": provenance.get("build_id")})
        return out


def publish(ws: Workspace, artifact_path: Path, manifest_path: Path, actor: str = "release-pipeline") -> tuple[Path, Path]:
    """Copy a signed release into the artifact registry (what customers download)."""
    ws.registry_dir.mkdir(parents=True, exist_ok=True)
    a = Path(shutil.copy2(artifact_path, ws.registry_dir / Path(artifact_path).name))
    m = Path(shutil.copy2(manifest_path, ws.registry_dir / Path(manifest_path).name))
    man = json.loads(m.read_text())["manifest"]
    AuditLog.for_workspace(ws).log(actor=actor, action="PUBLISH", result="OK", artifact=man["artifact"],
                                   version=man["version"], sha256=sha256_file(a), key_id=man["key_id"])
    return a, m


def release(ws: Workspace, version: str, user: str = "alice", otp: str | None = None,
            source_dir: Path | None = None) -> tuple[BuildResult, Path, Path, Path]:
    """Convenience: build -> sign -> publish. Returns (build, manifest, registry_artifact, registry_manifest)."""
    kwargs = {"source_dir": source_dir} if source_dir else {}
    res = build(ws, version, **kwargs)
    svc = SigningService(ws)
    otp = otp or svc.acl.current_otp(user)
    manifest = svc.sign_release(user=user, otp=otp, artifact_path=res.artifact_path, version=version,
                                provenance=res.provenance)
    reg_a, reg_m = publish(ws, res.artifact_path, manifest)
    return res, manifest, reg_a, reg_m


def main() -> None:
    ap = argparse.ArgumentParser(description="Build, sign and publish a release")
    ap.add_argument("--version", required=True)
    ap.add_argument("--user", default="alice")
    ap.add_argument("--otp", help="MFA code (default: read from the demo authenticator)")
    args = ap.parse_args()
    res, manifest, reg_a, _ = release(Workspace.default(), args.version, args.user, args.otp)
    env = json.loads(manifest.read_text())
    print(f"artifact  : {reg_a}\nsha256    : {res.sha256}\nkey_id    : {env['signatures'][0]['key_id']}"
          f"\nsignature : {env['signatures'][0]['sig']}\nmanifest  : {manifest}")


if __name__ == "__main__":
    main()
