"""Publisher side (what Codecov's release pipeline would run).

Folders
  vault/   private keys -> in production these live in an HSM / cloud KMS
  bucket/  public distribution storage (plays the role of Google Cloud Storage)
"""
import json
import os
import shutil
import time

from . import crypto_utils as cu
from . import pki
from .tlog import TransparencyLog

PASS = b"demo-passphrase"  # stands in for HSM/KMS access control


def _dump(obj, path):
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)


def setup_publisher(vault, bucket):
    """One-time key ceremony. Returns the public values a CI pipeline must pin."""
    os.makedirs(vault, exist_ok=True)
    os.makedirs(bucket, exist_ok=True)
    root_priv, root_pub = cu.new_keypair()        # offline root (trust anchor)
    release_priv, release_pub = cu.new_keypair()  # online signing key, 90-day cert
    log_priv, log_pub = cu.new_keypair()          # transparency-log operator key
    cu.save_private(root_priv, f"{vault}/root.key", PASS)
    cu.save_private(release_priv, f"{vault}/release.key", PASS)
    cu.save_private(log_priv, f"{vault}/log.key", PASS)
    _dump(pki.issue_key_certificate(root_priv, release_pub), f"{vault}/release.cert")
    _dump(pki.issue_revocation_list(root_priv), f"{bucket}/crl.json")
    TransparencyLog(f"{bucket}/tlog.json")._save()
    _dump(TransparencyLog(f"{bucket}/tlog.json").signed_head(log_priv), f"{bucket}/tlog_head.json")
    return {
        "root_public_key": cu.b64(cu.public_raw(root_pub)),
        "log_public_key": cu.b64(cu.public_raw(log_pub)),
    }


def rotate_release_key(vault):
    """Key rotation: new release key, new certificate from the root."""
    root_priv = cu.load_private(f"{vault}/root.key", PASS)
    release_priv, release_pub = cu.new_keypair()
    cu.save_private(release_priv, f"{vault}/release.key", PASS)
    _dump(pki.issue_key_certificate(root_priv, release_pub), f"{vault}/release.cert")
    return cu.key_id(release_pub)


def revoke(vault, bucket, key_ids=(), sha256s=()):
    root_priv = cu.load_private(f"{vault}/root.key", PASS)
    with open(f"{bucket}/crl.json") as f:
        old = json.load(f)["body"]
    crl = pki.issue_revocation_list(
        root_priv,
        set(old["revoked_key_ids"]) | set(key_ids),
        set(old["revoked_artifacts_sha256"]) | set(sha256s),
        sequence=old["sequence"] + 1,
    )
    _dump(crl, f"{bucket}/crl.json")


def build_manifest(artifact_path, version, release_priv, cert, name="codecov-uploader.sh"):
    body = {
        "artifact": name,
        "version": version,
        "sha256": cu.sha256_file(artifact_path),
        "size": os.path.getsize(artifact_path),
        "released_at": int(time.time()),
        "key_id": cert["body"]["key_id"],
    }
    return {"body": body, "signature": cu.sign(release_priv, body), "key_certificate": cert}


def release(vault, bucket, artifact_path, version, log_it=True):
    """Hash -> sign -> record in transparency log -> publish."""
    release_priv = cu.load_private(f"{vault}/release.key", PASS)
    log_priv = cu.load_private(f"{vault}/log.key", PASS)
    with open(f"{vault}/release.cert") as f:
        cert = json.load(f)
    manifest = build_manifest(artifact_path, version, release_priv, cert)
    if log_it:
        log = TransparencyLog(f"{bucket}/tlog.json")
        log.append(manifest["body"])
        _dump(log.signed_head(log_priv), f"{bucket}/tlog_head.json")
    shutil.copy(artifact_path, f"{bucket}/codecov-uploader.sh")
    _dump(manifest, f"{bucket}/manifest.json")
    return manifest
