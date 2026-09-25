"""Mini PKI: an offline ROOT key certifies short-lived RELEASE keys and signs the
revocation list. CI pipelines pin only the root public key (the trust anchor),
so a leaked release key can be revoked without touching any customer pipeline.
"""
import time

from . import crypto_utils as cu

DAY = 24 * 3600


def issue_key_certificate(root_priv, release_pub, valid_days=90, now=None):
    now = int(now if now is not None else time.time())
    body = {
        "type": "release-key-certificate",
        "key_id": cu.key_id(release_pub),
        "public_key": cu.b64(cu.public_raw(release_pub)),
        "purpose": "artifact-signing",
        "not_before": now,
        "not_after": now + valid_days * DAY,
    }
    return {"body": body, "signature": cu.sign(root_priv, body)}


def check_key_certificate(cert, root_pub, now=None):
    """Returns (ok, reason, release_public_key)."""
    now = int(now if now is not None else time.time())
    body = cert["body"]
    if not cu.verify(root_pub, body, cert["signature"]):
        return False, "key certificate NOT signed by pinned root key", None
    if body["purpose"] != "artifact-signing":
        return False, "key not authorised for artifact signing", None
    if not body["not_before"] <= now <= body["not_after"]:
        return False, "release key certificate expired / not yet valid", None
    return True, "release key certified by root", cu.public_from_b64(body["public_key"])


def issue_revocation_list(root_priv, revoked_key_ids=(), revoked_sha256=(), sequence=1):
    body = {
        "type": "revocation-list",
        "sequence": sequence,
        "issued_at": int(time.time()),
        "revoked_key_ids": sorted(revoked_key_ids),
        "revoked_artifacts_sha256": sorted(revoked_sha256),
    }
    return {"body": body, "signature": cu.sign(root_priv, body)}


def check_revocation(crl, root_pub, key_id, artifact_sha256):
    body = crl["body"]
    if not cu.verify(root_pub, body, crl["signature"]):
        return False, "revocation list signature invalid"
    if key_id in body["revoked_key_ids"]:
        return False, f"release key {key_id} has been REVOKED"
    if artifact_sha256 in body["revoked_artifacts_sha256"]:
        return False, "this exact artifact has been REVOKED"
    return True, "key and artifact not revoked"
