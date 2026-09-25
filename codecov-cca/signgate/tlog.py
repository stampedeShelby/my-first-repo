"""Hash-chained, append-only release transparency log (a tiny version of the
idea behind Certificate Transparency / Sigstore Rekor).

entry_hash[i] = SHA-256( entry_hash[i-1] || manifest_sha256[i] )

Every release must be recorded here. Deleting or editing an old entry breaks
the chain, and a release signed with a stolen key either shows up in the
public log (so the publisher's monitor sees a release it never made) or is
missing from it (so every CI gate rejects it).
"""
import json
import os
import time

from . import crypto_utils as cu

GENESIS = "0" * 64


class TransparencyLog:
    def __init__(self, path):
        self.path = path
        self.entries = []
        if os.path.exists(path):
            with open(path) as f:
                self.entries = json.load(f)["entries"]

    def _save(self):
        with open(self.path, "w") as f:
            json.dump({"entries": self.entries}, f, indent=2)

    def head_hash(self):
        return self.entries[-1]["entry_hash"] if self.entries else GENESIS

    def append(self, manifest_body):
        m_hash = cu.sha256_bytes(cu.canonical(manifest_body))
        prev = self.head_hash()
        entry = {
            "index": len(self.entries),
            "artifact": manifest_body["artifact"],
            "version": manifest_body["version"],
            "manifest_sha256": m_hash,
            "logged_at": int(time.time()),
            "prev_hash": prev,
            "entry_hash": cu.sha256_bytes((prev + m_hash).encode()),
        }
        self.entries.append(entry)
        self._save()
        return entry

    def signed_head(self, log_priv):
        body = {"size": len(self.entries), "head_hash": self.head_hash()}
        return {"body": body, "signature": cu.sign(log_priv, body)}

    # ---------- verification (used by the CI gate) ----------

    def chain_is_valid(self):
        prev = GENESIS
        for i, e in enumerate(self.entries):
            if e["index"] != i or e["prev_hash"] != prev:
                return False
            if e["entry_hash"] != cu.sha256_bytes((prev + e["manifest_sha256"]).encode()):
                return False
            prev = e["entry_hash"]
        return True

    def contains(self, manifest_body):
        m_hash = cu.sha256_bytes(cu.canonical(manifest_body))
        return any(e["manifest_sha256"] == m_hash for e in self.entries)


def check_log(log, signed_head, log_pub, manifest_body, last_seen_size=0):
    if not cu.verify(log_pub, signed_head["body"], signed_head["signature"]):
        return False, "log head signature invalid"
    if signed_head["body"] != {"size": len(log.entries), "head_hash": log.head_hash()}:
        return False, "log content does not match its signed head"
    if not log.chain_is_valid():
        return False, "log hash-chain broken (history was edited)"
    if len(log.entries) < last_seen_size:
        return False, "log shrank since last run (entries deleted)"
    if not log.contains(manifest_body):
        return False, "release NOT recorded in transparency log"
    return True, "release found in append-only log, chain intact"
