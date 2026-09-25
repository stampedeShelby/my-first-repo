"""Hash-chained, tamper-evident audit / transparency log (SQLite).

Every signing operation, key-management action, pipeline stage and
verification decision is appended here. Each row stores

    entry_hash = SHA-256(prev_hash || canonical_json(row fields))

so deleting, reordering or editing any historical row breaks the chain and is
reported by :meth:`AuditLog.verify_chain`. This gives the vendor (and an
auditor) the evidence that was missing in the Codecov case: a record of *every*
release that was signed and *every* artifact a customer accepted or blocked.

Run ``python -m audit.audit_logger`` to print the log and check its integrity.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from contextlib import closing
from pathlib import Path

from common.crypto_utils import canonical_json, sha256_bytes, utc_now_iso
from common.workspace import Workspace

GENESIS = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    actor       TEXT NOT NULL,          -- user or process
    action      TEXT NOT NULL,          -- e.g. SIGN_RELEASE, VERIFY, KEY_REVOKE
    artifact    TEXT,
    version     TEXT,
    sha256      TEXT,
    key_id      TEXT,
    result      TEXT NOT NULL,          -- PASS / BLOCKED / HASH_MISMATCH / ...
    reason      TEXT,                   -- rejection reason
    details     TEXT,                   -- JSON blob
    prev_hash   TEXT NOT NULL,
    entry_hash  TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_audit_artifact ON audit_events(artifact, version);
"""

FIELDS = ("timestamp", "actor", "action", "artifact", "version", "sha256",
          "key_id", "result", "reason", "details")


def _entry_hash(prev_hash: str, row: dict) -> str:
    return sha256_bytes(prev_hash.encode() + canonical_json({k: row.get(k) for k in FIELDS}))


class AuditLog:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as conn:
            conn.executescript(SCHEMA)

    @classmethod
    def for_workspace(cls, ws: Workspace) -> "AuditLog":
        return cls(ws.audit_db)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def log(self, *, actor: str, action: str, result: str, artifact: str | None = None,
            version: str | None = None, sha256: str | None = None, key_id: str | None = None,
            reason: str | None = None, details: dict | None = None) -> dict:
        row = {
            "timestamp": utc_now_iso(), "actor": actor, "action": action,
            "artifact": artifact, "version": version, "sha256": sha256, "key_id": key_id,
            "result": result, "reason": reason,
            "details": json.dumps(details, sort_keys=True) if details else None,
        }
        with closing(self._connect()) as conn, conn:
            conn.execute("BEGIN IMMEDIATE")  # serialise writers so the chain never forks
            last = conn.execute("SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
            prev = last["entry_hash"] if last else GENESIS
            row["prev_hash"] = prev
            row["entry_hash"] = _entry_hash(prev, row)
            cols = ", ".join(row)
            conn.execute(f"INSERT INTO audit_events ({cols}) VALUES ({', '.join('?' * len(row))})",
                         tuple(row.values()))
        return row

    def events(self, limit: int | None = None) -> list[dict]:
        sql = "SELECT * FROM audit_events ORDER BY id"
        with closing(self._connect()) as conn:
            rows = [dict(r) for r in conn.execute(sql)]
        return rows[-limit:] if limit else rows

    def verify_chain(self) -> tuple[bool, int | None]:
        """Return (True, None) if intact, otherwise (False, id_of_first_bad_row)."""
        prev = GENESIS
        for row in self.events():
            if row["prev_hash"] != prev or _entry_hash(prev, row) != row["entry_hash"]:
                return False, row["id"]
            prev = row["entry_hash"]
        return True, None


def main() -> None:
    from common.console import green, red

    ap = argparse.ArgumentParser(description="Show the audit log and verify its hash chain")
    ap.add_argument("--limit", type=int, default=25)
    args = ap.parse_args()
    log = AuditLog.for_workspace(Workspace.default())
    print(f"{'ID':>4}  {'TIMESTAMP':20}  {'ACTOR':18} {'ACTION':18} {'ARTIFACT@VERSION':26} RESULT")
    for e in log.events(args.limit):
        art = f"{e['artifact'] or '-'}@{e['version'] or '-'}"
        res = e["result"]
        colour = green if res in ("PASS", "OK", "DEPLOYED") else red if res not in ("INFO",) else str
        print(f"{e['id']:>4}  {e['timestamp']:20}  {e['actor'][:18]:18} {e['action'][:18]:18} "
              f"{art[:26]:26} {colour(res)}" + (f"  ({e['reason']})" if e["reason"] else ""))
    ok, bad = log.verify_chain()
    print("\nHash chain:", green("INTACT") if ok else red(f"BROKEN at entry {bad}"))


if __name__ == "__main__":
    main()
