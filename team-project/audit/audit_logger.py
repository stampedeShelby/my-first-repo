"""
Audit Logger for Cryptographically Verified Software Supply Chain.
Maintains an immutable SQLite database for all artifact signing, verification,
and security gate events.
"""

import sqlite3
import datetime
import os
from typing import Optional, List, Dict, Any

DEFAULT_DB_PATH = os.environ.get(
    "AUDIT_DB_PATH",  # set on Vercel, where only /tmp is writable
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "supply_chain_audit.db"),
)

class AuditLogger:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    artifact TEXT NOT NULL,
                    version TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    verification_result TEXT NOT NULL,
                    user_process TEXT NOT NULL,
                    action TEXT NOT NULL,
                    rejection_reason TEXT
                )
            """)
            conn.commit()

    def log_event(
        self,
        artifact: str,
        version: str,
        sha256: str,
        key_id: str,
        verification_result: str,
        user_process: str,
        action: str,
        rejection_reason: Optional[str] = None,
        timestamp: Optional[str] = None
    ) -> int:
        """
        Record a verification or signing event.
        Allowed results: PASS, BLOCKED, REVOKED, HASH_MISMATCH, INVALID_SIGNATURE, UNAUTHORIZED_KEY, PROVENANCE_FAILED
        """
        if timestamp is None:
            timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_logs (
                    timestamp, artifact, version, sha256, key_id,
                    verification_result, user_process, action, rejection_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp, artifact, version, sha256, key_id,
                verification_result, user_process, action, rejection_reason
            ))
            conn.commit()
            return cursor.lastrowid

    def get_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent logs."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def clear_logs(self):
        """Clear logs (for test resets)."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM audit_logs")
            conn.commit()

if __name__ == "__main__":
    logger = AuditLogger()
    row_id = logger.log_event(
        artifact="secure-uploader",
        version="1.0.0",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        key_id="KEY-VENDOR-2026-PRIMARY",
        verification_result="PASS",
        user_process="CI-Runner#402",
        action="DEPLOY",
        rejection_reason=None
    )
    print(f"[+] Audit log recorded successfully. Row ID: {row_id}")
    logs = logger.get_logs(limit=1)
    print(f"[+] Retrieved log entry: {logs[0]}")
