"""Vercel entry point for the Flask dashboard (dashboard/app.py).

Vercel's filesystem is read-only except /tmp, so the bundled audit database is
copied to /tmp on a cold start and the audit logger is pointed there. Entries
written by the live "Verify" button last only as long as that function instance.
"""

import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

TMP_DB = "/tmp/supply_chain_audit.db"
if not os.path.exists(TMP_DB):
    shutil.copyfile(os.path.join(ROOT, "audit", "supply_chain_audit.db"), TMP_DB)
os.environ.setdefault("AUDIT_DB_PATH", TMP_DB)

from dashboard.app import app  # noqa: E402  (Vercel serves this WSGI app)
