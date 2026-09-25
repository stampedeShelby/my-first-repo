"""One-time environment setup for a workspace.

Creates the vendor root + release keys, publishes the first root-signed trust
policy, pins the root public key into the customer trust anchor (the
out-of-band step), enrols the demo users for RBAC/MFA and creates the local
TLS certificate authority.

    python bootstrap.py            # uses ./workspace (or $SSCS_WORKSPACE)
    python bootstrap.py --reset    # wipe and recreate the workspace
"""

from __future__ import annotations

import argparse
import shutil

from common.workspace import Workspace
from distribution.tls_registry import ensure_tls_material
from vendor.access_control import AccessControl
from vendor.key_manager import KeyManager


def bootstrap(ws: Workspace, reset: bool = False) -> dict:
    if reset and ws.root.exists():
        shutil.rmtree(ws.root)
    ws.ensure()
    km = KeyManager(ws)
    ids = km.init()
    km.export_root_public_key()
    AccessControl(ws).enrol_demo_users()
    ensure_tls_material(ws)
    return ids


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--reset", action="store_true")
    args = ap.parse_args()
    ws = Workspace.default()
    ids = bootstrap(ws, reset=args.reset)
    print(f"workspace       : {ws.root}")
    print(f"root key        : {ids['root_key_id']}  (pinned in {ws.trusted_root})")
    print(f"release key     : {ids['release_key_id']}")
    print(f"trust policy    : {ws.trust_policy}")
    print("demo users      : alice (release-manager), bob (developer), carol (auditor)")


if __name__ == "__main__":
    main()
