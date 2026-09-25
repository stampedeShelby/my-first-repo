"""RBAC + MFA for release operations.

Only users holding the ``release-manager`` role may ask the signing service to
sign a release, and every request must carry a valid time-based one-time
password (TOTP, RFC 6238). In the Codecov incident a single leaked cloud
credential was enough to replace a production release; here a stolen
password/token alone is not enough to obtain a signature.

The TOTP is implemented with the standard library so the mechanism is visible;
``python -m vendor.access_control otp <user>`` plays the role of the user's
authenticator app in the demo.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import secrets
import struct
import time

from common.workspace import Workspace, read_json, write_json

ROLE_PERMISSIONS = {
    "release-manager": {"sign_release"},
    "developer": {"build"},
    "auditor": {"read_audit"},
}

DEMO_USERS = {"alice": "release-manager", "bob": "developer", "carol": "auditor"}


class AccessDenied(Exception):
    pass


def totp(secret_b32: str, at: float | None = None, step: int = 30, digits: int = 6) -> str:
    key = base64.b32decode(secret_b32)
    counter = int((at if at is not None else time.time()) // step)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return f"{code:0{digits}d}"


class AccessControl:
    def __init__(self, ws: Workspace):
        self.ws = ws.ensure()

    def _db(self) -> dict:
        return read_json(self.ws.access_control, {"users": {}})

    def enrol(self, user: str, role: str) -> str:
        if role not in ROLE_PERMISSIONS:
            raise ValueError(f"unknown role {role}")
        db = self._db()
        secret = base64.b32encode(secrets.token_bytes(20)).decode()
        db["users"][user] = {"role": role, "totp_secret": secret}
        write_json(self.ws.access_control, db)
        return secret

    def enrol_demo_users(self) -> None:
        for user, role in DEMO_USERS.items():
            if user not in self._db()["users"]:
                self.enrol(user, role)

    def current_otp(self, user: str) -> str:
        """Simulates the user's authenticator app (demo only)."""
        u = self._db()["users"].get(user)
        if not u:
            raise AccessDenied(f"unknown user {user}")
        return totp(u["totp_secret"])

    def authorize(self, user: str, otp: str | None, permission: str) -> str:
        u = self._db()["users"].get(user)
        if not u:
            raise AccessDenied(f"unknown user '{user}'")
        if permission not in ROLE_PERMISSIONS[u["role"]]:
            raise AccessDenied(f"user '{user}' (role {u['role']}) lacks permission '{permission}'")
        if not otp:
            raise AccessDenied("MFA code required")
        now = time.time()
        # accept the previous/current/next 30 s window to tolerate clock drift
        if not any(hmac.compare_digest(otp, totp(u["totp_secret"], now + d)) for d in (-30, 0, 30)):
            raise AccessDenied("invalid MFA code")
        return u["role"]


def main() -> None:
    ap = argparse.ArgumentParser(description="RBAC / MFA administration")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("enrol-demo")
    o = sub.add_parser("otp", help="print the current one-time code (authenticator simulation)")
    o.add_argument("user")
    args = ap.parse_args()
    ac = AccessControl(Workspace.default())
    if args.cmd == "enrol-demo":
        ac.enrol_demo_users(); print("enrolled:", ", ".join(f"{u} ({r})" for u, r in DEMO_USERS.items()))
    else:
        print(ac.current_otp(args.user))


if __name__ == "__main__":
    main()
