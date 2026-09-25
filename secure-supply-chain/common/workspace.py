"""Filesystem layout of one vendor + registry + customer environment.

Everything the prototype produces lives under one workspace root so that the
demo, the tests and the CI pipeline can each run in an isolated directory.

    <root>/keys/private/        encrypted vendor private keys   (VENDOR ONLY, 0600)
    <root>/keys/key_registry.json  vendor key metadata          (VENDOR ONLY)
    <root>/keys/access_control.json RBAC + MFA enrolment        (VENDOR ONLY)
    <root>/artifacts/           build output + signed manifests (vendor)
    <root>/registry/            what the public artifact registry serves
    <root>/tls/                 local CA + TLS 1.3 server certificate
    <root>/customer/            customer CI: pinned root key, policy, downloads, deployments
    <root>/audit/audit.db       hash-chained audit / transparency log
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIR = PROJECT_ROOT / "src_app"
DEFAULT_CUSTOMER_POLICY = PROJECT_ROOT / "policy" / "customer_security_policy.json"


@dataclass(frozen=True)
class Workspace:
    root: Path

    @classmethod
    def default(cls) -> "Workspace":
        return cls(Path(os.environ.get("SSCS_WORKSPACE", PROJECT_ROOT / "workspace")).resolve())

    # vendor side
    @property
    def keys_dir(self) -> Path:
        return self.root / "keys"

    @property
    def private_keys_dir(self) -> Path:
        return self.keys_dir / "private"

    @property
    def key_registry(self) -> Path:
        return self.keys_dir / "key_registry.json"

    @property
    def access_control(self) -> Path:
        return self.keys_dir / "access_control.json"

    @property
    def artifacts_dir(self) -> Path:
        return self.root / "artifacts"

    # distribution
    @property
    def registry_dir(self) -> Path:
        return self.root / "registry"

    @property
    def trust_policy(self) -> Path:
        return self.registry_dir / "trust_policy.json"

    @property
    def tls_dir(self) -> Path:
        return self.root / "tls"

    # customer side
    @property
    def customer_dir(self) -> Path:
        return self.root / "customer"

    @property
    def trusted_root(self) -> Path:
        return self.customer_dir / "trusted_root.pub"

    @property
    def customer_policy(self) -> Path:
        return self.customer_dir / "security_policy.json"

    @property
    def customer_state(self) -> Path:
        return self.customer_dir / "deployment_state.json"

    @property
    def downloads_dir(self) -> Path:
        return self.customer_dir / "downloads"

    @property
    def deployed_dir(self) -> Path:
        return self.customer_dir / "deployed"

    # audit
    @property
    def audit_db(self) -> Path:
        return self.root / "audit" / "audit.db"

    @property
    def security_events(self) -> Path:
        return self.root / "audit" / "security_events.jsonl"

    def ensure(self) -> "Workspace":
        for d in (
            self.private_keys_dir,
            self.artifacts_dir,
            self.registry_dir,
            self.tls_dir,
            self.downloads_dir,
            self.deployed_dir,
            self.audit_db.parent,
        ):
            d.mkdir(parents=True, exist_ok=True)
        if not self.customer_policy.exists():
            self.customer_policy.write_text(DEFAULT_CUSTOMER_POLICY.read_text())
        return self


def read_json(path: Path, default=None):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def parse_version(version: str) -> tuple[int, ...]:
    """Parse a MAJOR.MINOR.PATCH string into a comparable tuple."""
    parts = version.strip().split(".")
    if not parts or not all(p.isdigit() for p in parts):
        raise ValueError(f"invalid version: {version!r}")
    return tuple(int(p) for p in parts)
