"""Secure build: security tests -> package -> SHA-256 -> provenance.

The build refuses to produce an artifact if the static security tests find
behaviour that matches the Codecov-style exfiltration pattern (sending ``env``
or ``git remote -v`` output to an external host, hard-coded IP endpoints,
``curl | bash`` chains). This is a *preventive* control at the vendor side;
the customer-side verification gate is the *detective/blocking* control.

Provenance (inspired by SLSA / in-toto) records *how* the artifact was made
so that a customer can check it came from an approved builder and source
repository, not just that it is signed.
"""

from __future__ import annotations

import argparse
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

from audit.audit_logger import AuditLog
from common.crypto_utils import sha256_bytes, sha256_file, utc_now_iso
from common.security_rules import run_security_tests
from common.workspace import SOURCE_DIR, Workspace, parse_version

ARTIFACT_NAME = "secure-uploader"
SOURCE_FILE = "secure-uploader.sh"
BUILDER_ID = "vendor-secure-builder-01"
SOURCE_REPOSITORY = "https://git.vendor.example/secure-uploader.git"
DEPENDENCIES = [
    {"name": "bash", "version": ">=4.4", "type": "runtime"},
    {"name": "coreutils", "version": ">=8.30", "type": "runtime"},
]

class BuildError(Exception):
    pass


@dataclass
class BuildResult:
    artifact_path: Path
    sha256: str
    provenance: dict


def _git_commit() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=SOURCE_DIR, capture_output=True,
                              text=True, check=True, timeout=5).stdout.strip()
    except Exception:
        return "unversioned"


def build(ws: Workspace, version: str, source_dir: Path = SOURCE_DIR, actor: str = "ci-builder",
          builder_id: str = BUILDER_ID) -> BuildResult:
    parse_version(version)
    ws.ensure()
    audit = AuditLog.for_workspace(ws)
    src = (source_dir / SOURCE_FILE).read_text(encoding="utf-8")

    tests = run_security_tests(src)
    if not tests["passed"]:
        audit.log(actor=actor, action="SECURITY_TESTS", result="BLOCKED", artifact=ARTIFACT_NAME,
                  version=version, reason="security test findings", details=tests)
        raise BuildError(f"security tests failed: {tests['findings']}")
    audit.log(actor=actor, action="SECURITY_TESTS", result="PASS", artifact=ARTIFACT_NAME, version=version)

    content = src.replace("__VERSION__", version).encode("utf-8")
    out = ws.artifacts_dir / f"{ARTIFACT_NAME}-{version}.sh"
    out.write_bytes(content)
    digest = sha256_file(out)

    provenance = {
        "source_repository": SOURCE_REPOSITORY,
        "commit_id": _git_commit(),
        "source_sha256": sha256_bytes(src.encode("utf-8")),
        "build_id": str(uuid.uuid4()),
        "build_timestamp": utc_now_iso(),
        "builder_identity": builder_id,
        "build_type": "sscs/scripted-build@v1",
        "dependencies": DEPENDENCIES,
        "security_tests": tests,
        "artifact_sha256": digest,
    }
    audit.log(actor=actor, action="BUILD", result="PASS", artifact=ARTIFACT_NAME, version=version,
              sha256=digest, details={"build_id": provenance["build_id"]})
    return BuildResult(out, digest, provenance)


def main() -> None:
    ap = argparse.ArgumentParser(description="Build the secure-uploader artifact")
    ap.add_argument("--version", required=True)
    args = ap.parse_args()
    res = build(Workspace.default(), args.version)
    print(f"artifact : {res.artifact_path}\nsha256   : {res.sha256}\nbuild_id : {res.provenance['build_id']}")


if __name__ == "__main__":
    main()
