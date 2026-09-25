"""Static rules that flag Codecov-style credential exfiltration in shell artifacts.

Used twice (defence in depth):
* by the vendor build (``vendor/build.py``) before anything is signed, and
* by the customer gate (``verifier/verify.py``) on the downloaded bytes, so even
  an artifact signed with a *stolen* key is blocked if it carries the payload.

Pattern matching is a heuristic: an obfuscated payload can evade it. It
complements, and never replaces, signatures + key revocation.
"""

from __future__ import annotations

import re

SECURITY_RULES = [
    ("EXFIL_ENV", re.compile(r"\$\(\s*(env|printenv|set|export\s+-p)\s*\)"),
     "collects the full environment (credentials/tokens)"),
    ("EXFIL_GIT_REMOTE", re.compile(r"git\s+remote\s+-v"),
     "collects git remote URLs"),
    ("POST_TO_RAW_IP", re.compile(r"https?://\d{1,3}(\.\d{1,3}){3}"),
     "sends data to a hard-coded IP address"),
    ("CURL_DATA_SUBSHELL", re.compile(r"curl[^\n]*\s-(d|-data[\w-]*)\s+[\"']?\$\("),
     "posts command output with curl"),
    ("PIPE_TO_SHELL", re.compile(r"(curl|wget)[^\n|]*\|\s*(ba)?sh\b"),
     "downloads and executes remote code"),
    ("SILENT_FAILURE_EXFIL", re.compile(r"curl[^\n]*-s[^\n]*\|\|\s*true"),
     "silently ignores a network call's failure"),
]


def run_security_tests(text: str) -> dict:
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        for rule_id, pattern, desc in SECURITY_RULES:
            if pattern.search(line):
                findings.append({"rule": rule_id, "line": lineno, "description": desc})
    return {"passed": not findings, "rules_checked": len(SECURITY_RULES), "findings": findings}
