"""5-minute live demonstration (prompt section 20).

    python demo.py            # pauses between steps (press Enter)
    python demo.py --no-pause # run straight through (CI / recording)

Uses its own workspace (./demo_workspace) which is wiped at the start, so the
demo is repeatable. Nothing leaves the machine: the registry is a local
TLS 1.3 server on 127.0.0.1 and the injected "exfiltration" URL uses the
unresolvable .invalid TLD. The tampered script is never executed.
"""

from __future__ import annotations

import argparse
import json

from attack_simulation.tamper import MALICIOUS_LINE, inject_codecov_style_payload
from audit.audit_logger import AuditLog
from bootstrap import bootstrap
from ci.security_gate import SecurityGate
from common.console import banner, bold, cyan, dim, green, red, yellow
from common.workspace import PROJECT_ROOT, Workspace
from dashboard.generate_dashboard import generate
from distribution.tls_registry import RegistryServer, fetch
from vendor.key_manager import KeyManager
from vendor.sign import release
from verifier.verify import print_result

PAUSE = True


def step(n: int, title: str) -> None:
    if PAUSE:
        input(dim("\n  [Enter] next step ..."))
    banner(f"STEP {n}: {title}")


def main() -> None:
    global PAUSE
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-pause", action="store_true")
    PAUSE = not ap.parse_args().no_pause
    ws = Workspace(PROJECT_ROOT / "demo_workspace")

    step(1, "The Codecov-style attack (2021, documented)")
    print("  Attacker obtained a credential that allowed modifying the Bash Uploader in cloud storage,")
    print("  then added ONE line that sent `git remote -v` + all environment variables (CI secrets) out:")
    print(yellow("    " + MALICIOUS_LINE.strip()))
    print("  Customers downloaded it over HTTPS from the genuine domain for ~2 months; it was caught when")
    print("  a customer noticed that the script's checksum did not match the published one.")

    step(2, "Architecture")
    print("  Developer -> Repo -> Secure build -> Security tests -> SHA-256 -> Signing service (HSM/KMS)")
    print("  -> Signed manifest + provenance -> Registry -> TLS 1.3 -> Customer CI -> Verification engine")
    print("  [signature | SHA-256 | key status | artifact status | provenance | policy] -> DEPLOY or BLOCK -> Audit log")
    ids = bootstrap(ws, reset=True)
    print(green(f"\n  root key {ids['root_key_id']} pinned by customer; release key {ids['release_key_id']} active"))

    step(3, "Vendor builds a legitimate artifact (security tests run first)")
    res, manifest, reg_a, reg_m = release(ws, "1.0.0")
    print(f"  artifact : {reg_a.name}  ({reg_a.stat().st_size} bytes)")
    print(f"  build_id : {res.provenance['build_id']}  builder: {res.provenance['builder_identity']}")

    env = json.loads(manifest.read_text())
    step(4, "SHA-256 fingerprint")
    print(f"  SHA-256  : {cyan(res.sha256)}")

    step(5, "Ed25519 digital signature (signed by alice: release-manager + MFA)")
    print(f"  key_id             : {env['manifest']['key_id']}")
    print(f"  artifact signature : {env['manifest']['artifact_signature'][:64]}...")
    print(f"  manifest signature : {env['signatures'][0]['sig'][:64]}...")

    step(6, "Customer downloads over TLS 1.3 and verifies -> PASS")
    with RegistryServer(ws) as srv:
        ia = fetch(ws, srv.base_url, reg_a.name)
        im = fetch(ws, srv.base_url, reg_m.name)
    print(f"  channel: {ia['tls_version']} / {ia['cipher']}")
    gate = SecurityGate(ws)
    d = gate.evaluate(ia["path"], im["path"])
    print_result(d.result)
    print(bold(green("  DECISION: DEPLOY")))

    step(7, "ATTACK: the registry copy is modified - one line added after signing")
    good = reg_a.read_bytes()
    inject_codecov_style_payload(reg_a)
    print(red("  + " + MALICIOUS_LINE.strip()))

    step(8, "Customer downloads again (TLS 1.3 is still perfectly valid!) and verifies")
    with RegistryServer(ws) as srv:
        ia = fetch(ws, srv.base_url, reg_a.name)
    print(f"  channel: {ia['tls_version']} - TLS protected the transfer of an already-malicious file")
    d = gate.evaluate(ia["path"], im["path"])

    step(9, "SHA-256 mismatch")
    print(f"  expected : {d.result.expected_sha256}\n  actual   : {red(d.result.actual_sha256)}")

    step(10, "Signature failure")
    for c in d.result.checks:
        if not c.passed:
            print(red(f"  FAIL {c.name:20} {c.detail}"))

    step(11, "CI/CD security gate blocks deployment")
    print_result(d.result)
    print(bold(red(f"  DECISION: BLOCK ({d.result.status.value}) - security event raised")))
    print(dim("  " + json.dumps(d.security_event)[:200] + " ..."))

    step(12, "Audit log (hash-chained)")
    log = AuditLog.for_workspace(ws)
    for e in log.events(8):
        colour = green if e["result"] in ("PASS", "OK", "DEPLOYED") else red
        print(f"  #{e['id']:<3} {e['actor']:16} {e['action']:20} {str(e['version'] or '-'):6} {colour(e['result'])}")
    print("  chain:", green("INTACT") if log.verify_chain()[0] else red("BROKEN"))

    step(13, "Key revocation (simulated key compromise)")
    km = KeyManager(ws)
    kid = km.active_key_id()
    km.revoke(kid, "suspected compromise (demo)")
    reg_a.write_bytes(good)  # put the genuine bytes back on the registry
    d = gate.evaluate(reg_a, reg_m, deploy=False)
    print(f"  revoked {kid}; the ORIGINAL v1.0.0 is now rejected too: {red(d.result.status.value)}")
    print(f"  new active key: {km.active_key_id()}")

    step(14, "Restore: vendor re-releases with the new key -> PASS")
    _, _, a2, m2 = release(ws, "1.0.1")
    d = gate.evaluate(a2, m2)
    print_result(d.result)
    print(bold(green("  DECISION: DEPLOY")))
    out = generate(ws, PROJECT_ROOT / "dashboard" / "index.html")
    print(f"\n  dashboard: {out}")
    banner("LEGITIMATE SOFTWARE -> VERIFIED -> DEPLOYED   |   TAMPERED SOFTWARE -> DETECTED -> BLOCKED")


if __name__ == "__main__":
    main()
