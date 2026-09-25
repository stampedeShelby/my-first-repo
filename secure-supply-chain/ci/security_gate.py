"""Continuous Software Supply-Chain Security Gate.

Vendor pipeline -> registry -> customer pipeline, enforced end to end:

    Build -> Security tests -> SHA-256 -> Sign (RBAC+MFA) -> Provenance
          -> Publish -> TLS 1.3 download -> Verify signature -> Verify SHA-256
          -> Check key status -> Check artifact/version status -> Provenance
          -> Policy -> DEPLOY or BLOCK

If any stage violates policy the pipeline STOPS, nothing is deployed, a
security event is written to ``audit/security_events.jsonl`` and every decision
lands in the hash-chained audit log.

Customer CI usage (exit code 0 = deploy, 1 = blocked)::

    python -m ci.security_gate verify --artifact X --manifest X.manifest.json
    python -m ci.security_gate pipeline --version 1.0.0
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from audit.audit_logger import AuditLog
from common.console import bold, green, red, yellow
from common.crypto_utils import utc_now_iso
from common.workspace import Workspace, read_json, write_json
from distribution.tls_registry import RegistryServer, fetch
from verifier.verify import VerificationResult, Verifier, print_result

DEPLOY, BLOCK = "DEPLOY", "BLOCK"


@dataclass
class GateDecision:
    decision: str
    result: VerificationResult
    security_event: dict | None = None

    @property
    def deployed(self) -> bool:
        return self.decision == DEPLOY


class SecurityGate:
    def __init__(self, ws: Workspace, actor: str = "customer-ci"):
        self.ws = ws.ensure()
        self.actor = actor
        self.audit = AuditLog.for_workspace(ws)

    def evaluate(self, artifact_path: Path, manifest_path: Path, deploy: bool = True) -> GateDecision:
        res = Verifier(self.ws).verify(artifact_path, manifest_path)
        state = read_json(self.ws.customer_state, {"trust_policy_version_seen": 0, "deployed": {}})
        if res.trust_policy_version:
            state["trust_policy_version_seen"] = max(state["trust_policy_version_seen"], res.trust_policy_version)

        if res.passed:
            self.audit.log(actor=self.actor, action="VERIFY", result="PASS", artifact=res.artifact,
                           version=res.version, sha256=res.actual_sha256, key_id=res.key_id,
                           details={"elapsed_ms": round(res.elapsed_ms, 3)})
            if deploy:
                target = self.ws.deployed_dir / res.artifact
                shutil.copy2(artifact_path, target)
                state["deployed"][res.artifact] = {"version": res.version, "sha256": res.actual_sha256,
                                                   "deployed_at": utc_now_iso()}
                self.audit.log(actor=self.actor, action="DEPLOY", result="DEPLOYED", artifact=res.artifact,
                               version=res.version, sha256=res.actual_sha256, key_id=res.key_id)
            write_json(self.ws.customer_state, state)
            return GateDecision(DEPLOY, res)

        event = {
            "timestamp": utc_now_iso(), "type": "SUPPLY_CHAIN_SECURITY_EVENT", "severity": "HIGH",
            "decision": BLOCK, "status": res.status.value, "artifact": res.artifact,
            "version": res.version, "key_id": res.key_id, "expected_sha256": res.expected_sha256,
            "actual_sha256": res.actual_sha256, "reasons": res.reasons, "actor": self.actor,
        }
        self.audit.log(actor=self.actor, action="VERIFY", result=res.status.value, artifact=res.artifact,
                       version=res.version, sha256=res.actual_sha256, key_id=res.key_id,
                       reason="; ".join(res.reasons)[:500])
        self.audit.log(actor=self.actor, action="DEPLOY", result="BLOCKED", artifact=res.artifact,
                       version=res.version, sha256=res.actual_sha256, key_id=res.key_id,
                       reason=res.status.value)
        with open(self.ws.security_events, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event) + "\n")
        write_json(self.ws.customer_state, state)
        return GateDecision(BLOCK, res, event)


# --------------------------------------------------------------------------- pipeline

@dataclass
class PipelineReport:
    stages: list[dict] = field(default_factory=list)
    decision: GateDecision | None = None
    stopped_at: str | None = None

    def stage(self, name: str, ok: bool, detail: str = "") -> bool:
        self.stages.append({"stage": name, "ok": ok, "detail": detail})
        print(f"  {'[OK]  ' if ok else '[STOP]'} {name:28} {detail}" if not sys.stdout.isatty() else
              f"  {green('[OK]  ') if ok else red('[STOP]')} {name:28} {detail}")
        if not ok:
            self.stopped_at = name
        return ok


def run_pipeline(ws: Workspace, version: str, user: str = "alice", otp: str | None = None,
                 attack: Callable[[Path, Path], None] | None = None, use_tls: bool = True,
                 source_dir: Path | None = None) -> PipelineReport:
    """Run the whole vendor->customer pipeline. `attack(registry_artifact, registry_manifest)`
    can mutate the registry between publish and download (compromised-registry simulation)."""
    from vendor.access_control import AccessControl, AccessDenied
    from vendor.build import BuildError, build
    from vendor.sign import SigningService, publish

    rep = PipelineReport()
    audit = AuditLog.for_workspace(ws)
    try:
        b = build(ws, version, **({"source_dir": source_dir} if source_dir else {}))
    except BuildError as exc:
        rep.stage("build + security tests", False, str(exc)[:120])
        _pipeline_event(ws, audit, version, "build + security tests", str(exc))
        return rep
    rep.stage("build + security tests", True, f"{b.provenance['security_tests']['rules_checked']} rules, 0 findings")
    rep.stage("SHA-256", True, b.sha256)

    svc = SigningService(ws)
    try:
        otp = otp if otp is not None else AccessControl(ws).current_otp(user)
    except AccessDenied:
        otp = None
    try:
        manifest = svc.sign_release(user=user, otp=otp, artifact_path=b.artifact_path, version=version,
                                    provenance=b.provenance)
    except AccessDenied as exc:
        rep.stage("sign (RBAC + MFA)", False, f"UNAUTHORIZED_SIGNER: {exc}")
        _pipeline_event(ws, audit, version, "sign", f"unauthorized signing attempt: {exc}")
        return rep
    env = json.loads(manifest.read_text())
    rep.stage("sign (RBAC + MFA)", True, f"Ed25519 by {env['manifest']['key_id']}")
    rep.stage("record provenance", True, f"build {b.provenance['build_id'][:8]} by {b.provenance['builder_identity']}")

    reg_a, reg_m = publish(ws, b.artifact_path, manifest)
    rep.stage("publish to registry", True, reg_a.name)
    if attack:
        attack(reg_a, reg_m)
        print(yellow("  [!!]  registry compromised: artifact/manifest modified after signing"))

    if use_tls:
        with RegistryServer(ws) as srv:
            ia = fetch(ws, srv.base_url, reg_a.name)
            im = fetch(ws, srv.base_url, reg_m.name)
            fetch(ws, srv.base_url, "trust_policy.json", dest_dir=ws.customer_dir / "downloads")
        rep.stage("download over TLS", True, f"{ia['tls_version']} {ia['cipher']}")
        art, man = ia["path"], im["path"]
    else:
        art, man = reg_a, reg_m

    decision = SecurityGate(ws).evaluate(art, man)
    rep.decision = decision
    print_result(decision.result)
    rep.stage("verify + policy gate", decision.deployed, decision.result.status.value)
    if decision.deployed:
        rep.stage("deploy", True, f"{decision.result.artifact}@{version} deployed")
    else:
        print(red(bold(f"  PIPELINE STOPPED - deployment BLOCKED ({decision.result.status.value}); security event raised")))
    return rep


def _pipeline_event(ws: Workspace, audit: AuditLog, version: str, stage: str, reason: str) -> None:
    event = {"timestamp": utc_now_iso(), "type": "SUPPLY_CHAIN_SECURITY_EVENT", "severity": "HIGH",
             "decision": BLOCK, "stage": stage, "version": version, "reasons": [reason]}
    audit.log(actor="release-pipeline", action="PIPELINE_STOP", result="BLOCKED", version=version,
              reason=f"{stage}: {reason}"[:500])
    with open(ws.security_events, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(event) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser(description="Supply-chain security gate")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="customer CI gate for an already-downloaded artifact")
    v.add_argument("--artifact", required=True); v.add_argument("--manifest", required=True)
    v.add_argument("--no-deploy", action="store_true")
    p = sub.add_parser("pipeline", help="run the full vendor -> customer pipeline")
    p.add_argument("--version", required=True); p.add_argument("--user", default="alice")
    p.add_argument("--no-tls", action="store_true")
    args = ap.parse_args()
    ws = Workspace.default()
    if args.cmd == "verify":
        d = SecurityGate(ws).evaluate(Path(args.artifact), Path(args.manifest), deploy=not args.no_deploy)
        print_result(d.result)
        print(bold(green("DECISION: DEPLOY")) if d.deployed else bold(red("DECISION: BLOCK")))
        sys.exit(0 if d.deployed else 1)
    rep = run_pipeline(ws, args.version, args.user, use_tls=not args.no_tls)
    sys.exit(0 if rep.decision and rep.decision.deployed else 1)


if __name__ == "__main__":
    main()
