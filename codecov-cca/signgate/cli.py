"""Command line entry point.

  python -m signgate.cli init    --vault V --bucket B --policy policy.json
  python -m signgate.cli release --vault V --bucket B --file uploader.sh --version 1.4.0
  python -m signgate.cli run     --bucket B --policy policy.json [--state state.json]
  python -m signgate.cli revoke  --vault V --bucket B --key-id <id>
  python -m signgate.cli monitor --bucket B --known known.json
"""
import argparse
import json
import os
import sys

from . import gate, monitor, publisher


def main(argv=None):
    p = argparse.ArgumentParser(prog="signgate")
    p.add_argument("cmd", choices=["init", "release", "run", "revoke", "monitor"])
    p.add_argument("--vault")
    p.add_argument("--bucket")
    p.add_argument("--policy")
    p.add_argument("--state")
    p.add_argument("--file")
    p.add_argument("--version")
    p.add_argument("--key-id")
    p.add_argument("--known")
    a = p.parse_args(argv)

    if a.cmd == "init":
        policy = publisher.setup_publisher(a.vault, a.bucket)
        policy.update({"min_version": "1.0.0",
                       "env_allowlist": ["PATH", "CODECOV_TOKEN", "GITHUB_SHA", "GITHUB_REF"]})
        with open(a.policy, "w") as f:
            json.dump(policy, f, indent=2)
        print(f"Trust policy written to {a.policy} (commit this file to your repo)")
    elif a.cmd == "release":
        m = publisher.release(a.vault, a.bucket, a.file, a.version)
        print(f"Released v{a.version} sha256={m['body']['sha256']}")
    elif a.cmd == "revoke":
        publisher.revoke(a.vault, a.bucket, key_ids=[a.key_id])
        print(f"Key {a.key_id} revoked")
    elif a.cmd == "monitor":
        with open(a.known) as f:
            alerts = monitor.check_bucket(a.bucket, set(json.load(f)))
        print("\n".join(alerts) or "OK: served artifact matches the latest signed, logged release")
        return 1 if alerts else 0
    elif a.cmd == "run":
        with open(a.policy) as f:
            policy = json.load(f)
        state = {}
        if a.state and os.path.exists(a.state):
            with open(a.state) as f:
                state = json.load(f)
        allowed, report, output = gate.run(a.bucket, policy, state)
        gate.print_report(report)
        print(output)
        if allowed and a.state:
            with open(a.state, "w") as f:
                json.dump(state, f)
        return 0 if allowed else 1


if __name__ == "__main__":
    sys.exit(main())
