# Cryptographically Verified Software Supply Chain

**Preventing Codecov-style supply-chain attacks** — INS (BCS701) CCA prototype.

In 2021 an attacker who had obtained a storage credential modified Codecov's
Bash Uploader so that it sent customers' CI secrets to an external server. The
file was served from the genuine domain over HTTPS for about two months, and
was found only when a customer noticed that its checksum did not match the
published one.

This prototype makes that attack fail automatically. A customer pipeline
deploys vendor software only after proving **both**:

1. **Integrity**: the artifact was not modified (SHA-256 plus an Ed25519
   artifact signature).
2. **Authenticity and authorisation**: a vendor release key that the
   root-signed trust policy lists as valid signed it, the key is not revoked,
   the version is not revoked or rolled back, and the provenance shows an
   approved builder and repository.

```
LEGITIMATE SOFTWARE -> VERIFIED -> DEPLOYED
TAMPERED SOFTWARE   -> DETECTED -> BLOCKED
```

![architecture](docs/diagrams/architecture.png)

## Quick start

Requires Python 3.10+.

```bash
cd secure-supply-chain
pip install -r requirements.txt

python demo.py                       # 14-step live demo (press Enter between steps)
python demo.py --no-pause            # run straight through
python -m attack_simulation.run_all  # all attack scenarios -> docs/results/attack_results.json
python -m pytest -v                  # 25 automated tests
python -m tests.generate_test_report # test table + timing / FAR benchmark
```

The demo, the tests and the attack simulations each use their own isolated
workspace. Nothing contacts an external system. The registry is a local
TLS 1.3 server on 127.0.0.1, and the injected "exfiltration" URL uses the
reserved `.invalid` domain, which can never resolve. The tampered script is
never executed.

## Step-by-step (manual walkthrough)

```bash
python bootstrap.py --reset                        # root + release keys, trust policy, users, TLS CA
python -m vendor.sign --version 1.0.0 --user alice # build -> tests -> SHA-256 -> sign (MFA) -> publish
python -m distribution.tls_registry serve &        # TLS 1.3 registry on https://localhost:8443
python -m distribution.tls_registry fetch secure-uploader-1.0.0.sh
python -m distribution.tls_registry fetch secure-uploader-1.0.0.sh.manifest.json
python -m ci.security_gate verify \
    --artifact workspace/customer/downloads/secure-uploader-1.0.0.sh \
    --manifest workspace/customer/downloads/secure-uploader-1.0.0.sh.manifest.json   # -> DEPLOY (exit 0)

python -m attack_simulation.tamper workspace/customer/downloads/secure-uploader-1.0.0.sh
python -m ci.security_gate verify --artifact ... --manifest ...                     # -> BLOCK (exit 1)

python -m vendor.key_manager revoke <key_id> --reason "compromise"                  # key revocation
python -m audit.audit_logger                                                        # audit trail + chain check
python -m dashboard.generate_dashboard                                              # dashboard/index.html
```

Set `SSCS_KEY_PASSPHRASE` to protect the private keys with your own
passphrase. Without it, a demo passphrase is used.

## What the verification engine checks

| # | Check | Failure status |
|---|---|---|
| 1 | Trust policy signed by the pinned root key, not expired, not rolled back | `INVALID_TRUST_POLICY` |
| 2 | Manifest schema | `INVALID_MANIFEST` |
| 3 | Signing key is listed in the trust policy | `UNAUTHORIZED_KEY` |
| 4 | Key status (active; retired only for older releases) | `REVOKED` |
| 5 | Ed25519 manifest signature | `INVALID_SIGNATURE` |
| 6 | SHA-256 of the downloaded bytes equals the value in the manifest | `HASH_MISMATCH` |
| 7 | Ed25519 detached artifact signature | `INVALID_SIGNATURE` |
| 8 | Version not revoked, not below the minimum, no rollback | `REVOKED` / `REPLAY_BLOCKED` |
| 9 | Provenance is bound to the artifact; approved builder and repository | `INVALID_PROVENANCE` |
| 10 | Security policy: algorithms, vendor tests passed, content scan, maximum age | `POLICY_VIOLATION` |

## Results

The full table is in [docs/results/test_table.md](docs/results/test_table.md).

* 25/25 automated tests pass, and all 14 attack scenarios behave as expected.
* 1,000 randomly tampered artifacts were rejected, giving a **false-acceptance
  rate of 0**.
* A full 10-check verification takes about **2 ms**.

## Documentation

* [docs/DESIGN.md](docs/DESIGN.md) covers the architecture, STRIDE threat
  model, cryptographic design, key management, database schema, API,
  implementation plan, limitations and future work.
* [docs/diagrams/](docs/diagrams/) holds the diagrams
  (`python docs/diagrams/make_diagrams.py`, requires Graphviz).
* [docs/results/](docs/results/) holds the test table, benchmark, attack
  results, chart and dashboard screenshot.

## Scope

This is an academic prototype. The software key store stands in for an HSM or
cloud KMS, and the static rules are heuristics. See the limitations section of
`docs/DESIGN.md`.
