# SignGate: Codecov 2021 Supply-Chain Attack, Case Study and Cryptographic Fix

INS (BCS701) CCA: *Real-World Security Breach Analysis & Cryptographic Solution Design*.

**Incident.** Between 31 Jan and 1 Apr 2021, an attacker used a Google Cloud Storage HMAC key
leaked from a layer of Codecov's public Docker image to modify the Codecov Bash Uploader.
Thousands of CI pipelines ran the modified script, which sent their environment variables
(tokens, cloud keys, signing keys) and git remote URLs to the attacker.

**Solution.** SignGate is a *verify-before-execute* gate. It runs inside CI in place of
`curl https://codecov.io/bash | bash`. The uploader runs only if all six checks pass:

| # | Check | Crypto | Stops |
|---|-------|--------|-------|
| 1 | Key certificate from pinned root | Ed25519 mini-PKI | attacker's own signing key |
| 2 | Revocation list | root-signed CRL | stolen / leaked release key |
| 3 | Manifest signature | Ed25519 (RFC 8032) | forged or edited manifest |
| 4 | Artifact integrity | SHA-256 (FIPS 180-4) | **the actual 2021 attack** |
| 5 | Anti-rollback | signed version | downgrade to an old buggy release |
| 6 | Transparency log | SHA-256 hash chain + signed head | silent releases with a stolen key |

After the checks pass, the uploader runs with an **environment allowlist**. In our test, a
malicious uploader could read 1 of 8 CI secrets instead of all 8. On the publisher side, a
**monitor** re-downloads the served file and raises an alert within minutes. In 2021 the
change went unnoticed for about two months.

## Deliverables

- Report: `docs/INS_CCA_Report_Codecov_SignGate.docx` (+ `.pdf`)
- Slides: `docs/INS_CCA_Slides_Codecov_SignGate.pptx` (speaker notes included)
- Plan, rubric mapping, talk timing, viva Q&A: `PLAN.md`

## Run it

```bash
pip install cryptography
python demo/attack_demo.py                       # 9 attack scenarios + timing
python -m unittest discover -s tests -v          # 13 unit tests
```

## Layout

```
signgate/crypto_utils.py  SHA-256, Ed25519 sign/verify, AES-encrypted PKCS#8 key storage
signgate/pki.py           root -> release key certificates, revocation list
signgate/tlog.py          append-only hash-chained transparency log
signgate/publisher.py     key ceremony, release (hash -> sign -> log -> publish), rotate, revoke
signgate/gate.py          the 6-check CI gate + least-privilege execution
signgate/monitor.py       publisher-side tamper monitor
signgate/cli.py           command line
demo/attack_demo.py       replays the attack and stronger variants
docs/                     report (.docx/.pdf), slides (.pptx), figures, build scripts
```

Rebuild the documents: `python docs/src/build_report.py docs/templates/CCA_report_format-INS.docx out.docx` and
`python docs/src/build_ppt.py docs/templates/BCS701-ppt_format.pptx out.pptx` (needs python-docx, python-pptx).
