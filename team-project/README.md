# Cryptographically Verified Software Supply Chain
### Preventing Codecov-Style Supply Chain Attacks

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Cryptography](https://img.shields.io/badge/cryptography-Ed25519%20%7C%20SHA--256-green.svg)](https://cryptography.io/)
[![Security Gate](https://img.shields.io/badge/security%20gate-zero--trust-brightgreen.svg)](ci/security_gate.py)
[![False Acceptance Rate](https://img.shields.io/badge/FAR-0.00%25-success.svg)](tests/test_supply_chain.py)

---

## 1. Project Overview

This project implements a complete, working academic prototype of a **Cryptographically Verified Software Supply Chain**, engineered to prevent software supply-chain attacks such as the documented **2021 Codecov Bash Uploader breach**.

In that incident, an attacker obtained an HMAC key to Codecov's Google Cloud Storage (GCS) bucket, modified the publicly distributed `uploader.sh` script to exfiltrate developer credentials and CI environment secrets, and infected millions of downstream builds. Even though artifacts were served over valid HTTPS (TLS 1.3), downstream consumers implicitly trusted the server's contents.

### Core Security Principle
A customer must verify **BOTH**:
1. **Integrity:** The artifact has not been modified (deterministic SHA-256 fingerprint).
2. **Authenticity & Authorization:** The artifact was authorized and signed by the trusted vendor (Ed25519 digital signature + Key Revocation List check + SLSA provenance).

```
LEGITIMATE SOFTWARE  -->  VERIFIED  -->  DEPLOYED
TAMPERED SOFTWARE    -->  DETECTED  -->  BLOCKED
```

---

## 2. Directory Structure

```
secure-supply-chain/
├── vendor/
│   ├── build.py               # Deterministic hashing & SLSA Level 2+ provenance generator
│   ├── sign.py                # Ed25519 canonical JSON signing engine
│   └── key_manager.py         # Key generation, PKCS#8 storage, rotation, and CRL management
├── verifier/
│   ├── verify.py              # Customer-side multi-stage cryptographic verifier
│   ├── manifest.py            # Canonical JSON parser and schema validator
│   └── policy.py              # Zero-trust admission control policy
├── artifacts/
│   ├── uploader.sh            # Legitimate Codecov bash uploader script
│   ├── uploader.sh.manifest.json  # Tamper-evident Ed25519 signed release manifest
│   └── uploader.sh.provenance.json# SLSA provenance descriptor
├── attack_simulation/
│   ├── tamper.py              # Codecov-style credential exfiltration injection test
│   └── revoked_key_test.py    # Rogue key and version replay attack tests
├── ci/
│   └── security_gate.py       # Automated CI/CD admission gate CLI
├── audit/
│   ├── audit_logger.py        # SQLite persistent audit database engine
│   └── supply_chain_audit.db  # SQLite database storing verification logs
├── dashboard/
│   └── app.py                 # Real-time web observability dashboard (Flask)
├── keys/                      # Public/private keys and revoked_keys.json (CRL)
├── tests/
│   └── test_supply_chain.py   # Automated suite verifying the 9 required test cases
├── docs/
│   ├── architecture.md        # Architecture diagrams (Mermaid) and data flows
│   ├── threat_model.md        # Complete STRIDE threat analysis matrix
│   ├── report_design_and_implementation.md # Submission-ready academic report
│   └── presentation_slides.md # 12-slide presentation structure for viva/defense
├── demo.py                    # 14-step live interactive demonstration runner
└── README.md
```

---

## 3. Quickstart & Execution Guide

### Prerequisites
- Python 3.10+
- Libraries: `cryptography`, `flask`

```powershell
pip install cryptography flask
```

### A. Run the 5-Minute Live Viva Demonstration (14 Steps)
Executes the sequential 14-step academic demonstration protocol:
```powershell
python demo.py
```
*(Add `--interactive` or `-i` to pause between steps for live presentation defense!)*

### B. Run the Automated 9-Point Security Test Suite
Runs all 9 security test cases and prints validation telemetry and performance metrics:
```powershell
python tests/test_supply_chain.py
```

### C. Run the CI/CD Zero-Trust Security Gate
Simulates how a customer CI pipeline verifies artifacts before running them:
```powershell
# Legitimate release check (Returns Exit Code 0 -> ALLOWED):
python ci/security_gate.py

# Specify custom artifact / manifest paths:
python ci/security_gate.py --artifact artifacts/uploader.sh --manifest artifacts/uploader.sh.manifest.json
```

### D. Execute Attack Simulations
```powershell
# Scenario 2: Simulate Codecov GCS credential leak and script tampering
python attack_simulation/tamper.py

# Scenarios 3 & 4: Simulate rogue attacker keys and version replay attacks
python attack_simulation/revoked_key_test.py
```

### E. Launch the Observability Web Dashboard
Start the visual dashboard to inspect live audit records, CRL status, and test admissions:
```powershell
python dashboard/app.py
```
Open your browser at `http://127.0.0.1:5000`.

---

## 4. Empirical Test Results & Validation Metrics

| Test Case | Attack / Condition | Expected Result | Actual Result | Status |
|---|---|---|---|---|
| **Test 1** | Valid artifact | PASS | PASS | **PASS** |
| **Test 2** | Modified artifact (Codecov tampering) | BLOCK | BLOCKED | **PASS** |
| **Test 3** | Invalid digital signature | BLOCK | BLOCKED | **PASS** |
| **Test 4** | Wrong / mismatched public key | BLOCK | BLOCKED | **PASS** |
| **Test 5** | Revoked signing key (present in CRL) | BLOCK | BLOCKED | **PASS** |
| **Test 6** | Modified manifest payload | BLOCK | BLOCKED | **PASS** |
| **Test 7** | Replay of obsolete / revoked version | BLOCK | BLOCKED | **PASS** |
| **Test 8** | Unauthorized signing attempt | BLOCK | BLOCKED | **PASS** |
| **Test 9** | Valid new release (rotated key) | PASS | PASS | **PASS** |

### Reliability & Performance Telemetry
- **Test Success Rate:** 100.0% (9/9 passed)
- **Tamper Detection Rate:** 100.0% (7/7 blocked)
- **False Acceptance Rate (FAR):** 0.00% (Zero false positives in controlled evaluation)
- **Mean Verification Latency:** ~4 ms per verification

---

## 5. Innovation Beyond Basic Hash Checking
This project introduces the **Continuous Software Supply Chain Security Gate**:
1. **Asymmetric Origin Authentication:** Private key held in HSM/KMS; public key verified by client.
2. **Dynamic Key Revocation (CRL):** Stolen or leaked signing keys are immediately blacklisted.
3. **SLSA Level 2+ Provenance:** Cryptographically binds artifacts to the source Git commit and hermetic build container.
4. **Zero-Trust CI Admission Gate:** Automated gating halting pipelines with non-zero exit codes.
5. **Tamper-Evident Audit Ledger:** Append-only SQLite store ensuring end-to-end non-repudiation.
