# Presentation Deck (5–7 Minute Defense / Viva)
## Cryptographically Verified Software Supply Chain for Preventing Codecov-Style Supply Chain Attacks

---

### Slide 1: Title & Overview
- **Project Title:** Cryptographically Verified Software Supply Chain for Preventing Codecov-Style Supply Chain Attacks
- **Course / Assessment:** Information & Network Security (INS) — Design & Implementation
- **Role:** Senior Cybersecurity Engineer & Software Supply Chain Security Architect
- **Core Objective:** Design, build, and evaluate an automated zero-trust verification gate that detects and blocks tampered vendor software before execution.
- *Speaker Note:* "Good morning/afternoon. Today I present a cryptographically verified software supply chain engineered to eliminate the systemic vulnerability exploited in the infamous 2021 Codecov breach."

---

### Slide 2: The 2021 Codecov Incident
- **Event:** In April 2021, an attacker compromised Codecov’s Docker image extraction pipeline, stealing an HMAC key to a Google Cloud Storage (GCS) bucket.
- **Payload:** The attacker injected a single line into the widely used `uploader.sh` bash script.
- **Impact:** Millions of automated CI builds executed `curl -s https://codecov.io/bash | bash`, exfiltrating sensitive CI secrets, cloud access tokens, and private git repositories.
- **Detection Lag:** Undetected for over two months until a diligent customer manually compared SHA-256 hashes.
- *Speaker Note:* "Codecov was a wake-up call for the software industry: transport security does not equal artifact trust."

---

### Slide 3: Attack Flow vs. Proposed Flow
```
[Original Codecov Attack Flow]
Attacker steals GCS Key -> Injects Exfil Code -> Hosted on HTTPS Bucket -> Customer runs curl | bash -> CREDENTIALS STOLEN

[Our Cryptographically Verified Flow]
Developer -> Secure Build (SHA-256) -> Sign Manifest (Ed25519) -> Public Bucket
          -> Customer Zero-Trust CI Gate -> Recompute SHA-256 + Verify Ed25519 + CRL
          -> Tampering Detected -> PIPELINE BLOCKED (Exit 1)
```
- *Speaker Note:* "Even if an attacker gains full write access to the storage bucket, they cannot forge the vendor's private cryptographic signature."

---

### Slide 4: Root Vulnerability & Security Requirements
- **Root Flaw:** Conflating transport channel security (TLS 1.3) with payload authenticity and integrity.
- **Security Requirements:**
  1. *Deterministic Integrity:* Cryptographic SHA-256 fingerprinting.
  2. *Asymmetric Authenticity:* Ed25519 digital signatures.
  3. *Zero-Trust Storage:* Assume all public storage buckets and CDNs are untrusted.
  4. *Dynamic Revocation:* Instant invalidation via Key Revocation Lists (CRL).
  5. *Automated CI Gating:* Zero human intervention; non-zero exit code halts malicious runs.

---

### Slide 5: Proposed Security Architecture
- **Vendor Secure Build Enclave:** Generates artifact, deterministic SHA-256 digest, and SLSA Level 2+ provenance.
- **Signing Service (HSM/KMS Concept):** Signs canonical manifest using Ed25519 private key.
- **Customer CI/CD Admission Gate:** Executes 6 sequential verification steps before giving script execution permission.
- **Tamper-Evident Audit Database:** Records immutable verification telemetry in SQLite.

---

### Slide 6: Cryptographic Design
- **SHA-256 (FIPS 180-4):** Provides artifact integrity/fingerprinting. Second pre-image resistant.
  - *Distinction:* Hashing alone does NOT provide authenticity.
- **Ed25519 (RFC 8032):** High-speed, high-security Edwards-curve digital signature algorithm.
  - Private key resides strictly within vendor signing infrastructure / HSM.
  - Public key distributed to customers for local verification.
- **Canonical Serialization (RFC 8785):** Guarantees byte-level JSON determinism before signing.

---

### Slide 7: Key Management Lifecycle
- **Key Generation & Storage:** Asymmetric keypairs stored in PKCS#8 encrypted formats (local) / Cloud KMS & HSM (enterprise).
- **Public Key Distribution:** PEM / SubjectPublicKeyInfo export with SHA-256 fingerprinting.
- **Key Rotation:** Automated retirement of older keys with new key enrollment.
- **Emergency Revocation (CRL):** Centralized CRL ensures compromised keys are instantly blacklisted across customer CI/CD gates.

---

### Slide 8: Live Attack Simulation
- **Scenario 1 (Legitimate):** Untampered `uploader.sh` -> Signature & Hash PASS -> Pipeline ALLOWED.
- **Scenario 2 (Codecov Tampering):** Injected exfiltration payload -> SHA-256 Mismatch -> Pipeline BLOCKED.
- **Scenario 3 (Rogue Key):** Attacker signs with self-generated key -> Policy Rejection -> Pipeline BLOCKED.
- **Scenario 4 (Version Replay):** Attempt to deploy deprecated/vulnerable release -> Policy Rejection -> Pipeline BLOCKED.

---

### Slide 9: Empirical Validation & Testing Results
- **Automated Test Cases:** 9 distinct supply chain attack/boundary tests executed.
- **Success Rate:** 100.0% (9/9 passed).
- **Tamper Detection Rate:** 100.0% (7/7 blocked).
- **False Acceptance Rate (FAR):** 0.00% (Target: 0.00%).
- **Mean Verification Latency:** ~3.96 ms (negligible runtime overhead in CI).

---

### Slide 10: Innovation & Industry Relevance
- **Beyond Basic Hash Checking:**
  - Standard checksums fail if the hash file on the server is overwritten.
  - Our system couples asymmetric digital signatures, dynamic CRL revocation, and SLSA Level 2+ provenance.
- **Industry Alignment:** Directly implements principles from **Sigstore (Cosign)**, **SLSA framework**, and **TUF (The Update Framework)**.

---

### Slide 11: Conclusion
- **Key Takeaway:** The "curl pipe bash" antipattern is safely rehabilitated when guarded by an automated cryptographic admission gate.
- **Final Result:**
  $$\text{Legitimate Software} \longrightarrow \text{Verified} \longrightarrow \text{Deployed}$$
  $$\text{Tampered Software} \longrightarrow \text{Detected} \longrightarrow \text{Blocked}$$

---

### Slide 12: References & Standards
1. Codecov Security Incident Bash Uploader Disclosure (Official Codecov Post-Mortem, 2021).
2. Bernstein, D. J., et al. "High-speed high-security signatures." *Journal of Cryptographic Engineering* (2012) — RFC 8032 (Ed25519).
3. NIST FIPS PUB 180-4: "Secure Hash Standard (SHS)" (SHA-256).
4. RFC 8785: "JSON Canonicalization Scheme (JCS)".
5. OpenSSF SLSA: Supply-chain Levels for Software Artifacts (v1.0 Specification).
6. Linux Foundation / Sigstore: "Cosign: Container Signing, Verification and Storage in an OCI Registry".
