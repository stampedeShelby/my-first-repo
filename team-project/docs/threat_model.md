# Threat Model (STRIDE Framework)
## Project: Cryptographically Verified Software Supply Chain

This threat model rigorously evaluates the software supply chain attack surface using the Microsoft STRIDE methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) with specific focus on mitigating attacks modeled after the 2021 Codecov Bash Uploader breach.

---

### Threat Analysis Matrix (STRIDE)

| # | Asset | Threat Category (STRIDE) | Specific Attack Vector | Vulnerability Exploited | Applied Security Control | Expected System Result |
|---|---|---|---|---|---|---|
| **1** | **Software Artifact** (`uploader.sh`) | **Tampering** | Attacker modifies distribution script on GCS/CDN to inject credential-harvesting code. | Implicit trust in downloaded binaries; lack of pre-execution cryptographic verification. | Pre-execution SHA-256 digest recalculation & comparison against signed manifest. | **BLOCKED** (`HASH_MISMATCH`): Script is prohibited from executing; alert dispatched. |
| **2** | **Build Pipeline** | **Tampering / Elevation of Privilege** | Attacker breaches build cluster runner to inject malware before packaging. | Build runner lacking ephemeral isolation or build-step integrity checks. | Hermetic, reproducible builds & SLSA Level 2+ provenance assertions with signed commit hashes. | **BLOCKED** (`PROVENANCE_FAILED`): Discrepancy between source Git commit and build outputs. |
| **3** | **Artifact Repository** (Storage Bucket) | **Tampering** | Attacker obtains GCS HMAC access key and overwrites release files in place. | Static credentials with write permissions to public object storage buckets. | End-to-end asymmetric Ed25519 digital signatures decoupling bucket trust from artifact trust. | **BLOCKED** (`HASH_MISMATCH` / `INVALID_SIGNATURE`): Overwritten objects cannot forge signature. |
| **4** | **Private Signing Key** | **Elevation of Privilege / Spoofing** | Exfiltration or leak of vendor private signing key material. | Insecure local file storage or shared access credentials. | Hardware Security Module (HSM) / Cloud KMS enclave + Key Revocation List (CRL) invalidation. | **BLOCKED** (`REVOKED`): Compromised key is added to CRL; verifier rejects all signatures from it. |
| **5** | **Signer Identity** | **Spoofing** | Attacker signs malicious binary using their own rogue key pair. | Verifiers blindly trusting any signed payload without verifying public key trust roots. | Pinned Key IDs, Public Key Trust Stores, and strict Signer Admission Policy. | **BLOCKED** (`UNAUTHORIZED_KEY`): Rogue key ID is not recognized in customer trust store. |
| **6** | **Distribution Channel** (Network) | **Information Disclosure / Tampering** | Man-in-the-Middle (MitM) injection or proxy interception during download. | Plaintext HTTP transit or untrusted proxy gateways. | Mandatory TLS 1.3 cryptographic transit encryption combined with Ed25519 signature checks. | **BLOCKED** (`INVALID_SIGNATURE` / TLS Alert): Network alteration corrupts TLS or signature envelope. |
| **7** | **Legacy Release Artifact** | **Replay / Tampering** | Attacker forces customer CI/CD to download an older, vulnerable software version. | Downgrade attack exploiting missing minimum version checks. | Monotonic version threshold policy (`min_allowed_version`) & blacklisted version CRL. | **BLOCKED** (`VERSION_REPLAY_BLOCKED`): Policy engine halts pipeline on obsolete versions. |
| **8** | **Release Manifest** (`manifest.json`) | **Tampering** | Attacker alters SHA-256 hash inside manifest to match tampered software artifact. | Manifest integrity unverified or stored in cleartext without cryptographic seal. | Ed25519 signature computed over canonical JSON serialization (RFC 8785) of manifest. | **BLOCKED** (`INVALID_SIGNATURE`): Modifying a single character in manifest breaks digital signature. |
| **9** | **CI/CD Deployment Gate** | **Repudiation / Elevation of Privilege** | Attacker claims unauthorized software was legitimately deployed, or hides breach traces. | Absence of tamper-evident centralized audit logging. | Immutable SQLite / Transparency log recording all verifications, digests, timestamps, and verdicts. | **LOGGED & MONITORED**: Non-repudiable audit entry created with exact timestamps and process IDs. |

---

### Trust Boundary Analysis
1. **Developer / Source Trust Boundary**: Git repository with commit signing.
2. **Build / Vendor Trust Boundary**: Isolated build worker producing artifact + SLSA provenance; secure signing service with HSM/KMS-protected Ed25519 private key.
3. **Untrusted Distribution Zone**: Public CDN, GCS bucket, transit networks. (Zero trust placed in this zone).
4. **Customer CI/CD Trust Boundary**: Zero-trust admission gate verifying public keys, CRLs, signatures, hashes, and provenance before handing execution to the environment.
