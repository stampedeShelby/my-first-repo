# Security Architecture & Data Flow Specification
## Cryptographically Verified Software Supply Chain

### 1. High-Level Architecture Diagram

```mermaid
flowchart TD
    subgraph VENDOR ["Vendor Secure Environment"]
        DEV["Developer"] -->|Git Commit & Push| REPO["Source Repository (GitHub)"]
        REPO -->|Trigger Pipeline| BUILD["Secure CI/CD Build Enclave"]
        BUILD -->|Execute Security Unit Tests| TESTS["Security Testing & SAST"]
        TESTS -->|Deterministic Compilation| HASH["Compute SHA-256 Digest"]
        TESTS -->|Record Metadata| PROV["Generate SLSA Provenance"]
        HASH & PROV --> SIGN["Secure Signing Service"]
        KMS["HSM / Cloud KMS Enclave\n(Private Ed25519 Key)"] -->|Sign Canonical Manifest| SIGN
        SIGN --> MANIFEST["Signed Release Manifest\n(uploader.sh.manifest.json)"]
    end

    subgraph PUBLIC ["Untrusted Distribution Tier"]
        MANIFEST & BUILD --> REGISTRY["Artifact Registry / Storage Bucket\n(GCS / CDN / S3)"]
        REGISTRY -->|TLS 1.3 Distribution| TRANSIT["Transit Network (Untrusted Channel)"]
    end

    subgraph CUSTOMER ["Customer CI/CD Environment (Zero-Trust Gate)"]
        TRANSIT --> GATE["CI/CD Security Gate (security_gate.py)"]
        CRL["Key Revocation List (CRL)\n& Trust Store"] --> ENGINE["Verification Engine"]
        GATE --> ENGINE

        subgraph CHECKS ["Cryptographic Verification Engine"]
            direction TB
            C1["1. Schema & Syntax Check"]
            C2["2. Key Revocation (CRL) Check"]
            C3["3. Security Policy Evaluation"]
            C4["4. Ed25519 Signature Verification"]
            C5["5. Recalculate SHA-256 Digest"]
            C6["6. SLSA Provenance Integrity Check"]
            C1 --> C2 --> C3 --> C4 --> C5 --> C6
        end

        ENGINE --> DECISION{"Gate Verdict?"}
        DECISION -->|All Checks PASS| DEPLOY["DEPLOY / EXECUTE\n(Exit 0)"]
        DECISION -->|Any Check Fails| BLOCK["BLOCK & ALERT\n(Exit 1)"]

        DEPLOY & BLOCK --> AUDIT[("Tamper-Evident Audit Log\n(supply_chain_audit.db)")]
    end
```

---

### 2. Key Management Architecture (HSM / KMS Concept)

```mermaid
sequenceDiagram
    autonumber
    participant Dev as Vendor Engineer
    participant SignService as Secure Signing Service
    participant HSM as HSM / Cloud KMS (Enclave)
    participant CRL as Public CRL / Status Service
    participant Cust as Customer CI/CD Verifier

    Note over Dev,HSM: Key Generation & Protection Phase
    SignService->>HSM: Request Ed25519 Keypair Generation
    HSM-->>HSM: Generate Keypair inside Tamper-Proof Hardware
    HSM-->>SignService: Export Public Key (SubjectPublicKeyInfo)
    Note over HSM: Private Key NEVER leaves HSM boundary

    Note over SignService,CRL: Release Signing Phase
    SignService->>HSM: Submit Canonical Manifest Digest for Signing
    HSM-->>SignService: Return Ed25519 Raw Signature
    SignService->>Cust: Publish Artifact + Signed Manifest + Public Key

    Note over Cust,CRL: Verification & Revocation Phase
    Cust->>CRL: Query Key ID Revocation Status
    CRL-->>Cust: Return Revocation Status (Active / Revoked)
    Cust->>Cust: Verify Ed25519 Signature using Trusted Public Key
    Cust->>Cust: Recalculate SHA-256 & Compare against Manifest
```

---

### 3. Component Responsibilities

1. **Vendor Build Engine (`vendor/build.py`)**:
   - Compiles or packages software artifacts deterministically.
   - Computes canonical SHA-256 hash across raw artifact bytes.
   - Generates structured SLSA Level 2+ provenance documentation linking commit hash, build worker identity, build timestamp, and dependency hashes.

2. **Vendor Key Manager (`vendor/key_manager.py`)**:
   - Manages Ed25519 elliptic curve key pairs.
   - Enforces key encapsulation and PKCS#8 encrypted serialization.
   - Issues and manages the Key Revocation List (CRL) for instant emergency revocation.
   - Coordinates cryptographic key rotation.

3. **Vendor Signing Engine (`vendor/sign.py`)**:
   - Converts release manifests into deterministic RFC 8785 canonical JSON bytes.
   - Validates that signing keys are in active (non-revoked) status before signing.
   - Signs the canonical payload using Ed25519 private key.
   - Emits signed release bundles and records operations to the audit database.

4. **Customer Admission Policy (`verifier/policy.py`)**:
   - Implements zero-trust security constraints.
   - Pins allowed signers, trusted key IDs, and authorized source code repositories.
   - Enforces version monotonicity and rejects deprecated or vulnerable releases.

5. **Customer Verification Engine (`verifier/verify.py`)**:
   - Parses and validates signed manifests against schema.
   - Queries CRL to verify signing key validity.
   - Verifies Ed25519 asymmetric signature using vendor's public key.
   - Recalculates SHA-256 digest on local download and asserts byte-level equivalence.
   - Verifies build provenance metadata.

6. **CI/CD Security Gate (`ci/security_gate.py`)**:
   - Plugs directly into customer pipelines (e.g. Jenkins, GitHub Actions, GitLab CI).
   - Serves as the binary decision enforcement point: returns `0` (allow) or `1` (abort).

7. **Tamper-Evident Audit Logger (`audit/audit_logger.py`)**:
   - Records all signing, verification, pass, and block events in SQLite.
   - Captures timestamp, artifact, version, sha256, key_id, verification_result, process, action, rejection_reason.

8. **Web Observability Dashboard (`dashboard/app.py`)**:
   - Provides real-time visibility into pipeline security telemetry, blocked attacks, and CRL status.
