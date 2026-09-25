| Test Case | Attack / Condition | Expected Result | Actual Result | Status |
|---|---|---|---|---|
| TC01 | Valid signed artifact | PASS / DEPLOY | PASS / DEPLOY | PASS |
| TC02 | One malicious line added (Codecov-style) | BLOCK - HASH_MISMATCH | BLOCK - HASH_MISMATCH | PASS |
| TC02b | Single bit flipped in artifact | BLOCK - HASH_MISMATCH | BLOCK - HASH_MISMATCH | PASS |
| TC03 | Corrupted manifest signature | BLOCK - INVALID_SIGNATURE | BLOCK - INVALID_SIGNATURE | PASS |
| TC03b | Attacker claims vendor key ID | BLOCK - INVALID_SIGNATURE | BLOCK - INVALID_SIGNATURE | PASS |
| TC04 | Wrong pinned public (root) key | BLOCK - INVALID_TRUST_POLICY | BLOCK - INVALID_TRUST_POLICY | PASS |
| TC04b | Signed with attacker's own key | BLOCK - UNAUTHORIZED_KEY | BLOCK - UNAUTHORIZED_KEY | PASS |
| TC05 | Signing key revoked | BLOCK - REVOKED | BLOCK - REVOKED | PASS |
| TC05b | Stolen key signs payload | BLOCK - POLICY_VIOLATION, then REVOKED | BLOCK - POLICY_VIOLATION, then REVOKED | PASS |
| TC06 | Manifest SHA-256 replaced | BLOCK - INVALID_SIGNATURE | BLOCK - INVALID_SIGNATURE | PASS |
| TC06b | Manifest field removed | BLOCK - INVALID_MANIFEST | BLOCK - INVALID_MANIFEST | PASS |
| TC06c | Provenance builder changed | BLOCK - INVALID_SIGNATURE + INVALID_PROVENANCE | BLOCK - INVALID_SIGNATURE + INVALID_PROVENANCE | PASS |
| TC07 | Replay of older version (rollback) | BLOCK - REPLAY_BLOCKED | BLOCK - REPLAY_BLOCKED | PASS |
| TC07b | Revoked / below-minimum version | BLOCK - REVOKED / REPLAY_BLOCKED | BLOCK - REVOKED / REPLAY_BLOCKED | PASS |
| TC07c | Old trust policy replayed | BLOCK - INVALID_TRUST_POLICY | BLOCK - INVALID_TRUST_POLICY | PASS |
| TC07d | Trust policy edited on registry | BLOCK - INVALID_TRUST_POLICY | BLOCK - INVALID_TRUST_POLICY | PASS |
| TC08 | Wrong role / bad MFA / unknown user signs | DENIED - UNAUTHORIZED_SIGNER | DENIED - UNAUTHORIZED_SIGNER | PASS |
| TC08b | Exfiltration code in source | BUILD STOPPED | BUILD STOPPED | PASS |
| TC09 | New release after key rotation | PASS / DEPLOY | PASS / DEPLOY | PASS |
| TC10 | Audit log row edited | Chain BROKEN detected | Chain BROKEN detected | PASS |
| TC11 | Key file encrypted, 0600, wrong passphrase | Protected | Protected | PASS |
| TC12 | TLS 1.2 downgrade attempt | TLS 1.3 only | TLS 1.3 only | PASS |
| TC13 | Tampered file served over valid TLS | BLOCK - HASH_MISMATCH | BLOCK - HASH_MISMATCH | PASS |
| TC14 | End-to-end pipeline, legit release | DEPLOY | DEPLOY | PASS |
| TC15 | 200 random mutations | 0 accepted (FAR = 0) | 0 accepted (FAR = 0) | PASS |
