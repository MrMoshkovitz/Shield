---
name: skill-tee-attestation-auditor
description: Audit TEE attestation implementations for freshness, certificate chain validation, measurement pinning, and policy enforcement. Use when auditing confidential computing.
---

# TEE Attestation Auditor

Audit Trusted Execution Environment attestation across AWS Nitro, GCP SEV, Azure MAA, and Intel SGX.

## When to Use
- Auditing confidential computing attestation
- Checking TEE provider implementations
- Reviewing attestation policy enforcement

## Inputs
- TEE provider(s): "nitro" | "sev" | "maa" | "sgx" | "all"
- Source: Rust (`shield-core/src/confidential/`) and/or Python (`python/shield/integrations/confidential/`)

## Procedure
1. Locate attestation files per provider (see skill-shield-file-navigator)
2. Audit common attestation checks:

### Universal Checks
| Check | What to Verify | Risk if Missing |
|-------|---------------|----------------|
| Freshness/nonce | Attestation includes caller nonce | Critical (replay) |
| Certificate chain | Full chain validated to root | Critical (forgery) |
| Expiry check | Certs checked for expiration | High |
| Revocation check | CRL or OCSP verified | High |
| Measurement pinning | Expected PCR/MRENCLAVE values hardcoded or configurable | Critical |

### Provider-Specific Checks

#### AWS Nitro Enclaves
| Check | Pattern | Risk |
|-------|---------|------|
| COSE signature | Verify COSE_Sign1 structure | Critical |
| PCR values | PCR0-3 validated against expected | Critical |
| NSM module | Using `/dev/nsm` interface | Required |
| Document parsing | CBOR attestation document parsed | Required |

#### GCP SEV-SNP
| Check | Pattern | Risk |
|-------|---------|------|
| vTPM attestation | TPM2 quote verification | Critical |
| SNP report | AMD SEV-SNP attestation report | Critical |
| Measurement | Launch measurement validated | Critical |
| Guest policy | Minimum firmware version enforced | High |

#### Azure MAA
| Check | Pattern | Risk |
|-------|---------|------|
| MAA endpoint | Using regional MAA service | Required |
| JWT validation | MAA token signature verified | Critical |
| Secure Key Release | SKR policy enforced | Critical |
| TEE type claim | `x-ms-attestation-type` checked | High |

#### Intel SGX
| Check | Pattern | Risk |
|-------|---------|------|
| DCAP quote | Quote v3 structure validated | Critical |
| MRENCLAVE | Enclave measurement pinned | Critical |
| MRSIGNER | Signer identity verified | High |
| ISV SVN | Minimum security version enforced | High |
| Sealed storage | Seal key bound to enclave identity | Required |

3. Check policy enforcement:
   - Are attestation results cached? (staleness risk)
   - Is attestation required before key release?
   - Are failed attestations properly rejected?

## Output Format
```
### TEE Attestation Audit: [provider]
| # | File:Line | Check | Status | Risk |
|---|-----------|-------|--------|------|
| 1 | nitro.rs:42 | Nonce freshness | PASS | - |
...

**Summary**: X/Y checks passed per provider
```

## Used By
- A13 (Confidential TEE)
- T09 (Key Lifecycle)
