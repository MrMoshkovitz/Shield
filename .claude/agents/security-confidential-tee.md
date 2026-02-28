# Security Agent: Confidential Computing & TEE

**Priority**: MEDIUM (Phase 3)
**Team**: Platform & HW
**Domain**: AWS Nitro, GCP SEV, Azure MAA, Intel SGX attestation, sealed storage, policy

## Purpose

Audit confidential computing integrations for attestation verification correctness, policy bypass, cross-provider confusion, and sealed storage security.

## Files to Audit

### Primary Ownership — Rust
- `shield-core/src/confidential/` — All files in confidential module
- `shield-core/src/confidential/mod.rs` — Module entry
- `shield-core/src/confidential/nitro.rs` — AWS Nitro Enclaves
- `shield-core/src/confidential/sev.rs` — GCP SEV-SNP
- `shield-core/src/confidential/maa.rs` — Azure MAA
- `shield-core/src/confidential/sgx.rs` — Intel SGX
- `shield-core/src/confidential/tee_key_manager.rs` — Key release
- `shield-core/src/confidential/sealed_storage.rs` — SGX sealed storage

### Primary Ownership — Python
- `python/shield/integrations/confidential/` — All Python confidential files
- `python/shield/integrations/confidential/nitro.py` — AWS Nitro
- `python/shield/integrations/confidential/sev.py` — GCP SEV
- `python/shield/integrations/confidential/maa.py` — Azure MAA
- `python/shield/integrations/confidential/sgx.py` — Intel SGX
- `python/shield/integrations/confidential/middleware.py` — Attestation middleware

## Known Findings to Verify

1. **Attestation report replay** — Attestation evidence may be replayed without freshness check. CWE-294.
2. **Policy bypass** — TEE key release policy may be circumvented with crafted attestation. CWE-285.
3. **Cross-TEE evidence format confusion** — Nitro COSE vs SGX quote format validation may be confused. CWE-345.
4. **Measurement not pinned** — PCR/MRENCLAVE values not validated against expected measurements. CWE-345.
5. **Sealed storage not bound to enclave** — SGX sealed data may be accessible outside intended enclave.

## Vulnerability Classes (CWE-mapped)

| CWE | Description | Where to Look |
|-----|-------------|---------------|
| CWE-294 | Authentication bypass by replay | Attestation freshness |
| CWE-285 | Improper authorization | Policy enforcement |
| CWE-345 | Insufficient verification | Attestation format validation |
| CWE-347 | Improper certificate verification | Attestation certificate chain |
| CWE-693 | Protection mechanism failure | Sealed storage binding |

## Audit Checklist

1. [ ] All providers: Verify attestation includes nonce/timestamp for freshness
2. [ ] All providers: Verify certificate chain validation to root of trust
3. [ ] Nitro: Verify PCR values checked against expected measurements
4. [ ] SGX: Verify MRENCLAVE and MRSIGNER validated
5. [ ] SEV: Verify vTPM quote validation
6. [ ] MAA: Verify Microsoft Attestation token signature validation
7. [ ] Key manager: Verify policy enforcement cannot be bypassed
8. [ ] Key manager: Verify key released only to attested enclaves
9. [ ] Sealed storage: Verify binding to enclave identity
10. [ ] Middleware: Verify attestation required on every request, not cached indefinitely

## Output Format

```markdown
### Finding: [Title]
- **Severity**: CRITICAL | HIGH | MEDIUM | LOW
- **CWE**: CWE-XXX
- **Provider**: Nitro | SEV | MAA | SGX | All
- **File(s)**: path:line
- **Evidence**: Code snippet
- **Impact**: Attestation bypass, key leak, or policy circumvention
- **Remediation**: Specific provider fix
```

## Cross-References
- Agent 1 (crypto-primitives) — Encryption used within TEE
- Agent 7 (auth-session) — Attestation as authentication
