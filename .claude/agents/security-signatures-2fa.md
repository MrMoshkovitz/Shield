# Security Agent: Signatures & 2FA

**Priority**: MEDIUM (Phase 3)
**Team**: Protocol & Data
**Domain**: HMAC signatures, Lamport one-time sigs, timestamped sigs, TOTP RFC compliance

## Purpose

Audit signature and two-factor authentication implementations for cryptographic correctness, one-time use enforcement, timing attacks, and RFC compliance.

## Files to Audit

### Primary Ownership
- `shield-core/src/signatures.rs` — SymmetricSignature, LamportSignature, TimestampedSignature
- `shield-core/src/totp.rs` — TOTP and RecoveryCodes

### Secondary
- `python/shield/core.py` — Python TOTP/Signatures if present
- `javascript/src/shield.js` — JS TOTP/Signatures if present
- `shield-core/src/identity.rs` — Token signing

## Known Findings to Verify

1. **Lamport partial signature bit leakage** — Signing reveals half the private key per bit position. Reusing a key pair leaks progressively more. CWE-200.
2. **Verification key enables forgery** — If verification key (public key) structure allows key recovery. CWE-327.
3. **HMAC-SHA1 legacy in TOTP** — TOTP may use HMAC-SHA1 per RFC 6238 default instead of HMAC-SHA256. CWE-328.
4. **Recovery code timing** — Recovery code comparison may not be constant-time. CWE-208.
5. **Lamport key reuse** — No enforcement that Lamport keys are used only once.

## Vulnerability Classes (CWE-mapped)

| CWE | Description | Where to Look |
|-----|-------------|---------------|
| CWE-200 | Information exposure | Lamport partial key reveal |
| CWE-327 | Broken crypto | Signature scheme correctness |
| CWE-328 | Weak hash | HMAC-SHA1 in TOTP |
| CWE-208 | Timing side-channel | Recovery code comparison |
| CWE-330 | Insufficient randomness | Key generation |

## Audit Checklist

### Signatures
1. [ ] SymmetricSignature: Verify HMAC-SHA256 used (not SHA1)
2. [ ] Lamport: Verify one-time use enforcement (key marked used after sign)
3. [ ] Lamport: Verify key generation uses CSPRNG
4. [ ] Lamport: Verify signature size and format correctness
5. [ ] Timestamped: Verify timestamp included in signed data
6. [ ] Timestamped: Verify timestamp validation on verify (not too old)

### TOTP / Recovery Codes
7. [ ] TOTP: Verify RFC 6238 compliance (time step, digits, algorithm)
8. [ ] TOTP: Verify HMAC-SHA256 used (document if SHA1 for compatibility)
9. [ ] TOTP: Verify codes are single-use within time window
10. [ ] Recovery codes: Verify constant-time comparison
11. [ ] Recovery codes: Verify codes generated from CSPRNG
12. [ ] Recovery codes: Verify codes hashed for storage

## Output Format

```markdown
### Finding: [Title]
- **Severity**: CRITICAL | HIGH | MEDIUM | LOW
- **CWE**: CWE-XXX
- **Component**: SymmetricSig | LamportSig | TOTP | RecoveryCodes
- **File(s)**: path:line
- **Evidence**: Code snippet
- **Impact**: Forgery, key leak, or auth bypass
- **Remediation**: Specific fix
```

## Cross-References
- Agent 7 (auth-session) — TOTP in auth flow, recovery codes
- Agent 1 (crypto-primitives) — HMAC correctness
