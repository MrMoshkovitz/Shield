---
name: skill-pbkdf2-param-auditor
description: Audit PBKDF2 parameters (iterations, hash algorithm, output length, salt handling) across all Shield implementations against NIST SP 800-132 requirements. Use when auditing key derivation.
---

# PBKDF2 Parameter Auditor

Verify PBKDF2 key derivation parameters meet NIST SP 800-132 across all implementations.

## When to Use
- Auditing key derivation security
- Verifying cross-language parameter consistency
- Checking compliance with NIST standards

## Inputs
- Target language(s) or "all"

## Procedure
1. Use skill-multi-lang-symbol-scanner to find PBKDF2 calls across all 12 languages
2. For each implementation, extract and verify:

### Required Parameters (NIST SP 800-132)
| Parameter | Shield Spec | NIST Minimum | Check |
|-----------|------------|--------------|-------|
| Hash | SHA-256 | SHA-256+ | Must be SHA-256 |
| Iterations | 100,000 | 10,000 (2023: 600,000 recommended) | Must be >=100,000 |
| Output length | 256 bits (32 bytes) | >= hash output | Must be 32 bytes |
| Salt length | 16 bytes | >= 16 bytes | Must be >=16 bytes |
| Salt source | CSPRNG | CSPRNG | Must use secure random |

3. Check for these issues:
   - Hardcoded or zero salt
   - Iteration count as user-controllable parameter without minimum
   - Output length mismatch (some langs may use 64 bytes and split)
   - Salt reuse across different passwords
   - Missing salt uniqueness per encryption operation

4. Verify the derived key is split correctly (if applicable):
   - First 32 bytes -> encryption key
   - Separate HMAC key derivation (should NOT reuse same derived bytes)

5. Compare all implementations for parameter parity

## Output Format
```
### PBKDF2 Parameter Audit
| Language | Hash | Iterations | Output | Salt Len | Salt Source | Issues |
|----------|------|-----------|--------|----------|-------------|--------|
| Rust | SHA-256 | 100,000 | 32B | 16B | OsRng | None |
| Python | SHA-256 | 100,000 | 32B | 16B | os.urandom | None |
...

**Compliance**: X/12 fully compliant
**Issues Found**: [list]
```

## Used By
- A1 (Crypto Primitives), A2 (Cross-Language), T8 (Cross-Lang Interop)
