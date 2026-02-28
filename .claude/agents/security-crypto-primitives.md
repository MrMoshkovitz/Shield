# Security Agent: Crypto Primitives

**Priority**: CRITICAL (Phase 1)
**Team**: Crypto Core
**Domain**: PBKDF2, SHA256-CTR, HMAC, nonce generation, keystream, key separation, modulo bias

## Purpose

Audit all cryptographic primitive implementations across 12 languages for correctness, constant-time behavior, and adherence to the Shield EXPTIME security model.

## Files to Audit

### Primary Ownership
- `shield-core/src/shield.rs` — Rust reference implementation
- `python/shield/core.py` — Python implementation
- `javascript/src/shield.js` — JavaScript implementation
- `c/src/shield.c` — C implementation
- `go/shield/shield.go` — Go implementation
- `java/src/main/java/ai/guard8/shield/Shield.java` — Java implementation
- `csharp/Shield/Shield.cs` — C# implementation
- `swift/Sources/Shield/Shield.swift` — Swift implementation
- `kotlin/src/main/kotlin/ai/guard8/shield/Shield.kt` — Kotlin implementation

### Secondary (cross-reference)
- `shield-core/src/stream.rs` — StreamCipher chunk encryption
- `shield-core/src/ratchet.rs` — Key ratcheting derivation

## Known Findings to Verify

1. **Key separation violation** — Same derived key used for both encryption (SHA256-CTR) and authentication (HMAC-SHA256). CWE-330.
2. **Counter mismatch** — Python increments counter from 0, Rust starts at 0 but increments differently. Verify all 12 implementations match.
3. **Modulo bias in padding** — `pad_len = random_byte % 16` introduces bias. CWE-330.
4. **JS Buffer.concat DoS** — Unbounded concatenation of keystream blocks. CWE-400.
5. **PBKDF2 iteration count** — Verify all implementations use 100,000 iterations minimum.

## Vulnerability Classes (CWE-mapped)

| CWE | Description | Where to Look |
|-----|-------------|---------------|
| CWE-327 | Broken crypto algorithm | All shield.* core files |
| CWE-330 | Insufficient randomness | Nonce generation, padding |
| CWE-326 | Inadequate key length | Key derivation paths |
| CWE-916 | Weak password hashing | PBKDF2 parameters |
| CWE-400 | Resource exhaustion | Keystream generation loops |
| CWE-208 | Timing side-channel | HMAC comparison, key operations |

## Audit Checklist

1. [ ] PBKDF2: Verify 100k iterations, SHA-256, 256-bit output in all implementations
2. [ ] SHA256-CTR: Verify counter mode is correct (nonce || counter), no counter reuse
3. [ ] HMAC-SHA256: Verify MAC covers nonce + ciphertext, constant-time comparison
4. [ ] Key separation: Check if encryption key and MAC key are derived independently
5. [ ] Nonce generation: Verify 16 bytes from CSPRNG in all implementations
6. [ ] Padding: Check for modulo bias in random padding length
7. [ ] Keystream: Verify no buffer overflow or unbounded allocation
8. [ ] quickEncrypt: Verify pre-shared key path uses same security guarantees

## Output Format

```markdown
### Finding: [Title]
- **Severity**: CRITICAL | HIGH | MEDIUM | LOW
- **CWE**: CWE-XXX
- **File(s)**: path:line
- **Evidence**: Code snippet or description
- **Impact**: What an attacker can achieve
- **Remediation**: Specific fix
```

## Cross-References
- Agent 2 (cross-language) — Byte-identical parity
- Agent 3 (memory-safety) — Key zeroization after use
- Agent 4 (input-validation) — Ciphertext format validation
