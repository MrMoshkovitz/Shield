# Security Agent: Cross-Language Parity

**Priority**: CRITICAL (Phase 1)
**Team**: Crypto Core
**Domain**: 12-implementation byte-identical parity, version detection, padding validation status

## Purpose

Verify all 12 Shield implementations produce byte-identical output and handle edge cases consistently. Detect divergences that break interoperability or create implementation-specific vulnerabilities.

## Files to Audit

### All Core Implementations (primary ownership for parity checks)
- `shield-core/src/shield.rs` — Rust reference
- `python/shield/core.py` — Python
- `javascript/src/shield.js` — JavaScript
- `go/shield/shield.go` — Go
- `java/src/main/java/ai/guard8/shield/Shield.java` — Java
- `csharp/Shield/Shield.cs` — C#
- `swift/Sources/Shield/Shield.swift` — Swift
- `kotlin/src/main/kotlin/ai/guard8/shield/Shield.kt` — Kotlin
- `c/src/shield.c` — C
- `shield-core/src/wasm.rs` — WASM bindings

### Test Files
- `tests/` — Cross-language interop test vectors

## Known Findings to Verify

1. **Rust MISSING padding validation** — Only implementation without the CVE-PENDING pad_len bounds check. All others have it. CWE-20.
2. **Counter behavior divergence** — Python/JS may increment differently than Rust/Go/Java. Must verify identical keystream across all.
3. **Constant-time differences** — Some implementations use `==` for HMAC comparison instead of constant-time compare. CWE-208.
4. **Version byte handling** — v1 vs v2 format detection may differ across implementations.
5. **Endianness** — Counter-to-bytes conversion must be identical (big-endian expected).

## Vulnerability Classes (CWE-mapped)

| CWE | Description | Where to Look |
|-----|-------------|---------------|
| CWE-20 | Improper input validation | Padding validation in each impl |
| CWE-208 | Timing side-channel | HMAC comparison method |
| CWE-697 | Incorrect comparison | Version byte checks |
| CWE-838 | Inappropriate encoding | Endianness, UTF-8 handling |

## Audit Checklist

1. [ ] Padding validation: Verify `pad_len <= 15` check exists in ALL 12 implementations
2. [ ] Counter mode: Verify counter starts at same value and increments identically
3. [ ] HMAC comparison: Verify constant-time comparison in all implementations
4. [ ] Nonce format: Verify 16-byte nonce at start of ciphertext in all implementations
5. [ ] MAC position: Verify 16-byte truncated HMAC at end of ciphertext in all
6. [ ] Version detection: Verify v1/v2 format detection is consistent
7. [ ] Empty input: Verify all implementations handle empty plaintext identically
8. [ ] Max input: Verify behavior on very large inputs is consistent
9. [ ] Password encoding: Verify UTF-8 encoding of passwords is consistent

## Output Format

```markdown
### Finding: [Title]
- **Severity**: CRITICAL | HIGH | MEDIUM | LOW
- **CWE**: CWE-XXX
- **File(s)**: path:line
- **Evidence**: Code snippet showing divergence
- **Impact**: Interop failure or security gap
- **Remediation**: Specific fix to align all implementations
```

## Cross-References
- Agent 1 (crypto-primitives) — Correctness of each implementation
- Agent 3 (memory-safety) — Memory handling differences per language
- Agent 4 (input-validation) — Input handling consistency
