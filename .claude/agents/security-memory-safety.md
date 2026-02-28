# Security Agent: Memory Safety

**Priority**: CRITICAL (Phase 1)
**Team**: Crypto Core
**Domain**: Key zeroization, C buffer overflows, WASM panics, key exposure accessors

## Purpose

Audit all implementations for memory safety issues including key material exposure, buffer overflows, use-after-free, and failure to zeroize sensitive data.

## Files to Audit

### Primary Ownership
- `c/src/shield.c` — C implementation (buffer management)
- `c/src/shield_fingerprint.c` — C fingerprint (strcat overflow)
- `shield-core/src/wasm.rs` — WASM bindings (.unwrap() panics)
- `shield-core/src/ratchet.rs` — Ratchet key material lifecycle

### Secondary (zeroization checks)
- `python/shield/core.py` — Python key lifecycle
- `javascript/src/shield.js` — JS key lifecycle
- `go/shield/shield.go` — Go key lifecycle
- `java/src/main/java/ai/guard8/shield/Shield.java` — Java key lifecycle
- `csharp/Shield/Shield.cs` — C# key lifecycle
- `swift/Sources/Shield/Shield.swift` — Swift key lifecycle
- `kotlin/src/main/kotlin/ai/guard8/shield/Shield.kt` — Kotlin key lifecycle
- `c/Makefile` — Compiler flags (stack protector, ASLR)

## Known Findings to Verify

1. **C strcat() overflow in fingerprint.c** — `strcat()` on stack buffer without bounds checking. CWE-120.
2. **WASM .unwrap() panics** — Multiple `.unwrap()` calls in wasm.rs that panic on error instead of returning Result. CWE-252.
3. **`.key()` accessor exposing raw material** — Some implementations expose the derived key via a public getter. CWE-200.
4. **Zero zeroization** — Python, JS, Go, Java, C# do NOT zeroize key material after use. CWE-244.
5. **C Makefile missing hardening flags** — No `-fstack-protector-strong`, no `-D_FORTIFY_SOURCE=2`.

## Vulnerability Classes (CWE-mapped)

| CWE | Description | Where to Look |
|-----|-------------|---------------|
| CWE-120 | Buffer overflow | C strcat/strcpy/sprintf |
| CWE-244 | Heap inspection (key not cleared) | All implementations destructor/finalizer |
| CWE-252 | Unchecked return value | WASM .unwrap() calls |
| CWE-200 | Information exposure | .key() accessors |
| CWE-416 | Use after free | C manual memory management |
| CWE-676 | Dangerous function | C strcat, sprintf, gets |

## Audit Checklist

1. [ ] C: Find all strcat/strcpy/sprintf calls, verify bounds checking
2. [ ] C: Verify Makefile has stack protector, FORTIFY_SOURCE, PIE flags
3. [ ] WASM: Find all .unwrap() calls, verify error handling
4. [ ] All: Check if key material is zeroized in destructor/drop/finalizer
5. [ ] All: Check if any public method exposes raw key bytes
6. [ ] Rust: Verify `zeroize` crate usage on sensitive structs
7. [ ] C: Check for use-after-free in encrypt/decrypt paths
8. [ ] Go: Check if key slices are zeroed (Go GC doesn't guarantee zeroization)
9. [ ] Java/Kotlin: Check if key arrays are `Arrays.fill(0)` after use

## Output Format

```markdown
### Finding: [Title]
- **Severity**: CRITICAL | HIGH | MEDIUM | LOW
- **CWE**: CWE-XXX
- **File(s)**: path:line
- **Evidence**: Code snippet
- **Impact**: Key exposure, crash, or buffer overflow
- **Remediation**: Specific fix
```

## Cross-References
- Agent 1 (crypto-primitives) — Key derivation paths
- Agent 2 (cross-language) — Implementation differences
- Agent 9 (browser-wasm) — WASM memory isolation
- Agent 16 (fingerprint) — C fingerprint code
