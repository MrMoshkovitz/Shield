---
name: skill-multi-lang-symbol-scanner
description: Scan for a symbol, pattern, or function across all 12 Shield language implementations and return a comparison table. Use when auditing any cross-language feature.
---

# Multi-Language Symbol Scanner

Scan a pattern across all 12 Shield language implementations simultaneously.

## When to Use
- Auditing any feature that should be consistent across languages
- Checking if a function/constant exists in all implementations
- Finding language-specific variations of the same logic

## Inputs
- Search pattern (function name, constant, regex)
- Component scope (core, stream, ratchet, totp, etc.)

## Procedure
1. Use skill-shield-file-navigator to identify target files per language
2. For each of the 12 implementations, search for the pattern:
   ```
   Languages and primary source directories:
   - Rust: shield-core/src/
   - Python: python/shield/
   - JavaScript: javascript/src/
   - Go: go/
   - C: c/
   - Java: java/src/main/java/ai/guard8/shield/
   - C#: csharp/
   - Swift: swift/Sources/Shield/
   - Kotlin: kotlin/src/main/kotlin/ai/guard8/shield/
   - WASM: wasm/src/
   - Android: android/
   - iOS: ios/
   ```
3. Record for each language:
   - Found (Y/N)
   - File and line number
   - Implementation snippet (key lines only)
   - Any deviations from expected pattern
4. Build comparison table

## Output Format
```
### Symbol Scan: `{pattern}`
| Language | Found | File:Line | Implementation | Notes |
|----------|-------|-----------|---------------|-------|
| Rust | Y | lib.rs:42 | `fn encrypt(...)` | Reference impl |
| Python | Y | core.py:87 | `def encrypt(...)` | Matches |
| JavaScript | N | — | — | MISSING |
...

**Parity**: 11/12 implementations found
**Deviations**: JavaScript missing encrypt()
```

## Used By
- A1 (Crypto Primitives), A2 (Cross-Language), A3 (Memory Safety)
- A4 (Input Validation), A14 (Streaming), A15 (Signatures)
- T8 (Cross-Lang Interop), T9 (Key Lifecycle)
