---
name: skill-zeroization-verifier
description: Verify that cryptographic key material is properly wiped from memory after use, using language-appropriate zeroization mechanisms. Use when auditing key lifecycle.
---

# Zeroization Verifier

Verify key material is securely wiped after use in each implementation.

## When to Use
- Auditing key lifecycle and destruction
- Checking for key material persistence in memory
- Verifying language-specific secure wipe mechanisms

## Inputs
- Target language(s) or "all"
- Key types to check (master, derived, HMAC, session)

## Procedure
1. Use skill-key-accessor-mapper to find all key variables
2. For each key variable, trace its lifecycle to destruction
3. Verify zeroization per language:

### Language-Specific Zeroization
| Language | Correct Approach | Incorrect | Notes |
|----------|-----------------|-----------|-------|
| Rust | `zeroize` crate, `Zeroizing<>` wrapper | `drop` alone | Compiler may optimize out writes |
| Python | `del key; gc.collect()` or ctypes memset | `del key` alone | GC non-deterministic, copies exist |
| JavaScript | `buffer.fill(0)` then deref | `= null` | GC non-deterministic |
| Go | `for i := range key { key[i] = 0 }` | `key = nil` | Compiler may optimize |
| C | `memset_s()` or `explicit_bzero()` | `memset()` | Compiler may optimize out memset |
| Java | `Arrays.fill(key, (byte)0)` | `key = null` | GC non-deterministic |
| C# | `CryptographicOperations.ZeroMemory()` | `Array.Clear` | May be optimized |
| Swift | `key.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) }` | `= Data()` | ARC non-deterministic |
| Kotlin | `Arrays.fill(key, 0)` | `= null` | Same as Java |

4. Check for:
   - Key copies that aren't zeroized (substring, slice, clone)
   - Keys in string form (immutable, can't zeroize in Java/Python/JS)
   - Keys stored in collections that aren't cleared
   - Keys passed to logging or debug functions
   - Exception handlers that don't clean up keys

5. Flag missing zeroization for each key type found

## Output Format
```
### Zeroization Audit
| Language | Key Variable | Created | Zeroized? | Method | Correct? |
|----------|-------------|---------|-----------|--------|----------|
| Rust | self.key | lib.rs:30 | Yes | Zeroizing<> | ✓ |
| Python | self._key | core.py:25 | No | — | ✗ MISSING |
...

**Zeroization Coverage**: X/Y key variables properly zeroized
**Missing**: [list]
```

## Used By
- A3 (Memory Safety), T9 (Key Lifecycle)
