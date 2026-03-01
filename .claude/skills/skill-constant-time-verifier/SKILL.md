---
name: skill-constant-time-verifier
description: Verify that all cryptographic comparisons (MAC verification, key comparison, token validation) use constant-time operations to prevent timing side-channels. Use when auditing side-channel resistance.
---

# Constant-Time Verifier

Verify crypto comparisons use constant-time operations across all implementations.

## When to Use
- Auditing for timing side-channel vulnerabilities
- Checking MAC verification code
- Reviewing any code that compares secret values

## Inputs
- Target language(s) or "all"
- Comparison type (MAC, key, token, password hash)

## Procedure
1. Find all comparisons involving secret/crypto values:
   - MAC comparison in decrypt
   - Key comparison in authentication
   - Token comparison in session validation
   - Password hash comparison
   - TOTP code comparison

2. For each comparison, verify constant-time function usage:

### Correct Constant-Time Functions
| Language | Function | Notes |
|----------|---------|-------|
| Rust | `subtle::ConstantTimeEq::ct_eq()` | From `subtle` crate |
| Rust | `ring::constant_time::verify_slices_are_equal()` | From `ring` |
| Python | `hmac.compare_digest(a, b)` | Built-in |
| Python | `secrets.compare_digest(a, b)` | Built-in |
| JavaScript | `crypto.timingSafeEqual(a, b)` | Node.js built-in |
| Go | `subtle.ConstantTimeCompare(a, b)` | `crypto/subtle` |
| C | Custom loop (XOR accumulate) | Must NOT early-return |
| Java | `MessageDigest.isEqual(a, b)` | Built-in |
| C# | `CryptographicOperations.FixedTimeEquals(a, b)` | .NET Core 2.1+ |
| Swift | Custom or CC library | No standard |
| Kotlin | `MessageDigest.isEqual(a, b)` | Same as Java |

### Dangerous Patterns (Non-Constant-Time)
| Pattern | Language | Risk |
|---------|---------|------|
| `==` on byte arrays | All | Early termination |
| `Arrays.equals()` | Java/Kotlin | Early termination |
| `bytes.Equal()` | Go | Early termination |
| `===` on buffers | JavaScript | Early termination |
| `SequenceEqual()` | C# | Early termination |
| `memcmp()` | C | Early termination |
| `!=` with early return | All | Timing leak |

3. For each finding, assess exploitability:
   - Network-observable? (remote timing attack)
   - Local only? (side-channel in shared environment)
   - Protected by other mechanisms? (rate limiting, noise)

## Output Format
```
### Constant-Time Audit
| Language | Location | Comparison | Function Used | Constant-Time? | Risk |
|----------|----------|-----------|---------------|---------------|------|
| Python | core.py:142 | MAC verify | hmac.compare_digest | ✓ | None |
| C | shield.c:89 | MAC verify | memcmp | ✗ | High |
...

**Vulnerable Comparisons**: X found
**By Risk**: Critical: X, High: Y, Medium: Z
```

## Used By
- A1 (Crypto Primitives), A2 (Cross-Language), A8 (Transport), A11 (Error Disclosure)
