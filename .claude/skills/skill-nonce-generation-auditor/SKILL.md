---
name: skill-nonce-generation-auditor
description: Verify that nonce generation uses cryptographically secure random number generators (CSPRNG) in all Shield implementations. Use when auditing randomness sources.
---

# Nonce Generation Auditor

Verify CSPRNG usage for nonce generation across all implementations.

## When to Use
- Auditing randomness quality in encryption
- Checking for weak PRNG usage
- Verifying nonce uniqueness guarantees

## Inputs
- Target language(s) or "all"

## Procedure
1. Locate nonce generation code in each implementation
2. Verify CSPRNG usage per language:

### Acceptable CSPRNG Sources
| Language | Acceptable | Unacceptable |
|----------|-----------|-------------|
| Rust | `OsRng`, `thread_rng()` (ChaCha) | `StdRng::seed_from_u64` |
| Python | `os.urandom()`, `secrets` | `random.randint()` |
| JavaScript | `crypto.randomBytes()`, `crypto.getRandomValues()` | `Math.random()` |
| Go | `crypto/rand.Read()` | `math/rand` |
| C | `/dev/urandom`, `getrandom()`, platform API | `rand()`, `srand()` |
| Java | `SecureRandom` | `Random()` |
| C# | `RandomNumberGenerator` | `Random()` |
| Swift | `SecRandomCopyBytes` | `arc4random` (acceptable but verify) |
| Kotlin | `SecureRandom` | `Random()` |
| Android | `SecureRandom` | `Random()` |
| iOS | `SecRandomCopyBytes` | -- |
| WASM | Host `crypto.getRandomValues` | JS `Math.random` |

3. Verify nonce properties:
   - Length: exactly 16 bytes (128 bits)
   - Generated fresh for EVERY encryption call
   - Not derived from timestamp, counter, or other predictable source
   - Not reused across messages

4. Check for nonce-reuse vulnerabilities:
   - Is nonce parameter user-controllable? (should not be)
   - Any test/debug mode that fixes the nonce?
   - Any path where nonce generation could be skipped?

## Output Format
```
### Nonce Generation Audit
| Language | Source | Secure? | Length | Fresh? | User-controllable? | Issues |
|----------|--------|---------|--------|--------|-------------------|--------|
| Rust | OsRng | Y | 16B | Y | No | None |
| Python | os.urandom | Y | 16B | Y | No | None |
...

**Issues Found**: [list]
```

## Used By
- A1 (Crypto Primitives), A2 (Cross-Language)
