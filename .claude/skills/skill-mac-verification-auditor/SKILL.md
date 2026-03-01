---
name: skill-mac-verification-auditor
description: Audit HMAC-SHA256 message authentication implementation including MAC coverage, truncation, key separation, and constant-time comparison. Use when auditing message integrity.
---

# MAC Verification Auditor

Audit HMAC-SHA256 implementation for correctness and security.

## When to Use
- Auditing message authentication code implementation
- Checking MAC-then-encrypt vs encrypt-then-MAC
- Verifying MAC comparison is constant-time

## Inputs
- Target language(s) or "all"

## Procedure
1. Locate HMAC computation and verification in each implementation
2. Verify each aspect:

### MAC Coverage
- MAC must cover: nonce || ciphertext (encrypt-then-MAC)
- NOT: plaintext (would be MAC-then-encrypt, vulnerable)
- Verify exact bytes fed to HMAC:
  - `HMAC(key, nonce || ciphertext)` correct
  - `HMAC(key, ciphertext)` wrong (nonce not authenticated)
  - `HMAC(key, plaintext)` wrong (MAC-then-encrypt)

### Key Separation
- HMAC key MUST be different from encryption key
- Check: are encryption key and MAC key derived independently?
- Bad: same PBKDF2 output for both
- Good: PBKDF2 output split, or separate derivations with different info/context

### Truncation
- Shield spec: HMAC-SHA256 truncated to 128 bits (16 bytes)
- Verify truncation takes first 16 bytes (not last, not middle)
- Verify truncation is applied consistently in encrypt AND decrypt

### Verify-Before-Decrypt
- MAC MUST be verified BEFORE any decryption occurs
- If MAC fails, no decryption output should be produced
- Check for early-return on MAC failure
- No partial decryption before MAC check

### Constant-Time Comparison
- MAC comparison MUST use constant-time function
- Per language:
  | Language | Correct Function |
  |----------|-----------------|
  | Rust | `subtle::ConstantTimeEq` or manual |
  | Python | `hmac.compare_digest()` |
  | JavaScript | `crypto.timingSafeEqual()` |
  | Go | `subtle.ConstantTimeCompare()` |
  | C | custom constant-time memcmp |
  | Java | `MessageDigest.isEqual()` |
  | C# | `CryptographicOperations.FixedTimeEquals()` |
  | Swift | Custom or `SecureCompare` |
  | Kotlin | `MessageDigest.isEqual()` |

## Output Format
```
### MAC Audit Results
| Language | Coverage | Key Sep | Truncation | Verify-First | Const-Time | Issues |
|----------|----------|---------|-----------|-------------|-----------|--------|
| Rust | nonce+ct | Y | 16B | Y | Y | None |
...

**Critical Issues**: [list]
```

## Used By
- A1 (Crypto Primitives), A2 (Cross-Language), A8 (Transport Protocol)
