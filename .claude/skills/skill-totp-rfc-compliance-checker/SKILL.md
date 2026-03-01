---
name: skill-totp-rfc-compliance-checker
description: Verify TOTP implementation against RFC 6238 requirements including time step, digit count, algorithm, and replay prevention. Use when auditing two-factor authentication.
---

# TOTP RFC Compliance Checker

Verify TOTP implementation against RFC 6238.

## When to Use
- Auditing two-factor authentication
- Checking TOTP interoperability
- Verifying replay prevention

## Inputs
- Target implementation(s)

## Procedure
1. Locate TOTP implementation across languages:
   - Rust: `shield-core/src/totp.rs`
   - Python: `python/shield/totp.py`
   - JavaScript: `javascript/src/totp.js`
   - Others: search for "totp" or "TOTP"

2. Verify RFC 6238 compliance:
   | Requirement | RFC 6238 Spec | Check |
   |------------|--------------|-------|
   | Time step (T) | 30 seconds (default) | Configurable? Default correct? |
   | Start time (T0) | Unix epoch (0) | Correct? |
   | Digits | 6 (default), 6-8 allowed | Configurable? |
   | Algorithm | HMAC-SHA-1 (default), SHA-256/512 allowed | Which? |
   | Secret length | ≥128 bits recommended | Enforced? |
   | Time window | ±1 step tolerance recommended | Implemented? How many steps? |

3. Check security requirements:
   | Check | Description | Risk if Missing |
   |-------|-----------|----------------|
   | Replay prevention | Each code usable only once | Code reuse in window |
   | Rate limiting | Limit verification attempts | Brute force (10^6 for 6 digits) |
   | Secret storage | Encrypted at rest | Secret exposure |
   | Timing | Constant-time comparison | Timing attack |
   | Clock sync | Handle clock skew | False rejections or extended window |
   | Backup codes | Recovery mechanism | Account lockout |

4. Cross-language parity:
   - Do all implementations produce the same TOTP code for the same secret + time?
   - Test with RFC 6238 test vectors

## Output Format
```
### TOTP RFC 6238 Compliance
| Parameter | RFC Spec | Implementation | Compliant? |
|-----------|----------|---------------|-----------|
| Time step | 30s | 30s | ✓ |
| Digits | 6 | 6 | ✓ |
| Algorithm | HMAC-SHA-1 | HMAC-SHA-256 | ✓ (allowed) |
| Replay prevention | Required | Not implemented | ✗ |
...

**Compliance**: X/Y requirements met
```

## Used By
- A7 (Auth & Session), A15 (Signatures/2FA)
