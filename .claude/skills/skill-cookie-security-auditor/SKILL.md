---
name: skill-cookie-security-auditor
description: Audit cookie security attributes including Secure, HttpOnly, SameSite, encryption, and expiry settings. Use when auditing session management and cookie handling.
---

# Cookie Security Auditor

Audit cookie security attributes and encrypted cookie implementation.

## When to Use
- Auditing session management
- Checking Shield's EncryptedCookie implementation
- Verifying cookie security headers

## Inputs
- Target files (cookie implementation, middleware)

## Procedure
1. Locate cookie-related code:
   - `python/shield/integrations/cookies.py`: EncryptedCookie
   - Middleware cookie handling
   - Session cookie configuration

2. Check cookie security attributes:
   | Attribute | Required | Check |
   |-----------|----------|-------|
   | `Secure` | Yes | Only sent over HTTPS |
   | `HttpOnly` | Yes | Not accessible to JavaScript |
   | `SameSite` | Yes | Lax or Strict (not None) |
   | `Domain` | Scoped | Not overly broad |
   | `Path` | Scoped | Minimal necessary path |
   | `Max-Age`/`Expires` | Yes | Reasonable expiry |

3. Check encrypted cookie implementation:
   - Encryption algorithm (should use Shield.encrypt)
   - Key management for cookie encryption
   - Integrity protection (HMAC)
   - Replay protection (timestamp or counter)
   - Cookie size vs encryption overhead

4. Check for vulnerabilities:
   - Cookie value predictability
   - Missing encryption on sensitive cookies
   - Session fixation (cookie not regenerated after auth)
   - Cookie scope too broad (domain/path)

## Output Format
```
### Cookie Security Audit
| Cookie | Secure | HttpOnly | SameSite | Encrypted | Expiry | Issues |
|--------|--------|----------|----------|-----------|--------|--------|
| session | ✓ | ✓ | Lax | ✓ Shield | 24h | None |
| prefs | ✗ | ✗ | None | ✗ | Never | Missing flags |
...
```

## Used By
- A6 (Web Integration), A7 (Auth & Session)
