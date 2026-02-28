# Security Agent: Auth & Session

**Priority**: HIGH (Phase 2)
**Team**: Application
**Domain**: Tokens, API keys, TOTP, recovery codes, rate limiting, identity provider, FIDO2

## Purpose

Audit all authentication and session management components for bypass vulnerabilities, token lifecycle issues, rate limiting weaknesses, and compliance with authentication standards.

## Files to Audit

### Primary Ownership
- `python/shield/integrations/protection.py` — API protector, rate limiter
- `python/shield/integrations/auth.py` — Token and API key auth
- `shield-core/src/identity.rs` — Identity provider, token management
- `shield-core/src/totp.rs` — TOTP implementation
- `shield-core/src/fido2/` — FIDO2/WebAuthn (all files)

### Secondary
- `python/shield/integrations/fastapi.py` — Auth decorators
- `python/shield/integrations/flask.py` — Auth decorators
- `shield-core/src/signatures.rs` — Signature-based auth

## Known Findings to Verify

1. **Rate limiter bypass via decryption error reset** — Rate limit counter resets when decryption fails, allowing unlimited retries. CWE-307.
2. **Tokens valid after user revocation** — No token blacklist/revocation mechanism. CWE-613.
3. **TOTP replay within window** — Same TOTP code can be reused within the 30-second window. CWE-294.
4. **User enumeration** — Different error messages for "user not found" vs "wrong password". CWE-203.
5. **Recovery codes not hashed** — Recovery codes stored in plaintext. CWE-256.

## Vulnerability Classes (CWE-mapped)

| CWE | Description | Where to Look |
|-----|-------------|---------------|
| CWE-307 | Brute force not restricted | Rate limiter implementation |
| CWE-613 | Insufficient session expiration | Token lifecycle |
| CWE-294 | Authentication bypass by replay | TOTP verification |
| CWE-203 | User enumeration | Error messages |
| CWE-256 | Plaintext credentials | Recovery code storage |
| CWE-287 | Improper authentication | FIDO2 challenge verification |

## Audit Checklist

1. [ ] Rate limiter: Verify counter persists through encryption errors
2. [ ] Rate limiter: Verify per-IP and per-user limits
3. [ ] Tokens: Verify revocation mechanism exists and works
4. [ ] Tokens: Verify expiration is enforced
5. [ ] TOTP: Verify one-time use per code (reject replay within window)
6. [ ] TOTP: Verify RFC 6238 compliance (time step, digits, algorithm)
7. [ ] Recovery codes: Verify codes are hashed, not stored plaintext
8. [ ] API keys: Verify constant-time comparison
9. [ ] Identity: Verify user enumeration is not possible via error messages
10. [ ] FIDO2: Verify challenge is single-use and time-bound

## Output Format

```markdown
### Finding: [Title]
- **Severity**: CRITICAL | HIGH | MEDIUM | LOW
- **CWE**: CWE-XXX
- **File(s)**: path:line
- **Evidence**: Code snippet
- **Impact**: Auth bypass, account takeover, or brute force
- **Remediation**: Specific fix
```

## Cross-References
- Agent 6 (web-integration) — Middleware auth enforcement
- Agent 15 (signatures-2fa) — TOTP and signature details
- Agent 11 (error-disclosure) — Error messages revealing auth state
