# Security Agent: Web Integration

**Priority**: HIGH (Phase 2)
**Team**: Application
**Domain**: FastAPI/Flask/Django/Express middleware, browser bridge, cookies, CORS

## Purpose

Audit all web framework integrations for security issues including fail-open patterns, route bypass, credential exposure, and middleware misconfiguration.

## Files to Audit

### Primary Ownership
- `python/shield/integrations/fastapi.py` — FastAPI middleware
- `python/shield/integrations/flask.py` — Flask extension
- `javascript/integrations/express.js` — Express middleware
- `python/shield/integrations/browser.py` — Browser bridge
- `python/shield/integrations/cookies.py` — Encrypted cookies
- `python/shield/integrations/cors.py` — CORS signing

### Secondary
- `python/shield/integrations/protection.py` — API protection
- `python/shield/integrations/auth.py` — Auth helpers
- `browser/js/index.ts` — Browser SDK

## Known Findings to Verify

1. **Express fail-open** — On encryption error, Express middleware sends plaintext response instead of error. CWE-636.
2. **Route exclusion startswith() bypass** — `excluded_paths` uses `startswith()` which can be bypassed with path traversal. CWE-22.
3. **Password stored as constructor arg** — Middleware stores password as instance attribute in plaintext memory. CWE-256.
4. **CORS signing gaps** — SecureCORS may not validate origin against signed tokens properly. CWE-346.
5. **Cookie encryption key in memory** — EncryptedCookie keeps key accessible throughout request lifecycle.

## Vulnerability Classes (CWE-mapped)

| CWE | Description | Where to Look |
|-----|-------------|---------------|
| CWE-636 | Not failing securely | Express error handling |
| CWE-22 | Path traversal | Route exclusion logic |
| CWE-256 | Plaintext credential storage | Middleware constructors |
| CWE-346 | Origin validation | CORS middleware |
| CWE-614 | Sensitive cookie without Secure | Cookie attributes |
| CWE-352 | CSRF | Missing CSRF tokens |

## Audit Checklist

1. [ ] Express: Verify error handler returns 500, never plaintext on encryption failure
2. [ ] FastAPI: Verify excluded_paths uses exact match or proper path parsing
3. [ ] Flask: Verify same path exclusion pattern as FastAPI
4. [ ] All middleware: Verify password/key not stored as plain instance attribute
5. [ ] Cookies: Verify Secure, HttpOnly, SameSite flags set
6. [ ] CORS: Verify origin validation is strict (no wildcard with credentials)
7. [ ] Browser bridge: Verify key exchange is authenticated
8. [ ] All: Verify Content-Type headers set correctly on encrypted responses

## Output Format

```markdown
### Finding: [Title]
- **Severity**: CRITICAL | HIGH | MEDIUM | LOW
- **CWE**: CWE-XXX
- **File(s)**: path:line
- **Evidence**: Code snippet
- **Impact**: Data exposure, auth bypass, or CSRF
- **Remediation**: Specific middleware fix
```

## Cross-References
- Agent 7 (auth-session) — Token/session management in middleware
- Agent 9 (browser-wasm) — Browser bridge security
- Agent 11 (error-disclosure) — Error message content in middleware
