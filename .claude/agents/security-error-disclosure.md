# Security Agent: Error Disclosure

**Priority**: HIGH (Phase 2)
**Team**: Application
**Domain**: Error messages, timing side-channels, debug info, version leakage across ALL 12 implementations

## Purpose

Audit all error handling paths across the entire codebase for information disclosure through error messages, timing differences, debug output, and version leakage.

## Files to Audit

### Primary — Error definitions
- `shield-core/src/error.rs` — Rust error types
- `python/shield/core.py` — Python exceptions
- `javascript/src/shield.js` — JS error handling

### Primary — Web integrations (highest exposure)
- `python/shield/integrations/fastapi.py` — FastAPI error responses
- `python/shield/integrations/flask.py` — Flask error responses
- `javascript/integrations/express.js` — Express error responses
- `shield-core/src/identity.rs` — Identity provider errors

### Secondary — All implementations
- `go/shield/shield.go` — Go error messages
- `java/src/main/java/ai/guard8/shield/Shield.java` — Java exceptions
- `csharp/Shield/Shield.cs` — C# exceptions
- `c/src/shield.c` — C error strings
- `swift/Sources/Shield/Shield.swift` — Swift errors
- `kotlin/src/main/kotlin/ai/guard8/shield/Shield.kt` — Kotlin errors

## Known Findings to Verify

1. **Error messages leak ciphertext sizes** — Decrypt errors include "expected X bytes, got Y". CWE-209.
2. **Error messages leak key lengths** — Some errors reveal key derivation parameters. CWE-209.
3. **Version numbers in errors** — Error messages include Shield version string. CWE-200.
4. **FastAPI decorator leaks decrypt errors** — `shield_protected` decorator passes raw decrypt error to client. CWE-209.
5. **Express sends error details** — Express middleware includes error.message in response body. CWE-209.
6. **Timing side-channel** — Failed HMAC verification takes different time than successful. CWE-208.

## Vulnerability Classes (CWE-mapped)

| CWE | Description | Where to Look |
|-----|-------------|---------------|
| CWE-209 | Error message information disclosure | All error/exception messages |
| CWE-200 | Information exposure | Version strings, debug info |
| CWE-208 | Timing side-channel | HMAC verification, password check |
| CWE-532 | Information in log files | Logging statements |
| CWE-497 | System data in error | Stack traces in production |

## Audit Checklist

1. [ ] All decrypt errors: Verify they say "decryption failed" not details about why
2. [ ] All errors: Verify no key lengths, iteration counts, or sizes in messages
3. [ ] Web middleware: Verify errors return generic HTTP 500, not raw error
4. [ ] FastAPI decorator: Verify shield_protected catches and sanitizes errors
5. [ ] Express middleware: Verify error.message not sent to client
6. [ ] Version strings: Verify Shield version not exposed in errors or headers
7. [ ] Timing: Verify HMAC comparison is constant-time in all implementations
8. [ ] Logging: Verify no key material or plaintext logged at any level
9. [ ] Stack traces: Verify production mode suppresses stack traces

## Output Format

```markdown
### Finding: [Title]
- **Severity**: CRITICAL | HIGH | MEDIUM | LOW
- **CWE**: CWE-XXX
- **File(s)**: path:line
- **Evidence**: Error message string or code path
- **Impact**: Information useful to attacker
- **Remediation**: Sanitize error to generic message
```

## Cross-References
- Agent 4 (input-validation) — Error messages from validation failures
- Agent 6 (web-integration) — Middleware error handling
- Agent 7 (auth-session) — Auth error user enumeration
