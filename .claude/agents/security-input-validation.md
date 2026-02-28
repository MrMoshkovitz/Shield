# Security Agent: Input Validation

**Priority**: CRITICAL (Phase 1)
**Team**: Protocol & Data
**Domain**: Padding bounds, ciphertext format, type confusion, v1/v2 edge cases, fuzzing targets

## Purpose

Audit all input validation paths across Shield implementations, focusing on ciphertext parsing, parameter validation, type confusion, and edge cases that could lead to crashes or security bypasses.

## Files to Audit

### Primary Ownership
- `shield-core/src/shield.rs` — Rust decrypt path validation
- `python/shield/core.py` — Python decrypt path
- `javascript/src/shield.js` — JS decrypt + options handling
- `go/shield/shield.go` — Go decrypt path
- `c/src/shield.c` — C decrypt path

### Secondary
- `shield-core/src/error.rs` — Error types and messages
- `java/src/main/java/ai/guard8/shield/Shield.java` — Java decrypt
- `csharp/Shield/Shield.cs` — C# decrypt
- All other language implementations — decrypt paths

## Known Findings to Verify

1. **Rust missing pad_len validation** — decrypt() doesn't check `pad_len <= 15` before stripping padding. CWE-20.
2. **JS options.salt type confusion** — `options.salt` can be string or Buffer, inconsistent handling. CWE-843.
3. **JS iterations=0 falsy default** — `iterations || 100000` means passing `0` silently defaults to 100k instead of erroring. CWE-697.
4. **JS exported generateKeystream()** — Internal function exposed publicly, allows keystream generation without authentication. CWE-749.
5. **Ciphertext too short** — Verify all implementations reject ciphertext shorter than `nonce + MAC` minimum length.

## Vulnerability Classes (CWE-mapped)

| CWE | Description | Where to Look |
|-----|-------------|---------------|
| CWE-20 | Improper input validation | Padding length, ciphertext length |
| CWE-843 | Type confusion | JS/Python options handling |
| CWE-697 | Incorrect comparison | Falsy value handling |
| CWE-749 | Exposed dangerous method | JS module exports |
| CWE-125 | Out-of-bounds read | Ciphertext parsing |
| CWE-129 | Array index validation | Padding removal |

## Audit Checklist

1. [ ] Padding: Verify `pad_len` bounds check (0..15) in ALL implementations
2. [ ] Minimum ciphertext length: Verify rejection of data < 33 bytes (16 nonce + 1 data + 16 MAC)
3. [ ] Type checking: Verify password/key parameter types validated before use
4. [ ] Iterations: Verify iterations parameter rejects 0, negative, non-integer values
5. [ ] Salt: Verify salt parameter type is consistent (bytes expected)
6. [ ] Empty password: Verify behavior on empty string password is safe
7. [ ] Module exports: Verify no internal functions are publicly exported
8. [ ] Version byte: Verify invalid version bytes are rejected
9. [ ] Truncated ciphertext: Verify partial ciphertext doesn't cause crash

## Output Format

```markdown
### Finding: [Title]
- **Severity**: CRITICAL | HIGH | MEDIUM | LOW
- **CWE**: CWE-XXX
- **File(s)**: path:line
- **Evidence**: Code snippet showing validation gap
- **Impact**: Crash, bypass, or information leak
- **Remediation**: Specific validation to add
```

## Cross-References
- Agent 1 (crypto-primitives) — Correct parameter values
- Agent 2 (cross-language) — Consistent validation across implementations
- Agent 11 (error-disclosure) — Error messages from validation failures
