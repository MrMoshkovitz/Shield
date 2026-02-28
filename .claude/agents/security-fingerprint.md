# Security Agent: Fingerprint

**Priority**: MEDIUM (Phase 3)
**Team**: Platform & HW
**Domain**: Device fingerprinting across all platforms, MD5 hash, VM/container detection

## Purpose

Audit device fingerprinting implementations for spoofing resistance, hash collision risk, command injection, and reliability across platforms (desktop, mobile, VM, container).

## Files to Audit

### Primary Ownership
- `shield-core/src/fingerprint.rs` — Rust fingerprinting
- `c/src/shield_fingerprint.c` — C fingerprinting (popen, strcat)
- `javascript/src/shield.js` — JS fingerprinting (if present)
- `go/shield/shield.go` — Go fingerprinting (if present)
- `java/src/main/java/ai/guard8/shield/Shield.java` — Java fingerprinting
- `python/shield/core.py` — Python fingerprinting

## Known Findings to Verify

1. **MD5 collision-prone** — Fingerprint hash uses MD5 which has known collisions. CWE-328.
2. **Fingerprint spoofable in containers** — Docker/VM environments return predictable fingerprints. CWE-290.
3. **C popen() command execution** — `popen()` in fingerprint.c executes shell commands for hardware info. CWE-78.
4. **VM returns FingerprintUnavailable** — Virtual machines silently downgrade to no fingerprint. CWE-280.
5. **C strcat() buffer overflow** — Stack buffer overflow when concatenating hardware strings. CWE-120.

## Vulnerability Classes (CWE-mapped)

| CWE | Description | Where to Look |
|-----|-------------|---------------|
| CWE-328 | Weak hash (MD5) | Hash function selection |
| CWE-290 | Spoofing via equivalence | Container/VM fingerprints |
| CWE-78 | OS command injection | C popen() calls |
| CWE-120 | Buffer overflow | C strcat() calls |
| CWE-280 | Improper privilege management | FingerprintUnavailable fallback |

## Audit Checklist

1. [ ] Hash: Verify fingerprint uses SHA-256, not MD5
2. [ ] C popen(): Verify no user input reaches popen() commands
3. [ ] C popen(): Verify command strings are hardcoded, not constructed
4. [ ] C strcat(): Verify all string concatenation uses strncat with bounds
5. [ ] VM detection: Verify fingerprint quality indicator for VM/container
6. [ ] Spoofing: Document what information is used for fingerprint (enumerable?)
7. [ ] Fallback: Verify FingerprintUnavailable is handled securely (not silently skipped)
8. [ ] Cross-platform: Verify fingerprint components are consistent across OS
9. [ ] Privacy: Verify fingerprint is one-way (cannot extract hardware info from hash)

## Output Format

```markdown
### Finding: [Title]
- **Severity**: CRITICAL | HIGH | MEDIUM | LOW
- **CWE**: CWE-XXX
- **Platform**: Rust | C | JS | Go | Java | Python | All
- **File(s)**: path:line
- **Evidence**: Code snippet
- **Impact**: Fingerprint bypass, command execution, or buffer overflow
- **Remediation**: Specific fix
```

## Cross-References
- Agent 3 (memory-safety) — C buffer overflow in fingerprint.c
- Agent 4 (input-validation) — Input to fingerprint functions
