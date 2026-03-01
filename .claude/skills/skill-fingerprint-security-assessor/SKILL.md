---
name: skill-fingerprint-security-assessor
description: Assess device fingerprinting implementation for hash strength, injection vulnerabilities, buffer overflow, and spoofability. Use when auditing fingerprinting security.
---

# Fingerprint Security Assessor

Assess fingerprinting implementation security across languages.

## When to Use
- Auditing device fingerprinting implementations
- Checking for fingerprint spoofing vulnerabilities
- Assessing C implementation memory safety

## Inputs
- Target language(s) or "all"

## Procedure
1. Locate fingerprint implementations:
   - JavaScript: `javascript/src/fingerprint.js`
   - Go: `go/fingerprint.go`
   - Java: `java/.../Fingerprint.java`
   - C: `c/fingerprint.c`

2. Assess hash strength:
   | Check | Description |
   |-------|-----------|
   | Hash algorithm | MD5 (weak) vs SHA-256 (strong) |
   | Input coverage | What data feeds the fingerprint |
   | Collision resistance | Can two devices produce same fingerprint? |
   | Uniqueness | Is fingerprint sufficiently unique? |

3. Check for injection vulnerabilities:
   | Check | Language | Risk |
   |-------|---------|------|
   | Input sanitization | All | Fingerprint data from user-controlled sources |
   | Buffer bounds | C | Fixed buffer sizes with variable input |
   | String format | C | printf-style format strings |
   | Integer overflow | C/Go | Size calculations |
   | Null termination | C | String handling |

4. C-specific memory safety:
   - Use skill-cwe-pattern-detector for C patterns
   - Check buffer sizes vs actual data
   - Check for strcat/strcpy without bounds
   - Check malloc/free pairing
   - Check for stack buffer overflow

5. Assess spoofability:
   - Can fingerprint inputs be faked?
   - Is fingerprint bound to hardware?
   - Can fingerprint be replayed from another device?

## Output Format
```
### Fingerprint Security Assessment
| Language | Hash | Injection Risk | Memory Safety | Spoofability |
|----------|------|---------------|---------------|-------------|
| JS | MD5 | Low | N/A | High |
| C | MD5 | High (buffer) | At risk | High |
...

**Critical Issues**: [list]
```

## Used By
- A16 (Fingerprint), A3 (Memory Safety)
