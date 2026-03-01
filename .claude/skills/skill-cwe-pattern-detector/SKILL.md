---
name: skill-cwe-pattern-detector
description: Scan Shield codebase for CWE-mapped dangerous patterns like buffer overflows, unsafe operations, weak comparisons, and injection vectors. Use for automated vulnerability pattern detection.
---

# CWE Pattern Detector

Automated scan for known dangerous code patterns mapped to CWE identifiers.

## When to Use
- Initial sweep of any language implementation
- Checking for common vulnerability patterns
- Automated security screening before deep review

## Inputs
- Target language(s) or "all"
- Target directory or file
- CWE categories to check (optional, defaults to all)

## Procedure
1. Scan for these language-specific dangerous patterns:

### C (c/)
| Pattern | CWE | Risk |
|---------|-----|------|
| `strcat\|strcpy\|sprintf\|gets` | CWE-120 | Buffer overflow |
| `malloc.*(?!free)` | CWE-401 | Memory leak |
| `memcmp` (for crypto) | CWE-208 | Timing side-channel |
| `rand\(\)\|srand` | CWE-330 | Weak PRNG |
| `system\|popen\|exec` | CWE-78 | Command injection |

### Rust (shield-core/)
| Pattern | CWE | Risk |
|---------|-----|------|
| `\.unwrap\(\)\|\.expect\(` | CWE-252 | Unhandled error |
| `unsafe\s*\{` | CWE-676 | Unsafe code block |
| `as\s+\*` | CWE-704 | Type confusion via raw ptr |
| `==\|!=` (for crypto bytes) | CWE-208 | Non-constant-time compare |

### Python (python/)
| Pattern | CWE | Risk |
|---------|-----|------|
| `eval\|exec\|compile` | CWE-94 | Code injection |
| `pickle\.load\|yaml\.load` | CWE-502 | Deserialization |
| `==` (for HMAC/key compare) | CWE-208 | Timing attack |
| `random\.(` (not secrets) | CWE-330 | Weak PRNG |
| `os\.system\|subprocess\.call` | CWE-78 | Command injection |

### JavaScript (javascript/)
| Pattern | CWE | Risk |
|---------|-----|------|
| `eval\|Function\(` | CWE-94 | Code injection |
| `==\s` (not ===) | CWE-843 | Type confusion |
| `Math\.random` | CWE-330 | Weak PRNG |
| `innerHTML\|outerHTML` | CWE-79 | XSS |
| `Buffer\.from\(.*'ascii` | CWE-838 | Encoding issue |

### Go (go/)
| Pattern | CWE | Risk |
|---------|-----|------|
| `math/rand` (not crypto/rand) | CWE-330 | Weak PRNG |
| `bytes\.Equal` (for crypto) | CWE-208 | Timing attack |
| `exec\.Command` | CWE-78 | Command injection |
| `fmt\.Sprintf.*%v.*err` | CWE-209 | Error info leak |

### Java/Kotlin
| Pattern | CWE | Risk |
|---------|-----|------|
| `Random\(\)` (not SecureRandom) | CWE-330 | Weak PRNG |
| `Arrays\.equals` (for crypto) | CWE-208 | Timing attack |
| `Runtime\.exec` | CWE-78 | Command injection |
| `\.equals\(` (for crypto bytes) | CWE-208 | Timing attack |

### Swift
| Pattern | CWE | Risk |
|---------|-----|------|
| `arc4random` | CWE-330 | Weak PRNG (acceptable on Apple) |
| `==` (for Data compare in crypto) | CWE-208 | Timing attack |
| `try!` | CWE-252 | Forced unwrap |

### C#
| Pattern | CWE | Risk |
|---------|-----|------|
| `new Random\(\)` | CWE-330 | Weak PRNG |
| `SequenceEqual` (for crypto) | CWE-208 | Timing attack |
| `Process\.Start` | CWE-78 | Command injection |

2. For each match, record file:line, surrounding context, and CWE mapping
3. Filter false positives (pattern in comments, tests, or non-security context)
4. Group by CWE category

## Output Format
```
### CWE Pattern Scan Results
**Scope**: {language/directory}
**Patterns checked**: {count}
**Matches found**: {count}

| # | CWE | Pattern | File:Line | Context | Severity |
|---|-----|---------|-----------|---------|----------|
| 1 | CWE-330 | `Math.random` | shield.js:42 | nonce generation | Critical |
...

**By CWE Category**:
- CWE-208 (Timing): 3 findings
- CWE-330 (PRNG): 1 finding
```

## Used By
- A3 (Memory Safety), A4 (Input Validation)
- A16 (Fingerprint), A11 (Error Disclosure)
