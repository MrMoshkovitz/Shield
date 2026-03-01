---
name: skill-error-message-cataloger
description: Extract and catalog all error messages, exceptions, and error strings from Shield implementations. Classify information disclosed in each. Use for error disclosure auditing.
---

# Error Message Cataloger

Extract all error messages and classify information they disclose.

## When to Use
- Auditing error handling for information disclosure
- Building error message inventory
- Checking if errors leak crypto parameters, key sizes, or internal state

## Inputs
- Target language(s) or "all"
- Target component (core, middleware, auth, etc.)

## Procedure
1. Search for error patterns per language:
   - Rust: `Err\(`, `panic!`, `eprintln!`, `format!.*error`
   - Python: `raise `, `Exception(`, `ValueError(`, `logging.error`
   - JavaScript: `throw `, `new Error(`, `console.error`
   - Go: `fmt.Errorf`, `errors.New`, `log.Fatal`
   - C: `fprintf(stderr`, `perror`, return codes with messages
   - Java/Kotlin: `throw new`, `Exception(`, `Log.e`
   - Swift: `throw `, `fatalError`, `NSError`
   - C#: `throw new`, `Exception(`

2. For each error message, classify what it discloses:
   | Disclosure Type | Risk Level | Examples |
   |----------------|------------|---------|
   | Key size/length | High | "Key must be 32 bytes" |
   | Algorithm name | Medium | "PBKDF2 derivation failed" |
   | Iteration count | High | "100000 iterations" |
   | Internal state | High | "Counter overflow at position X" |
   | File paths | Medium | Stack traces with paths |
   | Version info | Low | "Shield v2.1" |
   | Generic | Info | "Decryption failed" |

3. Flag errors that differ between encrypt vs decrypt (oracle risk)
4. Note errors visible to external callers vs internal only

## Output Format
```
### Error Message Catalog: {language}
| # | File:Line | Error Text | Disclosure | Risk | External? |
|---|-----------|-----------|------------|------|-----------|
| 1 | core.py:42 | "Invalid key length: {len}" | Key size | High | Yes |
| 2 | core.py:89 | "Decryption failed" | None | Info | Yes |
...

**Disclosure Summary**:
- Key sizes exposed: 3 messages
- Algorithm details: 2 messages
- Distinguishable encrypt/decrypt errors: Yes -> Oracle risk
```

## Used By
- A11 (Error Disclosure), A6 (Web Integration), T6 (Crypto Oracle)
