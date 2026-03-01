---
name: skill-cross-lang-constant-audit
description: Verify that security-critical constants (ITERATIONS, NONCE_SIZE, MAC_SIZE, KEY_SIZE) are identical across all 12 Shield implementations. Use when checking cross-language consistency.
---

# Cross-Language Constant Audit

Verify security constants match across all 12 implementations.

## When to Use
- Checking if security parameters are consistent across languages
- After any constant change to verify propagation
- During cross-language interoperability audit

## Inputs
- Constants to check (default: all security constants)
- Target languages (default: all 12)

## Procedure
1. Use skill-multi-lang-symbol-scanner to find each constant
2. Check these critical constants:

### Required Constants
| Constant | Expected Value | Search Patterns |
|----------|---------------|-----------------|
| ITERATIONS | 100000 | `ITERATIONS`, `iterations`, `PBKDF2_ITERATIONS`, `iterationCount` |
| NONCE_SIZE | 16 | `NONCE_SIZE`, `NONCE_LEN`, `nonceSize`, `IV_SIZE` |
| MAC_SIZE | 16 | `MAC_SIZE`, `MAC_LEN`, `macSize`, `TAG_SIZE`, `TAG_LEN` |
| KEY_SIZE | 32 | `KEY_SIZE`, `KEY_LEN`, `keySize`, `KEY_LENGTH` |
| HASH_OUTPUT_SIZE | 32 | SHA-256 output, may be implicit |
| SALT_SIZE | 16 | `SALT_SIZE`, `SALT_LEN`, `saltSize` |

3. For each constant in each language, record:
   - Defined value
   - Variable/constant name used
   - Whether it's a true constant or mutable variable
   - Whether it's exported/public

4. Flag any deviations:
   - Different values across languages
   - Constant defined as variable (mutable)
   - Magic numbers instead of named constants
   - Missing constant (hardcoded inline)

## Output Format
```
### Constant Parity Audit
| Constant | Expected | Rust | Py | JS | Go | C | Java | C# | Swift | Kt | WASM | Android | iOS |
|----------|----------|------|----|----|----|----|------|-------|-------|-----|------|---------|-----|
| ITERATIONS | 100000 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| NONCE_SIZE | 16 | ✓ | ✓ | ✗ 32 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
...

**Parity**: X/Y constants match across all implementations
**Deviations**: [list]
```

## Used By
- A1 (Crypto Primitives), A2 (Cross-Language), T8 (Cross-Lang Interop)
