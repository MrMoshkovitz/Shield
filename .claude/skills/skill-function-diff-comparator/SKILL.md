---
name: skill-function-diff-comparator
description: Extract the same function from 2+ language implementations and produce a semantic diff highlighting behavioral differences. Use when comparing cross-language implementations.
---

# Function Diff Comparator

Produce semantic diffs of the same function across language implementations.

## When to Use
- Comparing encrypt/decrypt implementations across languages
- Finding behavioral divergences in cross-language code
- Investigating interoperability failures

## Inputs
- Function name (e.g., "encrypt", "derive_key", "verify_mac")
- Languages to compare (2+, default: all)

## Procedure
1. Use skill-multi-lang-symbol-scanner to locate the function in each language
2. Extract the full function body from each implementation
3. Normalize to pseudocode for comparison:
   - Strip language-specific syntax
   - Align variable names to canonical form
   - Identify logical steps in order
4. Compare step-by-step:

### Comparison Dimensions
| Dimension | What to Check |
|-----------|--------------|
| Algorithm steps | Same operations in same order? |
| Input validation | Same checks on input? |
| Error handling | Same error conditions? |
| Byte ordering | Big-endian vs little-endian? |
| Integer sizes | 32-bit vs 64-bit operations? |
| String encoding | UTF-8 handling consistent? |
| Buffer management | Allocation and cleanup? |
| Return format | Same output structure? |

5. Produce semantic diff showing:
   - Matching steps (aligned)
   - Missing steps in some implementations
   - Different logic for same step
   - Extra steps unique to one implementation

## Output Format
```
### Semantic Diff: `{function_name}`
**Languages**: Rust (reference) vs Python vs JavaScript

| Step | Rust | Python | JS | Match? |
|------|------|--------|----|--------|
| 1. Validate input | len check | len check | type check + len | ✗ JS extra |
| 2. Generate nonce | OsRng 16B | urandom 16B | randomBytes 16B | ✓ |
| 3. Derive key | PBKDF2 | PBKDF2 | PBKDF2 | ✓ |
| 4. CTR encrypt | SHA256-CTR | SHA256-CTR | SHA256-CTR | ✓ |
| 5. Compute MAC | HMAC(n+ct) | HMAC(n+ct) | HMAC(ct) | ✗ JS missing nonce |
...

**Behavioral Differences**: 2 found
1. JS MAC doesn't cover nonce — interop break
2. JS has extra type validation — cosmetic
```

## Used By
- A2 (Cross-Language), A14 (Streaming/Group), T8 (Cross-Lang Interop)
