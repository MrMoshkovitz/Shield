---
name: skill-ctr-mode-verifier
description: Verify SHA256-CTR stream cipher implementation correctness including counter initialization, increment logic, endianness, overflow handling, and XOR application. Use when auditing encryption mode.
---

# CTR Mode Verifier

Verify SHA256-CTR implementation correctness across all Shield implementations.

## When to Use
- Auditing the core encryption mode
- Checking counter handling for overflow bugs
- Verifying cross-language CTR behavior parity

## Inputs
- Target language(s) or "all"
- Focus area (counter, XOR, overflow, endianness)

## Procedure
1. Locate the CTR mode implementation in each language (typically in the encrypt function)
2. Verify each aspect:

### Counter Initialization
- Counter starts from nonce value (not zero)
- Nonce is 16 bytes from CSPRNG
- Counter block = nonce || counter_value (or nonce IS the counter block)
- Verify initial counter state is deterministic from nonce

### Counter Increment
- Increment is on the correct portion of the counter block
- Big-endian vs little-endian consistency across languages
- Increment by 1 per block (not per byte)
- No skip or double-increment bugs

### Overflow Handling
- What happens when counter reaches max value?
- Should: error/abort (not wrap to zero -- would reuse keystream)
- Check: is overflow even detectable given message size limits?
- Max message size = 2^128 x 32 bytes (with 128-bit counter) -- practically unlimited

### Keystream Generation
- SHA-256(key || counter) produces 32 bytes of keystream per block
- XOR is applied byte-by-byte between keystream and plaintext
- Last block: only XOR the bytes needed (no padding artifacts)
- Verify: SHA-256 input format is consistent (key || counter, not counter || key)

### XOR Application
- XOR operates on individual bytes
- No integer-width issues (e.g., XORing 32-bit ints vs bytes in C)
- Partial final block handled correctly

3. Use skill-function-diff-comparator to compare implementations

## Output Format
```
### CTR Mode Verification
| Aspect | Rust | Python | JS | Go | C | Java | C# | Swift | Kotlin |
|--------|------|--------|----|----|---|------|----|-------|--------|
| Counter init | Y | Y | Y | Y | ? | Y | Y | Y | Y |
| Endianness | BE | BE | BE | BE | BE | BE | BE | BE | BE |
| Overflow | Error | Error | ? | Error | ? | Error | Error | Error | Error |
| XOR correct | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| SHA input order | k||c | k||c | k||c | k||c | k||c | k||c | k||c | k||c | k||c |

**Issues**: [list any deviations]
```

## Used By
- A1 (Crypto Primitives), A2 (Cross-Language), A14 (Streaming/Group)
