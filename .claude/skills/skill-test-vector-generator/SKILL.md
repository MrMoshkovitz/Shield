---
name: skill-test-vector-generator
description: Generate edge case test vectors for cross-language interoperability testing of Shield encryption. Use when creating tests for cross-language parity.
---

# Test Vector Generator

Generate edge case test vectors to verify cross-language encryption/decryption interoperability.

## When to Use
- Creating test vectors for cross-language parity testing
- Generating edge cases that might break specific implementations
- Building regression tests for found vulnerabilities

## Inputs
- Target operation: "encrypt" | "decrypt" | "pbkdf2" | "hmac" | "stream" | "ratchet"
- Edge case category: "boundary" | "encoding" | "overflow" | "empty" | "all"

## Procedure
1. Generate vectors per category:

### Boundary Cases
| Vector | Input | Why It Matters |
|--------|-------|---------------|
| Empty plaintext | `""` or `b""` | Some impls may crash or produce different output |
| Single byte | `\x00` | Minimum input edge case |
| Block boundary | Exactly 32 bytes | CTR block alignment |
| Block + 1 | 33 bytes | Forces partial block handling |
| Large input | 1MB+ | Integer overflow in length calculations |
| Max nonce | `\xff` * 16 | Counter overflow in CTR mode |

### Encoding Cases
| Vector | Input | Why It Matters |
|--------|-------|---------------|
| UTF-8 multibyte | Emoji, CJK chars | String vs bytes handling |
| Null bytes | `\x00` in middle of plaintext | C string termination |
| High bytes | `\xff\xfe\xfd` | Signed/unsigned byte issues |
| BOM | `\xef\xbb\xbf` prefix | UTF-8 BOM stripping |
| Mixed encoding | Latin-1 in UTF-8 context | Encoding mismatch |

### Password Edge Cases
| Vector | Input | Why It Matters |
|--------|-------|---------------|
| Empty password | `""` | Should be rejected or handled consistently |
| Unicode password | Emoji, diacritics | Normalization (NFC/NFD) |
| Very long password | 10,000+ chars | PBKDF2 performance |
| Null in password | `"pass\x00word"` | C string truncation |
| Whitespace only | `"   "` | Trimming differences |

### Cross-Language Parity Vectors
| Vector | Test |
|--------|------|
| Known ciphertext | Encrypt with Rust, decrypt with each other lang |
| Known key | Same PBKDF2 output across all impls |
| Known HMAC | Same MAC value across all impls |

2. For each vector, specify:
   - Input bytes (hex-encoded)
   - Password (if applicable)
   - Expected output or expected behavior (success/error)
   - Languages that should match

## Output Format
```
### Test Vector Set: [category]
| # | Name | Input (hex) | Password | Expected | Verified In |
|---|------|-------------|----------|----------|-------------|
| 1 | empty-plaintext | (empty) | "test123" | Valid ciphertext | Rust, Python |
...
```

## Used By
- A02 (Cross-Language Parity)
- A04 (Input Validation)
- T08 (Cross-Lang Interop)
