# Cross-Domain Team 8: Cross-Language Interop Exploit Chain

**Priority**: CRITICAL
**Phase**: 4 (after Phase 2 — needs Agents 2, 4, 11, 14 findings)
**Type**: Cross-Domain Attack Chain
**Question**: Can behavioral differences across 12 implementations be exploited when systems interoperate (encrypt in lang A, decrypt in lang B)?

## Team Composition

| Role | Agent # | Agent File | Contribution |
|------|---------|-----------|-------------|
| Lead | 2 | `security-cross-language.md` | Catalog ALL behavioral divergences across 12 impls |
| Support | 4 | `security-input-validation.md` | Check which divergences affect security-critical paths |
| Support | 11 | `security-error-disclosure.md` | Check if errors differ per language (enables fingerprinting) |
| Support | 14 | `security-streaming-group.md` | Check streaming/group handling differences across langs |

## Coordination Flow

```
Agent 2: Exhaustive divergence catalog
    → Counter: Python increments, Rust=0 → same plaintext, different ciphertext
    → Padding validation: Rust MISSING (CVE-PENDING fix in 5 others, not Rust)
    → Constant-time: C/Java/C#/Swift use custom loops, others use library funcs
Agent 4: Which divergences create exploitable edge cases?
    → Encrypt in Python (counter=N), decrypt in Rust (expects counter=0) → fails?
    → Or succeeds silently with wrong keystream? Test this.
Agent 14: Do StreamCipher/GroupEncryption differ across languages?
    → Chunk handling, group key format, recipient list structure
Agent 11: Do error messages differ per language for same malformed input?
    → If yes: attacker can fingerprint which language is running
Joint verdict: Interop exploit matrix (lang A × lang B × input class)
```

## Known Evidence

- Counter mismatch: Python line 175-176 increments, Rust always 0
- Padding validation: Rust missing at line 300, all others have it
- Same key for enc+mac in ALL implementations (protocol specifies separation, none implement it)
- JS exports `generateKeystream()` — internal primitive exposed

## Expected Output

1. Interop exploit matrix (lang A × lang B × input class)
2. Language fingerprinting catalog (error message → language identification)
3. Silent failure catalog (encrypt in A, decrypt in B produces wrong plaintext)
4. Cross-references to Agents 2, 4, 11, 14 domain findings by ID

## Dedup Rule

Cross-domain finding REFERENCES domain finding by ID, never duplicates. If this chain escalates a MEDIUM domain finding to CRITICAL, the consolidated severity is CRITICAL.
