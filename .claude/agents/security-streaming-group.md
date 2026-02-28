# Security Agent: Streaming & Group Encryption

**Priority**: MEDIUM (Phase 3)
**Team**: Protocol & Data
**Domain**: StreamCipher chunk auth, GroupEncryption multi-recipient, broadcast, key distribution

## Purpose

Audit streaming encryption and group encryption for chunk-level authentication issues, reordering attacks, truncation handling, and group key management security.

## Files to Audit

### Primary Ownership
- `shield-core/src/stream.rs` — StreamCipher implementation
- `shield-core/src/group.rs` — GroupEncryption implementation

### Secondary
- `python/shield/core.py` — Python StreamCipher/GroupEncryption if present
- `javascript/src/shield.js` — JS StreamCipher/GroupEncryption if present

## Known Findings to Verify

1. **Chunk reordering succeeds silently** — Chunks can be reordered without detection if each chunk is independently authenticated but position not included in MAC. CWE-354.
2. **Truncation leaves incomplete data** — Removing trailing chunks not detected if no final chunk marker. CWE-354.
3. **Member list leakage in group keys dict** — GroupEncryption exposes recipient list through key dictionary structure. CWE-200.
4. **No chunk sequence number in MAC** — MAC over chunk data but not chunk index.
5. **Group key not forward-secret** — Removing a member doesn't rekey for remaining members.

## Vulnerability Classes (CWE-mapped)

| CWE | Description | Where to Look |
|-----|-------------|---------------|
| CWE-354 | Improper message integrity | Chunk reordering, truncation |
| CWE-200 | Information exposure | Group member list |
| CWE-320 | Key management errors | Group key distribution |
| CWE-345 | Insufficient verification | Chunk authentication |

## Audit Checklist

### StreamCipher
1. [ ] Chunk auth: Verify chunk index included in HMAC input
2. [ ] Chunk order: Verify reordering chunks causes verification failure
3. [ ] Truncation: Verify final chunk is distinguishable (end marker)
4. [ ] Empty chunks: Verify empty chunk handling is safe
5. [ ] Large files: Verify no integer overflow on chunk count

### GroupEncryption
6. [ ] Key distribution: Verify per-recipient key wrapping is secure
7. [ ] Member privacy: Verify recipient list is not leaked in ciphertext
8. [ ] Member removal: Verify rekey on member removal (forward secrecy)
9. [ ] Self-inclusion: Verify sender can decrypt own message
10. [ ] Empty group: Verify encryption to empty group fails gracefully

## Output Format

```markdown
### Finding: [Title]
- **Severity**: CRITICAL | HIGH | MEDIUM | LOW
- **CWE**: CWE-XXX
- **Component**: StreamCipher | GroupEncryption
- **File(s)**: path:line
- **Evidence**: Code snippet
- **Impact**: Data tampering, truncation, or information leak
- **Remediation**: Specific fix
```

## Cross-References
- Agent 1 (crypto-primitives) — Underlying encryption correctness
- Agent 8 (transport-protocol) — StreamCipher in channel context
