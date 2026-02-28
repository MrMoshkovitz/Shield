# Cross-Domain Team 9: Key Lifecycle & Exposure Chain

**Priority**: CRITICAL
**Phase**: 5 (after Phase 3 — needs Agents 3, 7, 9, 12, 13 findings)
**Type**: Cross-Domain Attack Chain
**Question**: Can keys be extracted from ANY point in their lifecycle — derivation, storage, memory, API accessor, transport — and used to forge or decrypt?

## Team Composition

| Role | Agent # | Agent File | Contribution |
|------|---------|-----------|-------------|
| Lead | 3 | `security-memory-safety.md` | Map complete key lifecycle: creation → usage → zeroization |
| Support | 12 | `security-mobile-platform.md` | Check mobile key storage (Keystore, Keychain) |
| Support | 9 | `security-browser-wasm.md` | Check browser/WASM key handling + BrowserBridge |
| Support | 7 | `security-auth-session.md` | Check session/token key management |
| Support | 13 | `security-confidential-tee.md` | Check TEE sealed key protection |

## Coordination Flow

```
Agent 3: Map key lifecycle across ALL implementations
    → Rust: Zeroize + ZeroizeOnDrop (good)
    → Python/JS/Go/Java/C#: NO zeroization (GC dependent)
    → ALL: .key() accessor exposes raw 32-byte material
Agent 12: Mobile key storage assessment
    → Android Keystore: is it hardware-backed?
    → iOS Keychain: what access level? kSecAttrAccessibleWhenUnlocked?
Agent 9: Browser key lifecycle
    → BrowserBridge returns unsigned key response → MITM can inject
    → WASM linear memory inspectable by JS on same page
    → Key stored in JS variable → accessible to extensions/XSS
Agent 7: Session/token key exposure
    → Tokens contain encrypted payloads — if key leaked, all tokens forged
    → Rate limiter bypass resets on decrypt error — key not needed
Agent 13: TEE sealed storage
    → Attestation report replay → extract sealed key?
    → Cross-TEE evidence format confusion
Joint verdict: Full key exposure surface map with attack tree
```

## Known Evidence

- `.key()` accessor available in ALL implementations (shield.rs:381)
- Zero zeroization in Python, JS, Go, Java, C# (GC-dependent)
- BrowserBridge key responses unsigned (browser.py:71-101)
- WASM linear memory inspectable by JS

## Expected Output

1. Full key exposure surface map (lifecycle stage × platform × attack vector)
2. Key extraction attack tree with complexity estimates
3. Remediation priorities: zeroization, accessor removal, transport signing
4. Cross-references to Agents 3, 7, 9, 12, 13 domain findings by ID

## Dedup Rule

Cross-domain finding REFERENCES domain finding by ID, never duplicates. If this chain escalates a MEDIUM domain finding to CRITICAL, the consolidated severity is CRITICAL.
