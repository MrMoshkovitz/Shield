# Cross-Domain Team 6: Crypto Oracle & Error Leakage

**Priority**: CRITICAL
**Phase**: 4 (after Phase 2 — needs Agents 1, 4, 6, 11 findings)
**Type**: Cross-Domain Attack Chain
**Question**: Can error messages, timing, or middleware behavior leak enough crypto state to enable an adaptive chosen-ciphertext attack?

## Team Composition

| Role | Agent # | Agent File | Contribution |
|------|---------|-----------|-------------|
| Lead | 1 | `security-crypto-primitives.md` | Assess feasibility of oracle attack from leaked info |
| Support | 11 | `security-error-disclosure.md` | Catalog all error messages revealing crypto state |
| Support | 6 | `security-web-integration.md` | Check which errors are network-reachable via middleware |
| Support | 4 | `security-input-validation.md` | Check which malformed inputs trigger distinguishable errors |

## Coordination Flow

```
Agent 11: Catalog all decrypt error messages across 12 impls
    → Which reveal: MAC failure vs padding error vs format error?
Agent 6: Check middleware error propagation paths
    → Flask: except Exception: pass (SILENT BYPASS)
    → Express: returns err.message (INFO LEAK)
    → FastAPI: raises HTTPException with detail string
Agent 4: Craft malformed inputs that trigger each error class
    → pad_len=0, pad_len=255, truncated MAC, wrong version byte
Agent 1: Given distinguishable errors, assess oracle attack feasibility
    → Can attacker recover plaintext via adaptive queries?
    → Output: feasibility matrix + proof-of-concept if viable
```

## Known Evidence

- Flask `except Exception: pass` silently drops decrypt failures → route gets None
- Express `res.status(400).json({error: err.message})` → leaks error details
- FastAPI `HTTPException(detail=f"Decryption failed: {e}")` → leaks exception type
- Rust missing padding validation → different error path than other 11 impls

## Expected Output

1. Error oracle feasibility matrix (error class × middleware × exploitability)
2. Proof-of-concept if viable (adaptive chosen-ciphertext attack)
3. Remediation: unified error responses across all middleware
4. Cross-references to Agent 11 domain findings by ID

## Dedup Rule

Cross-domain finding REFERENCES domain finding by ID, never duplicates. If this chain escalates a MEDIUM domain finding to CRITICAL, the consolidated severity is CRITICAL.
