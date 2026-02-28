# Cross-Domain Team 10: Auth & Transport MITM Chain

**Priority**: HIGH
**Phase**: 5 (after Phase 3 — needs Agents 7, 8, 15, 16 findings)
**Type**: Cross-Domain Attack Chain
**Question**: Can an attacker combine authentication weakness with transport MITM to fully compromise a session, bypass device binding, and break forward secrecy?

## Team Composition

| Role | Agent # | Agent File | Contribution |
|------|---------|-----------|-------------|
| Lead | 8 | `security-transport-protocol.md` | Find PAKE/channel handshake weaknesses |
| Support | 7 | `security-auth-session.md` | Check if auth tokens/sessions affected by transport compromise |
| Support | 16 | `security-fingerprint.md` | Check if device binding can be spoofed post-MITM |
| Support | 15 | `security-signatures-2fa.md` | Check if signatures can be forged with compromised key |

## Coordination Flow

```
Agent 8: PAKE handshake analysis
    → Plaintext contributions during handshake → MITM interception
    → Non-constant-time counter comparison → timing attack
    → 16MB unbounded receive → DoS
Agent 7: Post-MITM auth exploitation
    → If session key compromised, are tokens still valid?
    → Rate limiter: does transport compromise bypass rate limiting?
    → TOTP: replay within same window after MITM capture?
Agent 16: Device rebinding after MITM
    → Fingerprint spoofable in VM/container (CWE-290)
    → MD5 collision-prone hash → fingerprint collision
    → If device binding bypassed + session key stolen → full impersonation
Agent 15: Signature forgery assessment
    → If HMAC key compromised via MITM, can attacker forge signatures?
    → Lamport: if key exposed, all future signatures forgeable
Joint verdict: Full MITM → session compromise → identity takeover chain
```

## Known Evidence

- PAKE handshake sends plaintext contributions (channel.rs)
- Fingerprint spoofable in containers (CWE-290)
- MD5 hash for fingerprinting (CWE-328)
- TOTP replay within ±1 window

## Expected Output

1. Full MITM → session compromise → identity takeover attack chain
2. Device binding bypass feasibility assessment
3. Forward secrecy breaking conditions
4. Cross-references to Agents 7, 8, 15, 16 domain findings by ID

## Dedup Rule

Cross-domain finding REFERENCES domain finding by ID, never duplicates. If this chain escalates a MEDIUM domain finding to CRITICAL, the consolidated severity is CRITICAL.
