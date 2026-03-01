---
name: skill-token-lifecycle-auditor
description: Audit the complete token lifecycle from creation through validation to revocation and expiry. Use when auditing authentication and session management.
---

# Token Lifecycle Auditor

Audit token creation → validation → revocation → expiry lifecycle.

## When to Use
- Auditing token-based authentication
- Checking session management security
- Reviewing Shield's IdentityProvider token handling

## Inputs
- Token implementation file(s)
- Token type (session, API key, auth token)

## Procedure
1. Locate token-related code:
   - `python/shield/identity.py`: IdentityProvider
   - `python/shield/integrations/token_auth.py`: ShieldTokenAuth
   - Other language identity implementations

2. Audit each lifecycle phase:

### Creation
| Check | Description |
|-------|-----------|
| Entropy | Token generated with CSPRNG? |
| Length | Sufficient entropy (≥128 bits)? |
| Format | Opaque or structured (JWT-like)? |
| Binding | Bound to user/session/IP? |
| Encryption | Token encrypted with Shield? |

### Validation
| Check | Description |
|-------|-----------|
| Constant-time | Token comparison timing-safe? |
| Expiry check | Is expiry verified on each use? |
| Signature/MAC | Integrity verified? |
| Scope check | Token scope matches requested action? |
| Replay | Same token reusable? |

### Revocation
| Check | Description |
|-------|-----------|
| Mechanism | Can tokens be revoked? |
| Propagation | Revocation takes effect immediately? |
| Server-side | Server maintains revocation list? |
| All tokens | Can all user tokens be revoked? |

### Expiry
| Check | Description |
|-------|-----------|
| Max lifetime | Reasonable maximum age? |
| Sliding | Does usage extend expiry? |
| Absolute | Hard expiry regardless of usage? |
| Refresh | Refresh token mechanism? |

3. Map complete flow and identify gaps

## Output Format
```
### Token Lifecycle Audit
| Phase | Check | Status | Risk | Notes |
|-------|-------|--------|------|-------|
| Create | CSPRNG | ✓ | — | Uses secrets.token_hex |
| Create | Length | ✓ | — | 256 bits |
| Validate | Const-time | ✗ | High | Uses == comparison |
| Revoke | Mechanism | ✗ | Medium | No revocation support |
...
```

## Used By
- A7 (Auth & Session), T10 (Auth Transport MITM)
