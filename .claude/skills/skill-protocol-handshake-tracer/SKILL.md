---
name: skill-protocol-handshake-tracer
description: Trace ShieldChannel handshake flow, identify MITM opportunities, and verify mutual authentication in the transport protocol. Use when auditing secure transport.
---

# Protocol Handshake Tracer

Trace the ShieldChannel/AsyncShieldChannel handshake flow to identify MITM attack vectors.

## When to Use
- Auditing ShieldChannel transport protocol security
- Checking for MITM opportunities in key exchange
- Reviewing PAKE + RatchetSession handshake flow

## Inputs
- Rust source: `shield-core/src/` (ShieldChannel, AsyncShieldChannel)
- Protocol scope: "handshake" | "ratchet" | "full"

## Procedure
1. Locate transport protocol files:
   - `ShieldChannel` implementation
   - `AsyncShieldChannel` implementation
   - `ChannelConfig` (password, service, iterations, timeout)
   - `RatchetSession` (forward secrecy)

2. Trace handshake steps:

### Handshake Flow Analysis
| Step | What Happens | What to Check |
|------|-------------|---------------|
| 1. Init | Channel creation with password | Password strength enforced? |
| 2. PAKE | Password-authenticated key exchange | Which PAKE variant? Verified? |
| 3. Key derivation | Shared secret -> session keys | PBKDF2 params correct? |
| 4. Authentication | Mutual auth of peers | Both sides verified? |
| 5. Ratchet init | Forward secrecy setup | Ratchet properly initialized? |
| 6. Data transfer | Encrypted messages | Per-message auth? Counter? |

### MITM Attack Vectors
| Vector | Check | Risk |
|--------|-------|------|
| No server auth | Client doesn't verify server | Critical |
| No client auth | Server doesn't verify client | High |
| Replay attack | No nonce/timestamp in handshake | Critical |
| Downgrade | Protocol version negotiation | High |
| PAKE offline attack | Weak password allows offline brute-force | Medium |
| Ratchet skip | Messages accepted out of order | Medium |
| Timeout abuse | Long timeout allows slow attacks | Low |

### Forward Secrecy Checks
| Check | What to Verify |
|-------|---------------|
| Key ratchet | New keys derived per message/epoch |
| Old key deletion | Previous keys zeroized |
| Counter tracking | Message counter prevents replay |
| Chain separation | Send/receive chains independent |

3. Verify `ChannelConfig` defaults:
   - Password minimum strength
   - PBKDF2 iterations (should be >= 100,000)
   - Timeout value (not too long)
   - Service identifier uniqueness

## Output Format
```
### Protocol Handshake Trace
| Step | Component | Security | Status |
|------|-----------|----------|--------|
| 1 | PAKE init | Mutual auth | PASS/FAIL |
...

**MITM Risk**: Low/Medium/High/Critical
**Forward Secrecy**: Yes/Partial/No
```

## Used By
- A08 (Transport Protocol)
- T10 (Auth Transport MITM)
