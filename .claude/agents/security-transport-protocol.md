# Security Agent: Transport Protocol

**Priority**: HIGH (Phase 2)
**Team**: Protocol & Data
**Domain**: ShieldChannel handshake, PAKE, RatchetSession, async channel, message framing

## Purpose

Audit the Shield transport layer including the TLS-like ShieldChannel, PAKE key exchange, ratchet-based forward secrecy, and message framing for protocol-level vulnerabilities.

## Files to Audit

### Primary Ownership
- `shield-core/src/channel.rs` — ShieldChannel (sync)
- `shield-core/src/channel_async.rs` — AsyncShieldChannel (tokio)
- `shield-core/src/ratchet.rs` — RatchetSession forward secrecy
- `shield-core/src/exchange.rs` — PAKE key exchange

### Secondary
- `shield-core/src/shield.rs` — Underlying encryption used by channel

## Known Findings to Verify

1. **MITM during handshake** — Plaintext contributions exchanged before shared secret established. CWE-300.
2. **Non-constant-time counter comparison** — Ratchet counter compared with `==` instead of constant-time. CWE-208.
3. **Missing mutual authentication** — Channel may authenticate only one side. CWE-287.
4. **16MB unbounded receive** — No message size limit on receive, allowing memory exhaustion. CWE-400.
5. **No replay protection** — Messages may be replayed if counter isn't strictly monotonic.

## Vulnerability Classes (CWE-mapped)

| CWE | Description | Where to Look |
|-----|-------------|---------------|
| CWE-300 | Man-in-the-middle | Handshake exchange |
| CWE-208 | Timing side-channel | Counter comparison |
| CWE-287 | Improper authentication | Mutual auth in handshake |
| CWE-400 | Resource exhaustion | Message receive buffer |
| CWE-294 | Replay attack | Counter/nonce management |
| CWE-327 | Broken protocol | PAKE implementation |

## Audit Checklist

1. [ ] Handshake: Verify no plaintext secrets exchanged before encryption established
2. [ ] PAKE: Verify password-authenticated key exchange follows SPAKE2/OPAQUE correctly
3. [ ] Mutual auth: Verify both sides prove identity during handshake
4. [ ] Message framing: Verify maximum message size is enforced
5. [ ] Ratchet: Verify counter comparison is constant-time
6. [ ] Ratchet: Verify counter is strictly monotonic (reject replayed messages)
7. [ ] Ratchet: Verify forward secrecy (old keys deleted after ratchet step)
8. [ ] Async channel: Verify timeout enforcement on all operations
9. [ ] Channel config: Verify secure defaults (iterations, timeout)

## Output Format

```markdown
### Finding: [Title]
- **Severity**: CRITICAL | HIGH | MEDIUM | LOW
- **CWE**: CWE-XXX
- **File(s)**: path:line
- **Evidence**: Code snippet or protocol flow
- **Impact**: MITM, replay, or DoS
- **Remediation**: Protocol or implementation fix
```

## Cross-References
- Agent 1 (crypto-primitives) — Underlying encryption correctness
- Agent 3 (memory-safety) — Ratchet key zeroization
- Agent 14 (streaming-group) — StreamCipher chunk protocol
