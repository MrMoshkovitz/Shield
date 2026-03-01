# A08 Transport Protocol Security Audit

**Agent**: Security-Transport-Protocol | **Priority**: HIGH | **Findings**: 4 MEDIUM

## SHIELD-A08-001: Missing Async Handshake Timeout Enforcement

- **Severity**: MEDIUM | **CWE**: CWE-400
- **File(s)**: channel_async.rs:128-168, 174-218
- **Evidence**: handshake_timeout_ms configured but never applied. No tokio::time::timeout() wrapper on recv_handshake/send_confirmation during handshake.
- **Impact**: Indefinite hang DoS on async server via slow/non-responsive handshake.
- **Remediation**: Wrap handshake operations with tokio::time::timeout(config.handshake_timeout_ms()).

## SHIELD-A08-002: Non-Standard PAKE Lacks RFC Reference
- **Severity**: MEDIUM | **CWE**: CWE-327
- **File(s)**: exchange.rs:20-57, channel.rs:155-174
- **Evidence**: PBKDF2 + role-labeled SHA256 + byte-sort combine(). Not SPAKE2/OPAQUE. Offline dictionary attack possible if salt weak.
- **Impact**: Non-standard protocol lacking formal security analysis. Lacks exponential blinding. High risk with user weak passwords.
- **Remediation**: Document design rationale. Recommend SPAKE2-ED25519 or OPAQUE for production deployments.

## SHIELD-A08-003: 16MB Message Size Limit Allows Large DoS Allocations
- **Severity**: MEDIUM | **CWE**: CWE-400
- **File(s)**: channel.rs:41-42, 452-456, channel_async.rs:43-44, 386-390
- **Evidence**: MAX_MESSAGE_SIZE = 16 MB. Receiver allocates full buffer: vec![0u8; len] without rate limiting.
- **Impact**: Memory exhaustion on constrained devices. Single large message per connection = 16 MB allocation.
- **Remediation**: (1) Reduce default to 4-8 MB. (2) Make MAX_MESSAGE_SIZE configurable. (3) Add per-connection rate-limiting.

## SHIELD-A08-004: Configuration Timeout Field Unused
- **Severity**: MEDIUM | **CWE**: CWE-347
- **File(s)**: channel.rs:78, 91-93, 53-115
- **Evidence**: with_timeout() allows setting handshake_timeout_ms but (1) no public getter, (2) never used in sync or async channels.
- **Impact**: Developer expects timeout enforcement but it is silently ignored. Security misconfiguration.
- **Remediation**: Add public getter. Implement timeout enforcement in AsyncShieldChannel. Document limitation for sync channel.

---

## Verified Design ✅

**MITM (CWE-300)**: NOT FOUND - HMAC confirmations + password-key prevent blind MITM
**Timing side-channel (CWE-208)**: NOT FOUND - Counter is plaintext; timing not applicable
**Missing mutual auth (CWE-287)**: NOT FOUND - HMAC confirmations with constant-time verification verified
**Unbounded receive (CWE-400)**: PARTIAL - Limit enforced but 16MB is large (see A08-003)
**Replay protection (CWE-294)**: NOT FOUND - Strict monotonic counter rejects replays. Test confirmed.

**RatchetSession Forward Secrecy**: Zeroize trait on chain keys. Old keys destroyed after ratchet. PASS ✅
**Replay Detection**: Monotonic recv_counter. Out-of-order messages rejected. test_ratchet_replay_detection confirmed. PASS ✅

---

**TASK-2-014 COMPLETE** — 4 MEDIUM findings
TASK-2-015 FINDINGS DOCUMENTED - 3 MEDIUM, 1 LOW on RatchetSession key zeroization issues
TASK-2-016 FINDINGS: Counter overflow handling missing (MEDIUM), V2 timestamp protection not implemented (LOW). 2 additional findings documented.

---

## PHASE 2 PROGRESS UPDATE

**ITERATION 28 SUMMARY**: Completed TASK-2-015 (RatchetSession, 4 findings) + TASK-2-016 (Counter Replay, 2 findings)
