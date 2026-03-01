# A08 Transport Protocol Security Audit

**Agent**: Security-Transport-Protocol | **Priority**: HIGH
**Date**: 2026-03-02 | **Last Updated**: 2026-03-02T09:30:00+03:00
**Files Audited**: `shield-core/src/channel.rs`, `shield-core/src/channel_async.rs`, `shield-core/src/exchange.rs`, `shield-core/src/ratchet.rs`
**Findings**: 13 (0 CRITICAL, 3 HIGH, 6 MEDIUM, 3 LOW, 1 INFO)

---

## SHIELD-A08-001: Handshake Timeout Not Enforced — Indefinite Blocking DoS
- **Tag**: VERIFIED
- **Severity**: HIGH | **CWE**: CWE-400
- **Location**: `channel.rs:63,197-237,246-291`, `channel_async.rs:128-168,174-218`
- **Evidence**:
  ```rust
  // channel.rs:63 — timeout stored but NEVER used
  pub struct ChannelConfig {
      handshake_timeout_ms: u64,  // Set by with_timeout() but never read
  }
  // channel.rs:197 — connect() blocks indefinitely via read_exact()
  // No set_read_timeout(). No tokio::time::timeout() in async variant.
  ```
- **Impact**: Slowloris-style DoS. Attacker sends ClientHello then stalls — server thread blocks forever. Async version also lacks tokio::time::timeout wrapping. All server resources exhausted.
- **Reproduction**: Connect, send 16-byte ClientHello, never send more data. Server hangs permanently.
- **Fix Complexity**: LOW
- **Remediation**: Sync: call `stream.set_read_timeout()` before handshake. Async: wrap with `tokio::time::timeout(Duration::from_millis(config.handshake_timeout_ms), ...)`. Add public getter for timeout value.

---

## SHIELD-A08-002: Non-Standard PAKE — No Formal Security Proof
- **Tag**: VERIFIED
- **Severity**: MEDIUM | **CWE**: CWE-327
- **Location**: `exchange.rs:20-57`, `channel.rs:147-174`
- **Evidence**:
  ```rust
  // Custom PAKE: PBKDF2 + role-labeled SHA256 + byte-sort combine()
  // NOT SPAKE2, OPAQUE, SRP, or any standardized PAKE protocol
  // No exponential blinding — contributions are raw PBKDF2 outputs
  ```
- **Impact**: Custom protocol lacks formal security analysis. Offline dictionary attack possible if contributions are observed (though password_key mixing provides protection). Not suitable for high-security deployments without formal review.
- **Reproduction**: Protocol inspection reveals non-standard design.
- **Fix Complexity**: HIGH
- **Remediation**: Document design rationale. For production: consider SPAKE2 or OPAQUE. At minimum, get formal review of the custom PAKE construction.

---

## SHIELD-A08-003: 16MB Allocation from Untrusted Frame Length — Remote Memory Exhaustion
- **Tag**: VERIFIED
- **Severity**: HIGH | **CWE**: CWE-400
- **Location**: `channel.rs:446-464`, `channel_async.rs:379-400`
- **Evidence**:
  ```rust
  // channel.rs:452-459
  fn read_frame(stream: &mut S) -> Result<Vec<u8>> {
      let len = u32::from_be_bytes(len_buf) as usize;
      if len > MAX_MESSAGE_SIZE { return Err(...); } // MAX_MESSAGE_SIZE = 16MB
      let mut data = vec![0u8; len]; // Allocates up to 16MB from remote input
  ```
  Identical in `channel_async.rs:386-398`.
- **Impact**: Remote attacker sends `len=16777216` frames to force 16MB allocation each. Repeated rapidly → OOM. Post-handshake — no authentication needed to reach this code path once handshake is complete.
- **Reproduction**: Complete handshake, then send 4 bytes `0x01000000` (16MB), repeat rapidly.
- **Fix Complexity**: LOW
- **Remediation**: Reduce MAX_MESSAGE_SIZE to ~1MB. Make configurable. Add per-connection byte budget. Use incremental read buffer.

---

## SHIELD-A08-004: PAKE CPU DoS — 400k PBKDF2 Iterations Before Authentication
- **Tag**: VERIFIED
- **Severity**: HIGH | **CWE**: CWE-400, CWE-300
- **Location**: `channel.rs:200-230,246-284`
- **Evidence**:
  ```rust
  // channel.rs:260 — Server derives contribution (200k iterations)
  state.derive_contribution(config);
  // ...
  // channel.rs:279 — Server computes session key (another 200k iterations)
  let session_key = state.compute_session_key(config)?;
  // compute_session_key calls PAKEExchange::derive() again (200k more iterations)

  // channel.rs:283-284 — ONLY NOW does server verify authentication
  Self::verify_confirmation(&mut stream, &session_key, true)?;
  ```
  Any unauthenticated client forces server to spend ~400,000 PBKDF2-SHA256 iterations before discovering wrong password. Combined with SHIELD-A08-001 (no timeout), enables sustained CPU drain.
- **Impact**: CPU exhaustion DoS. Each fake connection costs ~400k PBKDF2 iterations on server. 10 connections/sec = sustained 100% CPU utilization.
- **Reproduction**: Connect, send valid-format ClientHello (16 random bytes), receive ServerHello, send any 32 bytes as Finished. Server computes 400k PBKDF2 before failing at confirmation. Repeat.
- **Fix Complexity**: MEDIUM
- **Remediation**: Add connection rate limiting per IP. Consider a proof-of-work step before PBKDF2. Or: send confirmation BEFORE expensive derivation using a cheaper pre-auth check.

---

## SHIELD-A08-005: Service Name Not in Session Key — Cross-Protocol Attack
- **Tag**: VERIFIED
- **Severity**: MEDIUM | **CWE**: CWE-346
- **Location**: `channel.rs:147-174`
- **Evidence**:
  ```rust
  // compute_session_key() does NOT include config.service:
  let password_key = PAKEExchange::derive(
      &config.password, &self.salt,
      "session",  // Fixed role label, NOT config.service
      Some(config.iterations),
  );
  ```
  Test `test_different_services_same_password` (line 710) acknowledges: different services with same password produce identical session keys.
- **Impact**: Same password used for "banking" and "chat" services → sessions are cryptographically identical. MITM can redirect traffic between services.
- **Fix Complexity**: LOW
- **Remediation**: Include `config.service` in session key derivation: `format!("session:{}", config.service)`.

---

## SHIELD-A08-006: Ratchet Counter Comparison Not Constant-Time + Leaks Expected Value
- **Tag**: VERIFIED
- **Severity**: MEDIUM | **CWE**: CWE-208, CWE-209
- **Location**: `ratchet.rs:87-91`
- **Evidence**:
  ```rust
  if counter != self.recv_counter {
      return Err(ShieldError::RatchetError(format!(
          "out of order message: expected {}, got {}",
          self.recv_counter, counter  // Leaks expected counter value
      )));
  }
  ```
- **Impact**: (1) Timing leak — `!=` not constant-time. (2) Error message reveals expected counter — enables state recovery.
- **Fix Complexity**: LOW
- **Remediation**: Use `subtle::ConstantTimeEq` on counter bytes. Generic error: "replay protection failed".

---

## SHIELD-A08-007: Ratchet Key Reuse for Encryption and Authentication
- **Tag**: VERIFIED
- **Severity**: MEDIUM | **CWE**: CWE-323
- **Location**: `ratchet.rs:145-188`
- **Evidence**:
  ```rust
  // ratchet.rs:157-167 — msg_key for keystream
  hash_input.extend_from_slice(key);
  // ratchet.rs:177 — SAME msg_key for HMAC
  let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
  ```
  Same `msg_key` for both XOR encryption and HMAC authentication.
- **Impact**: Same systemic key reuse as SHIELD-A01-001 but in ratchet subsystem. Best practice mandates separate enc/mac keys.
- **Fix Complexity**: LOW
- **Remediation**: Derive `enc_key = SHA256(msg_key || "enc")`, `mac_key = SHA256(msg_key || "mac")`. Cross-ref: SHIELD-A01-001.

---

## SHIELD-A08-008: PAKEExchange::derive() Panics on iterations=0
- **Tag**: VERIFIED
- **Severity**: MEDIUM | **CWE**: CWE-252, CWE-755
- **Location**: `exchange.rs:26`
- **Evidence**:
  ```rust
  NonZeroU32::new(iters).unwrap()  // PANICS if iters == 0
  ```
  ```rust
  // channel.rs:84-86 — Public API allows 0
  pub fn with_iterations(mut self, iterations: u32) -> Self {
      self.iterations = iterations;  // No validation
  ```
- **Impact**: `ChannelConfig::new("pw","svc").with_iterations(0)` → panic → DoS.
- **Fix Complexity**: LOW
- **Remediation**: Validate `iterations >= 1` (or minimum 10,000) in `with_iterations()`. Return `Result` instead of unwrap.

---

## SHIELD-A08-009: ChannelConfig Password Not Zeroized
- **Tag**: VERIFIED
- **Severity**: MEDIUM | **CWE**: CWE-316
- **Location**: `channel.rs:54-64`
- **Evidence**:
  ```rust
  #[derive(Clone)]  // Clone copies password, no Zeroize
  pub struct ChannelConfig {
      password: String,  // Plaintext, persists after handshake
  ```
- **Impact**: Password persists in memory after channel is established. Memory dumps expose shared secret. Cross-ref: SHIELD-A03-001.
- **Fix Complexity**: LOW
- **Remediation**: Add `Zeroize`/`ZeroizeOnDrop` to `ChannelConfig`. Zeroize `HandshakeState` intermediates.

---

## SHIELD-A08-010: QRExchange Exposes Raw Key in Base64
- **Tag**: VERIFIED
- **Severity**: MEDIUM | **CWE**: CWE-200
- **Location**: `exchange.rs:79-80,92-98`
- **Evidence**:
  ```rust
  pub fn encode(key: &[u8]) -> String { URL_SAFE_NO_PAD.encode(key) }
  // Also: serde_json::to_string(&data).unwrap()  // unwrap in public API
  ```
- **Impact**: QR code IS the key in base64. Anyone who sees/scans it has the full key.
- **Fix Complexity**: MEDIUM
- **Remediation**: Encrypt exchange data with PIN/passphrase. Add time-based expiry. Replace unwrap with Result.

---

## SHIELD-A08-011: Handshake Error Messages Leak Protocol State
- **Tag**: VERIFIED
- **Severity**: LOW | **CWE**: CWE-209
- **Location**: `channel.rs:364-375`, `ratchet.rs:88-91`
- **Evidence**:
  ```rust
  // Leaks protocol version, expected/received message type
  format!("unsupported protocol version: {}", header[0])
  format!("unexpected message type: expected {}, got {}", expected_type as u8, header[1])
  // Leaks expected/received counter values
  format!("out of order message: expected {}, got {}", self.recv_counter, counter)
  ```
- **Impact**: Protocol fingerprinting, state recovery. Cross-ref: A11 error disclosure agent.
- **Fix Complexity**: LOW
- **Remediation**: Generic error messages. Log details server-side only.

---

## SHIELD-A08-012: KeySplitter XOR-Only — No Threshold Scheme
- **Tag**: VERIFIED
- **Severity**: LOW | **CWE**: CWE-330
- **Location**: `exchange.rs:117-161`
- **Evidence**: Simple XOR split requires ALL shares. No Shamir's SSS (k-of-n). Loss of any single share = permanent key loss. Tampered shares produce wrong key silently (no share authentication).
- **Impact**: Operational risk in enterprise key management. No redundancy.
- **Fix Complexity**: MEDIUM
- **Remediation**: Document clearly that ALL shares required. Consider SSS for k-of-n. Add share authentication.

---

## SHIELD-A08-013: Async Channel Duplicates Sync Logic — Divergence Risk
- **Tag**: VERIFIED
- **Severity**: LOW | **CWE**: CWE-710
- **Location**: `channel_async.rs:56-113` vs `channel.rs:118-175`
- **Evidence**: `AsyncShieldChannel` duplicates HandshakeState, derive_contribution, compute_session_key, all constants. 618 lines of nearly-identical code. Security fix to one may miss the other.
- **Impact**: Future security patches may not be consistently applied to both implementations.
- **Fix Complexity**: MEDIUM
- **Remediation**: Extract shared types (HandshakeState, compute_session_key, constants) into common module.

---

## SHIELD-A08-014: Ratchet Forward Secrecy Verified Correct
- **Tag**: NON-VULN
- **Severity**: INFO | **CWE**: N/A
- **Location**: `ratchet.rs:23-109`
- **Evidence**: `#[derive(Zeroize, ZeroizeOnDrop)]` on RatchetSession. Chain advances on each encrypt/decrypt. Old chain keys overwritten (zeroized). Strict monotonic counter for replay protection. Constant-time MAC verification via `ct_eq`. Separate send/recv chains.
- **Impact**: N/A — forward secrecy mechanism is sound.
- **Verification Notes**: Core ratchet mechanism verified correct. Chain derivation, key advancement, zeroization, counter enforcement, MAC comparison all verified.

---

## Summary

| Severity | Count | IDs |
|----------|-------|-----|
| CRITICAL | 0 | — |
| HIGH | 3 | A08-001, A08-003, A08-004 |
| MEDIUM | 7 | A08-002, A08-005, A08-006, A08-007, A08-008, A08-009, A08-010 |
| LOW | 3 | A08-011, A08-012, A08-013 |
| INFO | 1 | A08-014 |
| **Total** | **14** | |

## Checklist Status

1. [x] Handshake: Contributions in plaintext (by design for PAKE), HMAC confirmation verifies — A08-004
2. [x] PAKE: Custom symmetric PAKE, password binding via confirmation — A08-002, A08-005
3. [x] Mutual auth: Confirmation messages verify both sides — working correctly
4. [x] Message framing: 16MB limit — too high — A08-003
5. [x] Ratchet counter: NOT constant-time — A08-006
6. [x] Ratchet replay: Strict monotonic counter enforced — correct — A08-014
7. [x] Forward secrecy: Chain keys zeroized on ratchet step — correct — A08-014
8. [x] Async timeout: NO timeout enforcement — A08-001
9. [x] Channel config: Timeout unused, iterations configurable to 0 — A08-001, A08-008

## Cross-References

| Finding | Related |
|---------|--------|
| A08-007 | SHIELD-A01-001 (systemic key reuse enc+MAC) |
| A08-009 | SHIELD-A03-001 (systemic zeroization gaps) |
| A08-011 | A11 (error disclosure) |
| A08-006 | SHIELD-A01-020 (non-constant-time comparisons) |
