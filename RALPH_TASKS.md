# Ralph-Loop Master Task Plan

> **State Machine**: Each Ralph iteration reads this file first, finds the next PENDING task, executes it, and updates status.
> **Version**: 1.0 | **Total Tasks**: 66 | **Created**: 2026-03-01

## Status Legend

| Symbol | Meaning |
|--------|---------|
| `[ ]` | PENDING — not started |
| `[~]` | IN-PROGRESS — currently executing |
| `[x]` | DONE — completed with findings written |
| `[!]` | BLOCKED — dependency not met |
| `[R]` | RESUME — partially done, continue next iteration |

## Ralph Loop Protocol

```
1. Read RALPH_STATE.md for resume point
2. Read this file (RALPH_TASKS.md)
3. Find next task: first RESUME [R], then first PENDING [ ] with all deps DONE
4. Set task status → [~] IN-PROGRESS, update RALPH_STATE.md
5. Read agent/team file + SHIELD_SECURITY_CONTEXT.md
6. Execute task using specified skills
7. Write findings to output file
8. Update findings/SECURITY_REPORT.md with new findings
9. Set task status → [x] DONE, update findings count
10. If token limit approaching → set status → [R] RESUME, save progress, exit
11. Loop to step 3
```

---

## PHASE 0: SETUP

### TASK-0-001: Verify Directory Structure & Reference Files
- **Status**: [ ] PENDING
- **Agent/Team**: Orchestrator
- **Phase**: 0 (SETUP)
- **Priority**: CRITICAL
- **Depends On**: None
- **Input Files**: `CLAUDE.md`, `.GM/SHIELD_SECURITY_CONTEXT.md`, `.GM/agent-map.md`, `.GM/agent-teams-map.md`, `.GM/skills-map.md`
- **Output Files**: None (verification only)
- **Skills**: `/skill-shield-file-navigator`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Verify all 16 agent files exist in `.claude/agents/`, all 7 team files exist, `findings/agents/` and `findings/teams/` directories exist, all reference files are readable.

### TASK-0-002: Create Report Skeleton & State Files
- **Status**: [x] DONE
- **Agent/Team**: Orchestrator
- **Phase**: 0 (SETUP)
- **Priority**: CRITICAL
- **Depends On**: None
- **Input Files**: `CLAUDE.md`
- **Output Files**: `RALPH_TASKS.md`, `RALPH_STATE.md`, `findings/SECURITY_REPORT.md`
- **Skills**: None
- **Started**: 2026-03-01T00:00:00+03:00
- **Completed**: 2026-03-01T00:00:00+03:00
- **Findings Count**: 0
- **Notes**: This task — creating the execution infrastructure.

### TASK-0-003: Verify Agent & Skill File Accessibility
- **Status**: [ ] PENDING
- **Agent/Team**: Orchestrator
- **Phase**: 0 (SETUP)
- **Priority**: HIGH
- **Depends On**: TASK-0-001
- **Input Files**: `.claude/agents/security-*.md`, `.claude/agents/team-*.md`
- **Output Files**: None (verification only)
- **Skills**: `/skill-shield-file-navigator`, `/skill-audit-progress-tracker`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Read each agent file header to confirm it loads correctly. Verify skills can be invoked.

---

## PHASE 1: CRYPTO CORE (BLOCKING)

> **BLOCKING**: ALL Phase 1 tasks must be DONE before ANY Phase 2 task starts.
> Agents 1, 2, 3 CAN run in parallel within Phase 1.

### Agent 1: Crypto Primitives (A01)

### TASK-1-001: A01 PBKDF2 Parameter Audit Across All Languages
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 1 — Crypto Primitives
- **Phase**: 1
- **Priority**: CRITICAL
- **Depends On**: TASK-0-001
- **Input Files**: `.claude/agents/security-crypto-primitives.md`, `shield-core/src/shield.rs`, `python/shield/core.py`, `javascript/src/shield.js`, `go/shield/shield.go`, `c/src/shield.c`, `java/**/Shield.java`, `csharp/Shield/Shield.cs`, `swift/**/Shield.swift`, `kotlin/**/Shield.kt`
- **Output Files**: `findings/agents/A01-crypto-primitives.md`
- **Skills**: `/skill-pbkdf2-param-auditor`, `/skill-multi-lang-symbol-scanner`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Verify 100k iterations, SHA256 hash, 32-byte output, salt = SHA256("shield:" + service) across ALL 12 languages. Check for hardcoded vs configurable iterations. Verify NonZeroU32 unwrap safety in Rust.

### TASK-1-002: A01 SHA256-CTR Mode Verification Across All Languages
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 1 — Crypto Primitives
- **Phase**: 1
- **Priority**: CRITICAL
- **Depends On**: TASK-0-001
- **Input Files**: Same as TASK-1-001
- **Output Files**: `findings/agents/A01-crypto-primitives.md`
- **Skills**: `/skill-ctr-mode-verifier`, `/skill-multi-lang-symbol-scanner`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Verify counter initialization (0 vs incrementing — Python increments, Rust doesn't per recon), endianness, overflow handling, XOR application. Check keystream = SHA256(key || nonce || counter++) pattern. Flag O(n^2) Buffer.concat in JavaScript (shield.js:39).

### TASK-1-003: A01 HMAC-SHA256 MAC Verification Audit
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 1 — Crypto Primitives
- **Phase**: 1
- **Priority**: CRITICAL
- **Depends On**: TASK-0-001
- **Input Files**: Same as TASK-1-001
- **Output Files**: `findings/agents/A01-crypto-primitives.md`
- **Skills**: `/skill-mac-verification-auditor`, `/skill-multi-lang-symbol-scanner`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Verify MAC = HMAC-SHA256(key, nonce || ciphertext)[0:16]. Verify 128-bit truncation is consistent. Check MAC coverage (does it cover nonce?). Verify constant-time comparison in ALL languages. Flag key separation violation: same key for encryption and MAC (PROTOCOL.md says mac_key = SHA256(master_key || "mac") but no implementation follows this).

### TASK-1-004: A01 Nonce Generation Audit Across All Languages
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 1 — Crypto Primitives
- **Phase**: 1
- **Priority**: CRITICAL
- **Depends On**: TASK-0-001
- **Input Files**: Same as TASK-1-001
- **Output Files**: `findings/agents/A01-crypto-primitives.md`
- **Skills**: `/skill-nonce-generation-auditor`, `/skill-multi-lang-symbol-scanner`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Verify CSPRNG usage in all 12 languages. Check C uses /dev/urandom with proper error handling (single read, no retry on EINTR). Check WASM uses getrandom with js feature. Verify 16-byte nonce size everywhere.

### TASK-1-005: A01 Key Separation & Constant-Time Operations
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 1 — Crypto Primitives
- **Phase**: 1
- **Priority**: CRITICAL
- **Depends On**: TASK-0-001
- **Input Files**: Same as TASK-1-001
- **Output Files**: `findings/agents/A01-crypto-primitives.md`
- **Skills**: `/skill-constant-time-verifier`, `/skill-cross-lang-constant-audit`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: CRITICAL — verify key separation (or lack thereof) in ALL implementations. Document that same 32-byte key used for both XOR encryption and HMAC. Verify constant-time MAC comparison: Rust (subtle::ConstantTimeEq), Python (hmac.compare_digest), JS (crypto.timingSafeEqual), Go (crypto/subtle.ConstantTimeCompare), C/Java/C#/Swift (custom loops). Verify modulo bias in padding length calculation ((random_byte % 97) + 32).

### Agent 2: Cross-Language Parity (A02)

### TASK-1-006: A02 Cross-Language Constants Audit
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 2 — Cross-Language Parity
- **Phase**: 1
- **Priority**: CRITICAL
- **Depends On**: TASK-0-001
- **Input Files**: `.claude/agents/security-cross-language.md`, all 12 implementation files
- **Output Files**: `findings/agents/A02-cross-language.md`
- **Skills**: `/skill-cross-lang-constant-audit`, `/skill-multi-lang-symbol-scanner`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Verify ITERATIONS=100000, NONCE_SIZE=16, MAC_SIZE=16, KEY_SIZE=32 are identical in all 12 implementations. Check for any language that uses different values or makes them configurable.

### TASK-1-007: A02 Encryption/Decryption Output Parity
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 2 — Cross-Language Parity
- **Phase**: 1
- **Priority**: CRITICAL
- **Depends On**: TASK-0-001
- **Input Files**: `.claude/agents/security-cross-language.md`, all 12 implementation files, `tests/`
- **Output Files**: `findings/agents/A02-cross-language.md`
- **Skills**: `/skill-function-diff-comparator`, `/skill-test-vector-generator`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Verify byte-identical ciphertext when given same password + service + plaintext + nonce. Check existing cross-language test vectors in `tests/`. Identify any divergences that break interoperability.

### TASK-1-008: A02 Counter Behavior & V1/V2 Format Divergence
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 2 — Cross-Language Parity
- **Phase**: 1
- **Priority**: CRITICAL
- **Depends On**: TASK-0-001
- **Input Files**: `.claude/agents/security-cross-language.md`, all 12 implementation files
- **Output Files**: `findings/agents/A02-cross-language.md`
- **Skills**: `/skill-function-diff-comparator`, `/skill-multi-lang-symbol-scanner`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: CRITICAL — Python increments counter per encryption (core.py:175-176), Rust always uses 0. This means Python ciphertext #2+ may not be decryptable by Rust (and vice versa). Verify V1/V2 auto-detection heuristic (timestamp 2020-2100 range) is consistent. Check padding length handling (CVE-PENDING: Rust is the ONLY impl missing the validation fix per recon).

### TASK-1-009: A02 Function-Level Semantic Diff (Rust vs All Others)
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 2 — Cross-Language Parity
- **Phase**: 1
- **Priority**: HIGH
- **Depends On**: TASK-0-001
- **Input Files**: `.claude/agents/security-cross-language.md`, all 12 implementation files
- **Output Files**: `findings/agents/A02-cross-language.md`
- **Skills**: `/skill-function-diff-comparator`, `/skill-multi-lang-symbol-scanner`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Compare encrypt(), decrypt(), derive_key(), generate_keystream() semantically across languages. Flag any behavioral differences: error handling, edge cases, default values. Check JS exports generateKeystream (shield.js:343-348) — internal primitive exposed.

### Agent 3: Memory Safety (A03)

### TASK-1-010: A03 Key Zeroization Verification Across All Languages
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 3 — Memory Safety
- **Phase**: 1
- **Priority**: CRITICAL
- **Depends On**: TASK-0-001
- **Input Files**: `.claude/agents/security-memory-safety.md`, all 12 implementation files
- **Output Files**: `findings/agents/A03-memory-safety.md`
- **Skills**: `/skill-zeroization-verifier`, `/skill-multi-lang-symbol-scanner`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Rust has Zeroize+ZeroizeOnDrop on Shield, RatchetSession, SymmetricSignature, TOTP. Python/JS/Go/Java/C# have NO zeroization (GC-dependent). C has memset(0) caller responsibility. Android has Arrays.fill(0)+Keystore. iOS has Keychain+Secure Enclave. Document each language's approach.

### TASK-1-011: A03 C Buffer Safety & Memory Management
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 3 — Memory Safety
- **Phase**: 1
- **Priority**: CRITICAL
- **Depends On**: TASK-0-001
- **Input Files**: `.claude/agents/security-memory-safety.md`, `c/src/shield.c`, `c/src/shield_fingerprint.c`, `c/Makefile`
- **Output Files**: `findings/agents/A03-memory-safety.md`
- **Skills**: `/skill-cwe-pattern-detector`, `/skill-fingerprint-security-assessor`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: CRITICAL — strcat() into 512-byte buffer with 256-byte inputs in shield_fingerprint.c:40-56. No bounds checking. Caller must free() all returned buffers. shield_secure_wipe() uses volatile pointer but compiler may optimize away. Stack-allocated keystream buffer (shield.c:294) — verify no overflow.

### TASK-1-012: A03 WASM Memory Isolation & Unwrap Safety
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 3 — Memory Safety
- **Phase**: 1
- **Priority**: HIGH
- **Depends On**: TASK-0-001
- **Input Files**: `.claude/agents/security-memory-safety.md`, `shield-core/src/wasm.rs`, `browser/js/index.ts`, `browser/js/fetch-hook.ts`
- **Output Files**: `findings/agents/A03-memory-safety.md`
- **Skills**: `/skill-wasm-memory-isolation-checker`, `/skill-cwe-pattern-detector`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: 4 instances of .unwrap() on try_into() in wasm.rs:67, 104, 115, 226. Safe after length check but should return JsError. WASM linear memory may be inspectable by JavaScript — assess key exposure risk. Check forbid(unsafe_code) in lib.rs.

### TASK-1-013: A03 Key Accessor Surface Mapping
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 3 — Memory Safety
- **Phase**: 1
- **Priority**: HIGH
- **Depends On**: TASK-0-001
- **Input Files**: `.claude/agents/security-memory-safety.md`, all 12 implementation files
- **Output Files**: `findings/agents/A03-memory-safety.md`
- **Skills**: `/skill-key-accessor-mapper`, `/skill-key-exposure-surface-mapper`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Map all public methods that expose raw key material. Known: .key() method in shield.rs:381-383 exposes derived key — available in ALL implementations for "testing/debugging". Assess whether this should be removed or gated behind a feature flag.

### Phase 1 Checkpoint

### TASK-1-014: Phase 1 Checkpoint — Verify All Crypto Core Findings
- **Status**: [ ] PENDING
- **Agent/Team**: Orchestrator
- **Phase**: 1 (CHECKPOINT)
- **Priority**: CRITICAL
- **Depends On**: TASK-1-001, TASK-1-002, TASK-1-003, TASK-1-004, TASK-1-005, TASK-1-006, TASK-1-007, TASK-1-008, TASK-1-009, TASK-1-010, TASK-1-011, TASK-1-012, TASK-1-013
- **Input Files**: `findings/agents/A01-crypto-primitives.md`, `findings/agents/A02-cross-language.md`, `findings/agents/A03-memory-safety.md`
- **Output Files**: `findings/SECURITY_REPORT.md` (update summary counts)
- **Skills**: `/skill-audit-progress-tracker`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Verify: (1) A01 findings file exists with ≥1 finding, (2) A02 findings file exists with ≥1 finding, (3) A03 findings file exists with ≥1 finding, (4) All known issues from recon are addressed (key separation, counter divergence, CVE-PENDING, zeroization gaps). Update SECURITY_REPORT.md with Phase 1 totals.

---

## PHASE 2: PROTOCOL, APPLICATION & INFRASTRUCTURE (PARALLEL)

> All Phase 2 tasks depend on Phase 1 Checkpoint (TASK-1-014).
> Phase 2 tasks CAN run in parallel with each other.

### Agent 4: Input Validation (A04)

### TASK-2-001: A04 Ciphertext & Padding Input Validation
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 4 — Input Validation
- **Phase**: 2
- **Priority**: CRITICAL
- **Depends On**: TASK-1-014
- **Input Files**: `.claude/agents/security-input-validation.md`, all 12 implementation files
- **Output Files**: `findings/agents/A04-input-validation.md`
- **Skills**: `/skill-cwe-pattern-detector`, `/skill-multi-lang-symbol-scanner`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: CVE-PENDING — padding length validation. Rust is the ONLY implementation missing the fix (shield.rs:300 — pad_len as usize, no bounds check). Python/JS/Go/Java/C have the fix. Verify min ciphertext length (40 bytes). Test: truncated ciphertext, oversized ciphertext, pad_len values 0, 31, 129, 255.

### TASK-2-002: A04 CLI Input & File Path Validation
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 4 — Input Validation
- **Phase**: 2
- **Priority**: HIGH
- **Depends On**: TASK-1-014
- **Input Files**: `.claude/agents/security-input-validation.md`, `shield-core/src/` (CLI module)
- **Output Files**: `findings/agents/A04-input-validation.md`
- **Skills**: `/skill-cwe-pattern-detector`, `/skill-shell-script-injection-checker`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: `shield check <password>` exposes password in shell history / process listing. No path traversal protection on file I/O. Check rpassword integration for password prompt security.

### TASK-2-003: A04 API & Middleware Input Validation
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 4 — Input Validation
- **Phase**: 2
- **Priority**: HIGH
- **Depends On**: TASK-1-014
- **Input Files**: `.claude/agents/security-input-validation.md`, `python/shield/integrations/*.py`, `javascript/integrations/express.js`
- **Output Files**: `findings/agents/A04-input-validation.md`
- **Skills**: `/skill-cwe-pattern-detector`, `/skill-route-exclusion-bypass-checker`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Check JS options.salt type confusion (shield.js:66-68 — truthy non-Buffer value bypasses salt derivation). Check session_id format validation (used as HMAC key derivation input, no format validation per recon). Check BigInt() conversion for counter (shield.js:131).

### Agent 5: Docker & Container (A05) — CRITICAL

### TASK-2-004: A05 Dockerfile & Base Image Security Audit
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 5 — Docker & Container
- **Phase**: 2
- **Priority**: CRITICAL
- **Depends On**: TASK-1-014
- **Input Files**: `.claude/agents/security-docker-container.md`, `Dockerfile`, `docker-compose.yml`
- **Output Files**: `findings/agents/A05-docker-container.md`
- **Skills**: `/skill-dockerfile-security-auditor`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: CIS Docker Benchmark audit. Check: base image (ubuntu:22.04), USER directive, HEALTHCHECK, COPY vs ADD, layer caching secrets, multi-stage builds, .dockerignore.

### TASK-2-005: A05 Docker-Compose & Networking Security
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 5 — Docker & Container
- **Phase**: 2
- **Priority**: CRITICAL
- **Depends On**: TASK-1-014
- **Input Files**: `.claude/agents/security-docker-container.md`, `docker-compose.yml`
- **Output Files**: `findings/agents/A05-docker-container.md`
- **Skills**: `/skill-dockerfile-security-auditor`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Check: network isolation, volume mounts, privileged mode, capability dropping, resource limits, secrets management, environment variable exposure.

### TASK-2-006: A05 Opaque Container Examples Security
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 5 — Docker & Container
- **Phase**: 2
- **Priority**: CRITICAL
- **Depends On**: TASK-1-014
- **Input Files**: `.claude/agents/security-docker-container.md`, `examples/opaque-containers/*`
- **Output Files**: `findings/agents/A05-docker-container.md`
- **Skills**: `/skill-dockerfile-security-auditor`, `/skill-shell-script-injection-checker`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Licensed opaque containers with SaaS integration — audit for key management in containers, encryption-at-rest, network security, secret injection patterns.

### Agent 6: Web Integration (A06)

### TASK-2-007: A06 FastAPI Middleware Security Audit
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 6 — Web Integration
- **Phase**: 2
- **Priority**: HIGH
- **Depends On**: TASK-1-014
- **Input Files**: `.claude/agents/security-web-integration.md`, `python/shield/integrations/fastapi.py`
- **Output Files**: `findings/agents/A06-web-integration.md`
- **Skills**: `/skill-route-exclusion-bypass-checker`, `/skill-middleware-error-propagation-tracer`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Audit ShieldMiddleware, dependency injection (ShieldTokenAuth, ShieldAPIKeyAuth), route exclusion patterns, error propagation from decrypt failures.

### TASK-2-008: A06 Flask Extension & Express Middleware Audit
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 6 — Web Integration
- **Phase**: 2
- **Priority**: HIGH
- **Depends On**: TASK-1-014
- **Input Files**: `.claude/agents/security-web-integration.md`, `python/shield/integrations/flask.py`, `javascript/integrations/express.js`
- **Output Files**: `findings/agents/A06-web-integration.md`
- **Skills**: `/skill-route-exclusion-bypass-checker`, `/skill-error-message-cataloger`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Audit Flask decorators, FlaskAPIKeyAuth, Express shieldMiddleware. Check for path-based route exclusion bypass (traversal, encoding, case). Check error information disclosure in middleware responses.

### TASK-2-009: A06 CORS, Route Exclusion & Browser Bridge
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 6 — Web Integration
- **Phase**: 2
- **Priority**: HIGH
- **Depends On**: TASK-1-014
- **Input Files**: `.claude/agents/security-web-integration.md`, `python/shield/integrations/browser.py`, `python/shield/integrations/fastapi.py`
- **Output Files**: `findings/agents/A06-web-integration.md`
- **Skills**: `/skill-cookie-security-auditor`, `/skill-route-exclusion-bypass-checker`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Audit SecureCORS (HMAC-signed origin verification). Audit BrowserBridge.generate_client_key() — session-derived keys, TTL-based. Check route exclusion bypass vectors.

### Agent 7: Auth & Session (A07)

### TASK-2-010: A07 Token Auth & API Key Security
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 7 — Auth & Session
- **Phase**: 2
- **Priority**: HIGH
- **Depends On**: TASK-1-014
- **Input Files**: `.claude/agents/security-auth-session.md`, `python/shield/integrations/fastapi.py`, `python/shield/integrations/flask.py`, `python/shield/integrations/protection.py`
- **Output Files**: `findings/agents/A07-auth-session.md`
- **Skills**: `/skill-token-lifecycle-auditor`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Audit ShieldTokenAuth (Bearer token, HMAC-verified, TTL-enforced), ShieldAPIKeyAuth (Header-based, encrypted key comparison). Check token creation, validation, revocation, and expiry flows.

### TASK-2-011: A07 Rate Limiter & Brute Force Protection
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 7 — Auth & Session
- **Phase**: 2
- **Priority**: HIGH
- **Depends On**: TASK-1-014
- **Input Files**: `.claude/agents/security-auth-session.md`, `python/shield/integrations/protection.py`
- **Output Files**: `findings/agents/A07-auth-session.md`
- **Skills**: `/skill-rate-limiter-bypass-analyzer`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Audit RateLimiter (per-user/IP, encrypted counters), TokenBucket (configurable refill rate), APIProtector (combined: rate limit + IP filter + audit log). Check for counter reset, IP spoofing, race conditions, distributed attack vectors. In-memory state only — no persistence.

### TASK-2-012: A07 Session & Identity Management
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 7 — Auth & Session
- **Phase**: 2
- **Priority**: HIGH
- **Depends On**: TASK-1-014
- **Input Files**: `.claude/agents/security-auth-session.md`, `shield-core/src/identity.rs`, all language implementations
- **Output Files**: `findings/agents/A07-auth-session.md`
- **Skills**: `/skill-token-lifecycle-auditor`, `/skill-multi-lang-symbol-scanner`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Audit IdentityProvider register/authenticate/validate_token flows. Check PBKDF2-derived user keys, session tokens. In-memory session state (BrowserBridge, RateLimiter, IdentityProvider) — race conditions possible under load.

### TASK-2-013: A07 Cookie Security & TOTP/Recovery Codes
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 7 — Auth & Session
- **Phase**: 2
- **Priority**: HIGH
- **Depends On**: TASK-1-014
- **Input Files**: `.claude/agents/security-auth-session.md`, `python/shield/integrations/`, `shield-core/src/totp.rs`
- **Output Files**: `findings/agents/A07-auth-session.md`
- **Skills**: `/skill-cookie-security-auditor`, `/skill-totp-rfc-compliance-checker`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Audit EncryptedCookie (Shield-encrypted, HttpOnly, SameSite=Strict). TOTP uses HMAC-SHA1 (RFC required) with ring "LEGACY_USE_ONLY" warning. RecoveryCodes: 10 one-time codes, 8 hex chars each. Check ±1 interval window.

### Agent 8: Transport Protocol (A08)

### TASK-2-014: A08 ShieldChannel Handshake & PAKE Security
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 8 — Transport Protocol
- **Phase**: 2
- **Priority**: HIGH
- **Depends On**: TASK-1-014
- **Input Files**: `.claude/agents/security-transport-protocol.md`, `shield-core/src/channel.rs`, `shield-core/src/channel_async.rs`, `shield-core/src/exchange.rs`
- **Output Files**: `findings/agents/A08-transport-protocol.md`
- **Skills**: `/skill-protocol-handshake-tracer`, `/skill-constant-time-verifier`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Trace ShieldChannel handshake. PAKEExchange uses 200k iterations. combine() sorts contributions then hashes — deterministic. Check NonZeroU32::new(iters).unwrap() in exchange.rs:26 — would panic if iterations=Some(0). Check serde_json::to_string().unwrap() in exchange.rs:98.

### TASK-2-015: A08 RatchetSession & Forward Secrecy
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 8 — Transport Protocol
- **Phase**: 2
- **Priority**: HIGH
- **Depends On**: TASK-1-014
- **Input Files**: `.claude/agents/security-transport-protocol.md`, `shield-core/src/ratchet.rs`
- **Output Files**: `findings/agents/A08-transport-protocol.md`
- **Skills**: `/skill-protocol-handshake-tracer`, `/skill-mac-verification-auditor`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Audit key ratchet mechanism for forward secrecy. Verify RatchetSession has Zeroize. Check monotonic counter for replay protection. Verify old keys are properly destroyed after ratchet.

### TASK-2-016: A08 Counter-Based Replay Protection
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 8 — Transport Protocol
- **Phase**: 2
- **Priority**: HIGH
- **Depends On**: TASK-1-014
- **Input Files**: `.claude/agents/security-transport-protocol.md`, `shield-core/src/channel.rs`
- **Output Files**: `findings/agents/A08-transport-protocol.md`
- **Skills**: `/skill-protocol-handshake-tracer`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Verify strict sequence counter in ShieldChannel. Check counter overflow handling. Verify V2 timestamp validation (60s window, 5s future clock skew). Check C time(NULL)*1000 — 1-second precision reduces replay protection.

### Agent 9: Browser & WASM (A09)

### TASK-2-017: A09 WASM Memory & Key Exposure
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 9 — Browser & WASM
- **Phase**: 2
- **Priority**: HIGH
- **Depends On**: TASK-1-014
- **Input Files**: `.claude/agents/security-browser-wasm.md`, `shield-core/src/wasm.rs`, `browser/js/index.ts`
- **Output Files**: `findings/agents/A09-browser-wasm.md`
- **Skills**: `/skill-wasm-memory-isolation-checker`, `/skill-key-accessor-mapper`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: WASM linear memory inspectable by JavaScript. Assess key storage in WASM memory. Check ShieldBrowser.init(keyEndpoint) — how is the key endpoint authenticated? Verify key stored only in WASM memory, not JS heap.

### TASK-2-018: A09 Fetch Hook & Auto-Decrypt Security
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 9 — Browser & WASM
- **Phase**: 2
- **Priority**: HIGH
- **Depends On**: TASK-1-014
- **Input Files**: `.claude/agents/security-browser-wasm.md`, `browser/js/fetch-hook.ts`
- **Output Files**: `findings/agents/A09-browser-wasm.md`
- **Skills**: `/skill-wasm-memory-isolation-checker`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Monkey-patch window.fetch() — detect {encrypted:true,data:"..."} → WASM quick_decrypt(). Check: (1) Can attacker craft malicious response that triggers decrypt with wrong key? (2) Is decrypted plaintext exposed to other scripts? (3) Same-origin policy enforcement.

### TASK-2-019: A09 Browser SDK Key Exchange & CSP
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 9 — Browser & WASM
- **Phase**: 2
- **Priority**: HIGH
- **Depends On**: TASK-1-014
- **Input Files**: `.claude/agents/security-browser-wasm.md`, `browser/js/index.ts`, `python/shield/integrations/browser.py`
- **Output Files**: `findings/agents/A09-browser-wasm.md`
- **Skills**: `/skill-wasm-memory-isolation-checker`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: BrowserBridge.generate_client_key() — session-derived keys, TTL-based. Check CSP compatibility (no testing documented per recon). Check WASM binary integrity — no checksum verification before loading.

### Agent 10: CI/CD & Supply Chain (A10)

### TASK-2-020: A10 GitHub Actions Workflow Audit
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 10 — CI/CD & Supply Chain
- **Phase**: 2
- **Priority**: HIGH
- **Depends On**: TASK-1-014
- **Input Files**: `.claude/agents/security-cicd-supply-chain.md`, `.github/workflows/*.yml`
- **Output Files**: `findings/agents/A10-cicd-supply-chain.md`
- **Skills**: `/skill-github-actions-auditor`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Check SHA pinning on all third-party actions (actions/checkout v4, dtolnay/rust-toolchain, etc.). Verify permissions are minimally scoped. Check TruffleHog uses @main (unpinned). Check softprops/action-gh-release v1. TODO in release.yml:141 about WASM build.

### TASK-2-021: A10 Dependency Audit (All Package Managers)
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 10 — CI/CD & Supply Chain
- **Phase**: 2
- **Priority**: HIGH
- **Depends On**: TASK-1-014
- **Input Files**: `.claude/agents/security-cicd-supply-chain.md`, `shield-core/Cargo.toml`, `python/pyproject.toml`, `javascript/package.json`, `go/go.mod`, `java/build.gradle*`, `android/build.gradle*`, `browser/package.json`, `csharp/*.csproj`
- **Output Files**: `findings/agents/A10-cicd-supply-chain.md`
- **Skills**: `/skill-dependency-audit-scanner`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Audit all dependency manifests. Check: ring 0.17 (uses unsafe internally), zeroize 1.7, subtle 2.5, md5 0.7. Android: security-crypto 1.1.0-alpha06 (ALPHA version!). Go: x/crypto v0.47.0. No SLSA, SBOM, or Sigstore integration per recon.

### TASK-2-022: A10 Release Integrity & Secret Management
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 10 — CI/CD & Supply Chain
- **Phase**: 2
- **Priority**: HIGH
- **Depends On**: TASK-1-014
- **Input Files**: `.claude/agents/security-cicd-supply-chain.md`, `.github/workflows/*.yml`
- **Output Files**: `findings/agents/A10-cicd-supply-chain.md`
- **Skills**: `/skill-github-actions-auditor`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Check secrets: CARGO_REGISTRY_TOKEN, PYPI_API_TOKEN, NPM_TOKEN, CODECOV_TOKEN. Verify release signing. Check multi-platform binary builds (5 targets). No supply chain verification (no SLSA/SBOM/Sigstore per recon). No dependency pinning verification beyond lockfiles.

### Agent 11: Error Disclosure (A11)

### TASK-2-023: A11 Error Message Catalog (All 12 Implementations)
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 11 — Error Disclosure
- **Phase**: 2
- **Priority**: HIGH
- **Depends On**: TASK-1-014
- **Input Files**: `.claude/agents/security-error-disclosure.md`, all 12 implementation files, `shield-core/src/error.rs`
- **Output Files**: `findings/agents/A11-error-disclosure.md`
- **Skills**: `/skill-error-message-cataloger`, `/skill-multi-lang-symbol-scanner`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Extract ALL error messages, exceptions, error strings from all 12 implementations. Classify information disclosed in each: does it reveal key length? Nonce? Algorithm? Internal state? Create a catalog per language.

### TASK-2-024: A11 Middleware Error Propagation & Crypto Leakage
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 11 — Error Disclosure
- **Phase**: 2
- **Priority**: HIGH
- **Depends On**: TASK-1-014
- **Input Files**: `.claude/agents/security-error-disclosure.md`, `python/shield/integrations/*.py`, `javascript/integrations/express.js`
- **Output Files**: `findings/agents/A11-error-disclosure.md`
- **Skills**: `/skill-middleware-error-propagation-tracer`, `/skill-error-message-cataloger`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Trace error propagation from Shield decrypt failures through middleware to HTTP responses. Does a MAC failure return a different error than a padding failure? If so, this enables a crypto oracle. Classify information leakage at each propagation stage.

### TASK-2-025: A11 Stack Trace & Debug Info Exposure
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 11 — Error Disclosure
- **Phase**: 2
- **Priority**: MEDIUM
- **Depends On**: TASK-1-014
- **Input Files**: `.claude/agents/security-error-disclosure.md`, all implementation files
- **Output Files**: `findings/agents/A11-error-disclosure.md`
- **Skills**: `/skill-error-message-cataloger`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Check for stack trace exposure in production configurations. Check debug logging that may leak key material or plaintext. Check thiserror derive macros in Rust for information leakage.

### Phase 2 Checkpoint

### TASK-2-026: Phase 2 Checkpoint — Verify All Protocol/App/Infra Findings
- **Status**: [ ] PENDING
- **Agent/Team**: Orchestrator
- **Phase**: 2 (CHECKPOINT)
- **Priority**: CRITICAL
- **Depends On**: TASK-2-001, TASK-2-002, TASK-2-003, TASK-2-004, TASK-2-005, TASK-2-006, TASK-2-007, TASK-2-008, TASK-2-009, TASK-2-010, TASK-2-011, TASK-2-012, TASK-2-013, TASK-2-014, TASK-2-015, TASK-2-016, TASK-2-017, TASK-2-018, TASK-2-019, TASK-2-020, TASK-2-021, TASK-2-022, TASK-2-023, TASK-2-024, TASK-2-025
- **Input Files**: `findings/agents/A04-input-validation.md`, `findings/agents/A05-docker-container.md`, `findings/agents/A06-web-integration.md`, `findings/agents/A07-auth-session.md`, `findings/agents/A08-transport-protocol.md`, `findings/agents/A09-browser-wasm.md`, `findings/agents/A10-cicd-supply-chain.md`, `findings/agents/A11-error-disclosure.md`
- **Output Files**: `findings/SECURITY_REPORT.md` (update summary counts)
- **Skills**: `/skill-audit-progress-tracker`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Verify all 8 agent finding files exist (A04-A11) with ≥1 finding each. Update SECURITY_REPORT.md with Phase 2 totals. Flag any agents that produced 0 findings for re-examination.

---

## PHASE 3: PLATFORM & HARDWARE (PARALLEL)

> All Phase 3 tasks depend on Phase 2 Checkpoint (TASK-2-026).
> Phase 3 tasks CAN run in parallel with each other.

### Agent 12: Mobile Platform (A12)

### TASK-3-001: A12 Android Keystore & Biometric Security
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 12 — Mobile Platform
- **Phase**: 3
- **Priority**: MEDIUM
- **Depends On**: TASK-2-026
- **Input Files**: `.claude/agents/security-mobile-platform.md`, `android/.../shield/src/**`
- **Output Files**: `findings/agents/A12-mobile-platform.md`
- **Skills**: `/skill-android-keystore-auditor`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Audit SecureKeyStore for hardware backing, biometric protection, key purposes. Check androidx.security:security-crypto 1.1.0-alpha06 (ALPHA!). Check Arrays.fill(0) zeroization. Check Keystore/TEE/StrongBox selection logic.

### TASK-3-002: A12 iOS Keychain & Secure Enclave Security
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 12 — Mobile Platform
- **Phase**: 3
- **Priority**: MEDIUM
- **Depends On**: TASK-2-026
- **Input Files**: `.claude/agents/security-mobile-platform.md`, `ios/Sources/Shield/**`
- **Output Files**: `findings/agents/A12-mobile-platform.md`
- **Skills**: `/skill-ios-keychain-auditor`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Audit SecureKeychain for access control, Secure Enclave usage, data protection class, biometric integration (FaceID/TouchID). Check CommonCrypto + Security.framework usage. Check bitwise OR accumulation for constant-time comparison.

### Agent 13: Confidential TEE (A13) — CRITICAL

### TASK-3-003: A13 AWS Nitro & GCP SEV Attestation Audit
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 13 — Confidential TEE
- **Phase**: 3
- **Priority**: CRITICAL
- **Depends On**: TASK-2-026
- **Input Files**: `.claude/agents/security-confidential-tee.md`, `shield-core/src/confidential/*.rs`, `python/.../confidential/*.py`
- **Output Files**: `findings/agents/A13-confidential-tee.md`
- **Skills**: `/skill-tee-attestation-auditor`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Audit NitroAttestationProvider (COSE signatures, PCR validation, Vsock). Audit SEVAttestationProvider (AMD SEV-SNP, vTPM attestation). Check attestation freshness, certificate chain validation, measurement pinning.

### TASK-3-004: A13 Azure MAA & Intel SGX Attestation Audit
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 13 — Confidential TEE
- **Phase**: 3
- **Priority**: CRITICAL
- **Depends On**: TASK-2-026
- **Input Files**: `.claude/agents/security-confidential-tee.md`, `shield-core/src/confidential/*.rs`
- **Output Files**: `findings/agents/A13-confidential-tee.md`
- **Skills**: `/skill-tee-attestation-auditor`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Audit MAAAttestationProvider (JWT validation, Azure Key Vault integration). Audit SGXAttestationProvider (DCAP quotes, MRENCLAVE/MRSIGNER). Check sealed storage security.

### TASK-3-005: A13 TEEKeyManager Policy & Sealed Storage
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 13 — Confidential TEE
- **Phase**: 3
- **Priority**: CRITICAL
- **Depends On**: TASK-2-026
- **Input Files**: `.claude/agents/security-confidential-tee.md`, `shield-core/src/confidential/*.rs`
- **Output Files**: `findings/agents/A13-confidential-tee.md`
- **Skills**: `/skill-tee-attestation-auditor`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Audit TEEKeyManager attestation-gated key release with policy enforcement. Check: (1) Policy bypass vectors, (2) Key release conditions, (3) Sealed storage integrity, (4) Sidecar pattern security in Azure/GCP.

### Agent 14: Streaming & Group (A14)

### TASK-3-006: A14 StreamCipher Security & Per-Chunk Auth
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 14 — Streaming & Group
- **Phase**: 3
- **Priority**: MEDIUM
- **Depends On**: TASK-2-026
- **Input Files**: `.claude/agents/security-streaming-group.md`, `shield-core/src/stream.rs`
- **Output Files**: `findings/agents/A14-streaming-group.md`
- **Skills**: `/skill-ctr-mode-verifier`, `/skill-mac-verification-auditor`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Audit StreamCipher chunk encryption. Verify per-chunk authentication — can chunks be reordered, truncated, or replayed? Check chunk boundary handling.

### TASK-3-007: A14 GroupEncryption & Multi-Recipient Security
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 14 — Streaming & Group
- **Phase**: 3
- **Priority**: MEDIUM
- **Depends On**: TASK-2-026
- **Input Files**: `.claude/agents/security-streaming-group.md`, `shield-core/src/group.rs`
- **Output Files**: `findings/agents/A14-streaming-group.md`
- **Skills**: `/skill-multi-lang-symbol-scanner`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Audit GroupEncryption multi-recipient and subgroup encrypt. Check key distribution, member addition/removal, forward secrecy within groups.

### Agent 15: Signatures & 2FA (A15)

### TASK-3-008: A15 HMAC & Lamport Signature Security
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 15 — Signatures & 2FA
- **Phase**: 3
- **Priority**: MEDIUM
- **Depends On**: TASK-2-026
- **Input Files**: `.claude/agents/security-signatures-2fa.md`, `shield-core/src/signatures.rs`
- **Output Files**: `findings/agents/A15-signatures-2fa.md`
- **Skills**: `/skill-mac-verification-auditor`, `/skill-constant-time-verifier`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Audit HMAC signature scheme. Audit Lamport signatures (256-bit chains, claimed post-quantum safe). Verify SymmetricSignature has Zeroize. Check one-time use enforcement for Lamport.

### TASK-3-009: A15 TOTP RFC Compliance & Recovery Codes
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 15 — Signatures & 2FA
- **Phase**: 3
- **Priority**: MEDIUM
- **Depends On**: TASK-2-026
- **Input Files**: `.claude/agents/security-signatures-2fa.md`, `shield-core/src/totp.rs`
- **Output Files**: `findings/agents/A15-signatures-2fa.md`
- **Skills**: `/skill-totp-rfc-compliance-checker`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Verify TOTP against RFC 6238: time step, digit count (6-8), algorithm (HMAC-SHA1), replay prevention, ±1 interval window. Check ring "LEGACY_USE_ONLY" warning for HMAC-SHA1. RecoveryCodes: 10 one-time codes, 8 hex chars — check entropy, single-use enforcement.

### Agent 16: Fingerprint (A16)

### TASK-3-010: A16 Fingerprint Hash Strength & Spoofability
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 16 — Fingerprint
- **Phase**: 3
- **Priority**: MEDIUM
- **Depends On**: TASK-2-026
- **Input Files**: `.claude/agents/security-fingerprint.md`, `shield-core/src/fingerprint.rs`
- **Output Files**: `findings/agents/A16-fingerprint.md`
- **Skills**: `/skill-fingerprint-security-assessor`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: MD5 used for fingerprint hash (fingerprint.rs:59, shield_fingerprint.c:65) — cryptographically broken but used only as hash-to-string. Assess spoofability of device fingerprint. Check collect_fingerprint() system calls across platforms.

### TASK-3-011: A16 C Fingerprint Buffer Overflow & Command Injection
- **Status**: [ ] PENDING
- **Agent/Team**: Agent 16 — Fingerprint
- **Phase**: 3
- **Priority**: MEDIUM
- **Depends On**: TASK-2-026
- **Input Files**: `.claude/agents/security-fingerprint.md`, `c/src/shield_fingerprint.c`
- **Output Files**: `findings/agents/A16-fingerprint.md`
- **Skills**: `/skill-fingerprint-security-assessor`, `/skill-shell-script-injection-checker`, `/skill-cwe-pattern-detector`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: CRITICAL sub-task — strcat() into 512-byte buffer at lines 40-56 without bounds checking. _popen("wmic ...") at lines 76, 107 — hardcoded commands, no injection risk FROM user input but check if any path allows user-controlled input to reach popen. md5_hash() for combined fingerprint at line 65.

### Phase 3 Checkpoint

### TASK-3-012: Phase 3 Checkpoint — Verify All Platform/HW Findings
- **Status**: [ ] PENDING
- **Agent/Team**: Orchestrator
- **Phase**: 3 (CHECKPOINT)
- **Priority**: CRITICAL
- **Depends On**: TASK-3-001, TASK-3-002, TASK-3-003, TASK-3-004, TASK-3-005, TASK-3-006, TASK-3-007, TASK-3-008, TASK-3-009, TASK-3-010, TASK-3-011
- **Input Files**: `findings/agents/A12-mobile-platform.md`, `findings/agents/A13-confidential-tee.md`, `findings/agents/A14-streaming-group.md`, `findings/agents/A15-signatures-2fa.md`, `findings/agents/A16-fingerprint.md`
- **Output Files**: `findings/SECURITY_REPORT.md` (update summary counts)
- **Skills**: `/skill-audit-progress-tracker`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Verify all 5 agent finding files exist (A12-A16) with ≥1 finding each. Update SECURITY_REPORT.md with Phase 3 totals. All individual agent audits are now complete.

---

## PHASE 4: CROSS-DOMAIN BATCH 1 (PARALLEL)

> All Phase 4 tasks depend on Phase 3 Checkpoint (TASK-3-012).
> Phase 4 tasks CAN run in parallel with each other.
> Teams consume ALL agent findings as input.

### TASK-4-001: T06 Crypto Oracle & Error Leakage Chain Analysis
- **Status**: [ ] PENDING
- **Agent/Team**: Team 6 — Crypto Oracle & Error Leakage
- **Phase**: 4
- **Priority**: CRITICAL
- **Depends On**: TASK-3-012
- **Input Files**: `.claude/agents/team-6-crypto-oracle-error.md`, `findings/agents/A01-crypto-primitives.md`, `findings/agents/A11-error-disclosure.md`, `findings/agents/A06-web-integration.md`, `findings/agents/A04-input-validation.md`
- **Output Files**: `findings/teams/T06-crypto-oracle-error.md`
- **Skills**: `/skill-crypto-oracle-feasibility-assessor`, `/skill-attack-chain-builder`, `/skill-middleware-error-propagation-tracer`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Chain: Error messages + middleware behavior → crypto oracle attack. Can an attacker distinguish MAC failure from padding failure from decryption failure? If yes, adaptive chosen-ciphertext attack is feasible. Cross-reference A01, A11, A06, A04 findings.

### TASK-4-002: T07 Supply Chain to Runtime Chain Analysis
- **Status**: [ ] PENDING
- **Agent/Team**: Team 7 — Supply Chain to Runtime
- **Phase**: 4
- **Priority**: HIGH
- **Depends On**: TASK-3-012
- **Input Files**: `.claude/agents/team-7-supply-chain-runtime.md`, `findings/agents/A10-cicd-supply-chain.md`, `findings/agents/A05-docker-container.md`, `findings/agents/A09-browser-wasm.md`
- **Output Files**: `findings/teams/T07-supply-chain-runtime.md`
- **Skills**: `/skill-attack-chain-builder`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Chain: CI/CD compromise → deployment → runtime crypto corruption. Can a compromised GitHub Action inject malicious code into a published package? Can a tampered WASM module bypass integrity checks? Cross-reference A10, A05, A09 findings.

### TASK-4-003: T08 Cross-Language Interop Exploit Chain Analysis
- **Status**: [ ] PENDING
- **Agent/Team**: Team 8 — Cross-Language Interop Exploit
- **Phase**: 4
- **Priority**: CRITICAL
- **Depends On**: TASK-3-012
- **Input Files**: `.claude/agents/team-8-cross-lang-interop.md`, `findings/agents/A02-cross-language.md`, `findings/agents/A04-input-validation.md`, `findings/agents/A11-error-disclosure.md`, `findings/agents/A14-streaming-group.md`
- **Output Files**: `findings/teams/T08-cross-lang-interop.md`
- **Skills**: `/skill-interop-exploit-matrix-builder`, `/skill-attack-chain-builder`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Chain: Behavioral divergences across 12 impls → interop exploitation. Counter behavior divergence (Python increments, Rust doesn't). CVE-PENDING fix missing in Rust only. Exported internals (JS generateKeystream). Build language A × language B × input exploit matrix.

### TASK-4-004: T11 Config & Deployment Drift Chain Analysis
- **Status**: [ ] PENDING
- **Agent/Team**: Team 11 — Config & Deployment Drift
- **Phase**: 4
- **Priority**: HIGH
- **Depends On**: TASK-3-012
- **Input Files**: `.claude/agents/team-11-config-deployment-drift.md`, `findings/agents/A05-docker-container.md`, `findings/agents/A10-cicd-supply-chain.md`, `findings/agents/A06-web-integration.md`, `findings/agents/A11-error-disclosure.md`
- **Output Files**: `findings/teams/T11-config-deployment-drift.md`
- **Skills**: `/skill-config-drift-detector`, `/skill-attack-chain-builder`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Chain: Dev config differences → production security gaps. Compare development vs production configurations: debug modes, error verbosity, rate limiting settings, CORS policies. Cross-reference A05, A10, A06, A11 findings.

### Phase 4 Checkpoint

### TASK-4-005: Phase 4 Checkpoint — Verify All Cross-Domain Batch 1 Findings
- **Status**: [ ] PENDING
- **Agent/Team**: Orchestrator
- **Phase**: 4 (CHECKPOINT)
- **Priority**: CRITICAL
- **Depends On**: TASK-4-001, TASK-4-002, TASK-4-003, TASK-4-004
- **Input Files**: `findings/teams/T06-crypto-oracle-error.md`, `findings/teams/T07-supply-chain-runtime.md`, `findings/teams/T08-cross-lang-interop.md`, `findings/teams/T11-config-deployment-drift.md`
- **Output Files**: `findings/SECURITY_REPORT.md` (update summary counts)
- **Skills**: `/skill-audit-progress-tracker`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Verify all 4 team finding files exist (T06, T07, T08, T11) with ≥1 finding or explicit "no cross-domain issues found" conclusion. Verify attack chains reference agent finding IDs (SHIELD-A##-###) rather than duplicating. Update SECURITY_REPORT.md.

---

## PHASE 5: CROSS-DOMAIN BATCH 2 (PARALLEL)

> All Phase 5 tasks depend on Phase 4 Checkpoint (TASK-4-005).
> Phase 5 tasks CAN run in parallel with each other.

### TASK-5-001: T09 Key Lifecycle & Exposure Chain Analysis
- **Status**: [ ] PENDING
- **Agent/Team**: Team 9 — Key Lifecycle & Exposure
- **Phase**: 5
- **Priority**: CRITICAL
- **Depends On**: TASK-4-005
- **Input Files**: `.claude/agents/team-9-key-lifecycle.md`, `findings/agents/A03-memory-safety.md`, `findings/agents/A12-mobile-platform.md`, `findings/agents/A09-browser-wasm.md`, `findings/agents/A07-auth-session.md`, `findings/agents/A13-confidential-tee.md`
- **Output Files**: `findings/teams/T09-key-lifecycle.md`
- **Skills**: `/skill-key-exposure-surface-mapper`, `/skill-attack-chain-builder`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Chain: Key extraction at any lifecycle point → forge/decrypt. Map complete key lifecycle: generation → derivation → storage → usage → destruction. Check every platform: memory (GC languages), Keystore (Android), Keychain (iOS), WASM memory (Browser), TEE sealed storage. Cross-reference A03, A12, A09, A07, A13 findings.

### TASK-5-002: T10 Auth & Transport MITM Chain Analysis
- **Status**: [ ] PENDING
- **Agent/Team**: Team 10 — Auth & Transport MITM
- **Phase**: 5
- **Priority**: HIGH
- **Depends On**: TASK-4-005
- **Input Files**: `.claude/agents/team-10-auth-transport-mitm.md`, `findings/agents/A08-transport-protocol.md`, `findings/agents/A07-auth-session.md`, `findings/agents/A16-fingerprint.md`, `findings/agents/A15-signatures-2fa.md`
- **Output Files**: `findings/teams/T10-auth-transport-mitm.md`
- **Skills**: `/skill-protocol-handshake-tracer`, `/skill-attack-chain-builder`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Chain: MITM → session compromise → device rebinding → identity takeover. Can an attacker intercept ShieldChannel handshake? Can they bypass fingerprint-based device binding? Can they forge signatures after MITM key compromise? Cross-reference A08, A07, A16, A15 findings.

### Phase 5 Checkpoint

### TASK-5-003: Phase 5 Checkpoint — Verify All Cross-Domain Batch 2 Findings
- **Status**: [ ] PENDING
- **Agent/Team**: Orchestrator
- **Phase**: 5 (CHECKPOINT)
- **Priority**: CRITICAL
- **Depends On**: TASK-5-001, TASK-5-002
- **Input Files**: `findings/teams/T09-key-lifecycle.md`, `findings/teams/T10-auth-transport-mitm.md`
- **Output Files**: `findings/SECURITY_REPORT.md` (update summary counts)
- **Skills**: `/skill-audit-progress-tracker`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Verify T09 and T10 finding files exist. Verify cross-references to agent findings. Update SECURITY_REPORT.md. All cross-domain analysis is now complete.

---

## PHASE 6: FINAL — LAUNCH READINESS

> Phase 6 tasks are sequential: Dedup → T12 Go/No-Go → Final Report.

### TASK-6-001: Finding Deduplication & Consolidation
- **Status**: [ ] PENDING
- **Agent/Team**: Orchestrator
- **Phase**: 6
- **Priority**: CRITICAL
- **Depends On**: TASK-5-003
- **Input Files**: All files in `findings/agents/`, all files in `findings/teams/`
- **Output Files**: `findings/SECURITY_REPORT.md` (deduplicated findings section)
- **Skills**: `/skill-finding-deduplicator`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Dedup rules: (1) Domain + cross-domain find same issue → cross-domain REFERENCES domain finding by ID, (2) Chain escalates severity → consolidated severity = highest in chain, (3) Multiple chains share root cause → single root cause with multiple chain references, (4) Contradictory findings → flag for manual review. Produce deduplicated finding list.

### TASK-6-002: T12 Launch Readiness Go/No-Go Assessment
- **Status**: [ ] PENDING
- **Agent/Team**: Team 12 — Launch Readiness
- **Phase**: 6
- **Priority**: CRITICAL
- **Depends On**: TASK-6-001
- **Input Files**: `.claude/agents/team-12-launch-readiness.md`, `findings/SECURITY_REPORT.md`, all files in `findings/agents/`, all files in `findings/teams/`
- **Output Files**: `findings/teams/T12-launch-readiness.md`, `findings/SUMMARY.md`
- **Skills**: `/skill-risk-matrix-generator`, `/skill-remediation-roadmap-builder`, `/skill-audit-progress-tracker`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Generate Likelihood x Impact risk matrix. Produce go/no-go recommendation. Create remediation roadmap with effort estimates, dependencies, and milestones. Write executive summary. This is the FINAL assessment deliverable.

### TASK-6-003: Final Security Report & Executive Summary
- **Status**: [ ] PENDING
- **Agent/Team**: Orchestrator
- **Phase**: 6
- **Priority**: CRITICAL
- **Depends On**: TASK-6-002
- **Input Files**: `findings/SECURITY_REPORT.md`, `findings/SUMMARY.md`, `findings/teams/T12-launch-readiness.md`
- **Output Files**: `findings/SECURITY_REPORT.md` (final version), `findings/SUMMARY.md` (final version)
- **Skills**: `/skill-risk-matrix-generator`, `/skill-remediation-roadmap-builder`
- **Started**:
- **Completed**:
- **Findings Count**: 0
- **Notes**: Finalize SECURITY_REPORT.md with all sections complete. Finalize SUMMARY.md with executive summary, risk matrix, go/no-go recommendation. This is the last task — assessment is complete when this is DONE.

---

## COVERAGE VERIFICATION

### Agents (16/16)
- [x] A01 Crypto Primitives → TASK-1-001 through TASK-1-005
- [x] A02 Cross-Language Parity → TASK-1-006 through TASK-1-009
- [x] A03 Memory Safety → TASK-1-010 through TASK-1-013
- [x] A04 Input Validation → TASK-2-001 through TASK-2-003
- [x] A05 Docker & Container → TASK-2-004 through TASK-2-006
- [x] A06 Web Integration → TASK-2-007 through TASK-2-009
- [x] A07 Auth & Session → TASK-2-010 through TASK-2-013
- [x] A08 Transport Protocol → TASK-2-014 through TASK-2-016
- [x] A09 Browser & WASM → TASK-2-017 through TASK-2-019
- [x] A10 CI/CD & Supply Chain → TASK-2-020 through TASK-2-022
- [x] A11 Error Disclosure → TASK-2-023 through TASK-2-025
- [x] A12 Mobile Platform → TASK-3-001 through TASK-3-002
- [x] A13 Confidential TEE → TASK-3-003 through TASK-3-005
- [x] A14 Streaming & Group → TASK-3-006 through TASK-3-007
- [x] A15 Signatures & 2FA → TASK-3-008 through TASK-3-009
- [x] A16 Fingerprint → TASK-3-010 through TASK-3-011

### Teams (7/7)
- [x] T06 Crypto Oracle & Error Leakage → TASK-4-001
- [x] T07 Supply Chain to Runtime → TASK-4-002
- [x] T08 Cross-Language Interop Exploit → TASK-4-003
- [x] T09 Key Lifecycle & Exposure → TASK-5-001
- [x] T10 Auth & Transport MITM → TASK-5-002
- [x] T11 Config & Deployment Drift → TASK-4-004
- [x] T12 Launch Readiness → TASK-6-002

### Phase Dependencies (Acyclic ✓)
```
TASK-0-* → TASK-1-* → TASK-1-014 → TASK-2-* → TASK-2-026 → TASK-3-* → TASK-3-012 → TASK-4-* → TASK-4-005 → TASK-5-* → TASK-5-003 → TASK-6-001 → TASK-6-002 → TASK-6-003
```

### Task Count Summary
| Phase | Tasks | Agents/Teams |
|-------|-------|-------------|
| 0 (Setup) | 3 | Orchestrator |
| 1 (Crypto Core) | 14 | A01, A02, A03 + Checkpoint |
| 2 (Protocol/App/Infra) | 26 | A04-A11 + Checkpoint |
| 3 (Platform/HW) | 12 | A12-A16 + Checkpoint |
| 4 (Cross-Domain 1) | 5 | T06, T07, T08, T11 + Checkpoint |
| 5 (Cross-Domain 2) | 3 | T09, T10 + Checkpoint |
| 6 (Final) | 3 | Dedup + T12 + Final Report |
| **TOTAL** | **66** | **16 agents + 7 teams** |
