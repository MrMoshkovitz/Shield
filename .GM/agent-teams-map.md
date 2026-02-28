# Shield Security Agent Teams

> 12 teams (5 domain + 7 cross-domain), 16 agents, 6 execution phases

---

## Domain Teams (Phase 1-3)

### Team 1: Crypto Core
**Phase**: 1 (BLOCKING — must complete before Phase 2)
**Focus**: Cryptographic correctness, cross-language parity, memory safety

| Agent # | Agent File | Role in Team |
|---------|-----------|-------------|
| 1 | `security-crypto-primitives.md` | Audit all crypto primitives (PBKDF2, CTR, HMAC) across 12 languages |
| 2 | `security-cross-language.md` | Verify byte-identical parity across all implementations |
| 3 | `security-memory-safety.md` | Audit key lifecycle, buffer safety, zeroization |

**Handoff**: Findings from Team 1 inform all Phase 2 teams on crypto assumptions.

---

### Team 2: Protocol & Data
**Phase**: 2 (PARALLEL — after Phase 1)
**Focus**: Transport security, input handling, streaming, signatures

| Agent # | Agent File | Role in Team |
|---------|-----------|-------------|
| 8 | `security-transport-protocol.md` | Audit ShieldChannel, PAKE handshake, RatchetSession |
| 4 | `security-input-validation.md` | Audit all input parsing and validation paths |
| 14 | `security-streaming-group.md` | Audit StreamCipher and GroupEncryption |
| 15 | `security-signatures-2fa.md` | Audit signature schemes and TOTP/recovery codes |

**Dependencies**: Requires Agent 1 findings on crypto primitive correctness.

---

### Team 3: Application
**Phase**: 2 (PARALLEL — after Phase 1)
**Focus**: Web frameworks, authentication, browser, error handling

| Agent # | Agent File | Role in Team |
|---------|-----------|-------------|
| 6 | `security-web-integration.md` | Audit FastAPI/Flask/Express middleware |
| 7 | `security-auth-session.md` | Audit tokens, rate limiting, identity |
| 9 | `security-browser-wasm.md` | Audit browser SDK, WASM, fetch hook |
| 11 | `security-error-disclosure.md` | Audit error messages across all 12 impls |
| 4 | `security-input-validation.md` | **(Secondary)** Input validation in middleware paths |

**Dependencies**: Requires Agent 3 findings on WASM memory safety.

---

### Team 4: Infrastructure
**Phase**: 2 (PARALLEL — after Phase 1)
**Focus**: Docker hardening, CI/CD pipeline, supply chain

| Agent # | Agent File | Role in Team |
|---------|-----------|-------------|
| 5 | `security-docker-container.md` | Audit all Dockerfiles, compose, opaque containers |
| 10 | `security-cicd-supply-chain.md` | Audit GitHub Actions, dependencies, release signing |

**Dependencies**: None (can run independently).

---

### Team 5: Platform & HW
**Phase**: 3 (PARALLEL — after Phase 2)
**Focus**: Mobile SDKs, TEE attestation, device fingerprinting

| Agent # | Agent File | Role in Team |
|---------|-----------|-------------|
| 12 | `security-mobile-platform.md` | Audit Android Keystore, iOS Keychain, biometrics |
| 13 | `security-confidential-tee.md` | Audit Nitro/SEV/MAA/SGX attestation and sealed storage |
| 16 | `security-fingerprint.md` | Audit device fingerprinting, MD5, command injection |
| 7 | `security-auth-session.md` | **(Secondary)** Auth state in mobile/TEE key management |

**Dependencies**: Requires Agent 1 findings on crypto used in mobile/TEE.

---

## Cross-Domain Teams (Phase 4-6)

### Team 6: Crypto Oracle & Error Leakage
**Phase**: 4 | **Priority**: CRITICAL | **File**: `team-6-crypto-oracle-error.md`
**Chain**: Error messages + middleware behavior → crypto oracle attack

| Role | Agent # | Agent File |
|------|---------|-----------|
| Lead | 1 | `security-crypto-primitives.md` |
| Support | 11 | `security-error-disclosure.md` |
| Support | 6 | `security-web-integration.md` |
| Support | 4 | `security-input-validation.md` |

---

### Team 7: Supply Chain to Runtime
**Phase**: 4 | **Priority**: HIGH | **File**: `team-7-supply-chain-runtime.md`
**Chain**: CI/CD compromise → deployment → runtime crypto corruption

| Role | Agent # | Agent File |
|------|---------|-----------|
| Lead | 10 | `security-cicd-supply-chain.md` |
| Support | 5 | `security-docker-container.md` |
| Support | 9 | `security-browser-wasm.md` |

---

### Team 8: Cross-Language Interop Exploit
**Phase**: 4 | **Priority**: CRITICAL | **File**: `team-8-cross-lang-interop.md`
**Chain**: Behavioral divergences across 12 impls → interop exploitation

| Role | Agent # | Agent File |
|------|---------|-----------|
| Lead | 2 | `security-cross-language.md` |
| Support | 4 | `security-input-validation.md` |
| Support | 11 | `security-error-disclosure.md` |
| Support | 14 | `security-streaming-group.md` |

---

### Team 9: Key Lifecycle & Exposure
**Phase**: 5 | **Priority**: CRITICAL | **File**: `team-9-key-lifecycle.md`
**Chain**: Key extraction at any lifecycle point → forge/decrypt

| Role | Agent # | Agent File |
|------|---------|-----------|
| Lead | 3 | `security-memory-safety.md` |
| Support | 12 | `security-mobile-platform.md` |
| Support | 9 | `security-browser-wasm.md` |
| Support | 7 | `security-auth-session.md` |
| Support | 13 | `security-confidential-tee.md` |

---

### Team 10: Auth & Transport MITM
**Phase**: 5 | **Priority**: HIGH | **File**: `team-10-auth-transport-mitm.md`
**Chain**: MITM → session compromise → device rebinding → identity takeover

| Role | Agent # | Agent File |
|------|---------|-----------|
| Lead | 8 | `security-transport-protocol.md` |
| Support | 7 | `security-auth-session.md` |
| Support | 16 | `security-fingerprint.md` |
| Support | 15 | `security-signatures-2fa.md` |

---

### Team 11: Config & Deployment Drift
**Phase**: 4 | **Priority**: HIGH | **File**: `team-11-config-deployment-drift.md`
**Chain**: Dev config differences → production security gaps

| Role | Agent # | Agent File |
|------|---------|-----------|
| Lead | 5 | `security-docker-container.md` |
| Support | 10 | `security-cicd-supply-chain.md` |
| Support | 6 | `security-web-integration.md` |
| Support | 11 | `security-error-disclosure.md` |

---

### Team 12: Launch Readiness (Meta-Team)
**Phase**: 6 (FINAL) | **Priority**: CRITICAL | **File**: `team-12-launch-readiness.md`
**Purpose**: Aggregate, deduplicate, prioritize ALL findings → Go/No-Go

| Role | Input |
|------|-------|
| Lead | Orchestrator |
| Input | All 11 teams' complete findings |

---

## Execution DAG

```
                    ┌─────────────────────────────────┐
                    │  Phase 1 (BLOCKING)              │
                    │  Team 1: Crypto Core             │
                    │  [Agents 1, 2, 3]                │
                    └────────────┬────────────────────┘
                                 ▼
       ┌──────────────────────────────────────────────────────────┐
       │  Phase 2 (PARALLEL) — Domain Audit                       │
       │                                                          │
       │  Team 2: Protocol    Team 3: Application    Team 4: Infra│
       │  [8, 4, 14, 15]     [6, 7, 9, 11, +4]     [5, 10]      │
       └────────────────────────┬─────────────────────────────────┘
                                ▼
       ┌──────────────────────────────────────────────────────────┐
       │  Phase 3 (PARALLEL) — Platform Audit                     │
       │                                                          │
       │  Team 5: Platform & HW [12, 13, 16, +7]                 │
       └────────────────────────┬─────────────────────────────────┘
                                ▼
       ┌──────────────────────────────────────────────────────────┐
       │  Phase 4 (PARALLEL) — Cross-Domain Batch 1               │
       │                                                          │
       │  Team 6: Crypto     Team 7: Supply   Team 8: Cross-Lang │
       │  Oracle & Error     Chain→Runtime    Interop Exploit     │
       │  [1,11,6,4]        [10,5,9]         [2,4,11,14]         │
       │                                                          │
       │  Team 11: Config & Deployment Drift [5,6,10,11]          │
       └────────────────────────┬─────────────────────────────────┘
                                ▼
       ┌──────────────────────────────────────────────────────────┐
       │  Phase 5 (PARALLEL) — Cross-Domain Batch 2               │
       │                                                          │
       │  Team 9: Key Lifecycle     Team 10: Auth & Transport     │
       │  & Exposure                MITM Chain                    │
       │  [3,12,9,7,13]            [8,7,16,15]                   │
       └────────────────────────┬─────────────────────────────────┘
                                ▼
       ┌──────────────────────────────────────────────────────────┐
       │  Phase 6 (FINAL) — Launch Readiness                      │
       │                                                          │
       │  Team 12: Go/No-Go Assessment [ALL findings]             │
       └──────────────────────────────────────────────────────────┘
```

---

## Agent Participation Matrix

| Agent | Domain Team | Cross-Domain Team(s) |
|-------|------------|---------------------|
| 1 (crypto-primitives) | Team 1 | Team 6 (lead) |
| 2 (cross-language) | Team 1 | Team 8 (lead) |
| 3 (memory-safety) | Team 1 | Team 9 (lead) |
| 4 (input-validation) | Team 2 | Team 6, Team 8, Team 3 (secondary) |
| 5 (docker-container) | Team 4 | Team 7, Team 11 (lead) |
| 6 (web-integration) | Team 3 | Team 6, Team 11 |
| 7 (auth-session) | Team 3 | Team 9, Team 10, Team 5 (secondary) |
| 8 (transport-protocol) | Team 2 | Team 10 (lead) |
| 9 (browser-wasm) | Team 3 | Team 7, Team 9 |
| 10 (cicd-supply-chain) | Team 4 | Team 7 (lead), Team 11 |
| 11 (error-disclosure) | Team 3 | Team 6, Team 8, Team 11 |
| 12 (mobile-platform) | Team 5 | Team 9 |
| 13 (confidential-tee) | Team 5 | Team 9 |
| 14 (streaming-group) | Team 2 | Team 8 |
| 15 (signatures-2fa) | Team 2 | Team 10 |
| 16 (fingerprint) | Team 5 | Team 10 |

Every agent: exactly 1 domain team + 1-3 cross-domain teams.

---

## Pairwise Domain Coverage

| Domain A × Domain B | Chain | Team |
|---------------------|-------|------|
| Crypto × Web middleware | Crypto oracle via error leak | Team 6 |
| Crypto × Transport | PAKE key compromise → crypto break | Team 10 |
| Crypto × Cross-language | Interop exploit via divergence | Team 8 |
| Crypto × Memory | Key lifecycle exposure | Team 9 |
| Web × Docker | Config drift dev→prod | Team 11 |
| Web × CI/CD | Config drift via deployment | Team 11 |
| Web × Browser | Key exchange MITM | Team 9 |
| CI/CD × Docker | Supply chain → deployment | Team 7 |
| CI/CD × WASM | Tampered build → runtime | Team 7 |
| Auth × Transport | MITM → session compromise | Team 10 |
| Auth × Fingerprint | Device binding bypass | Team 10 |
| Mobile × Memory | Mobile key storage → extraction | Team 9 |
| TEE × Memory | Sealed storage → key extraction | Team 9 |
| Error × Crypto | Error oracle attack | Team 6 |
| Streaming × Cross-lang | Chunk handling divergence | Team 8 |
| Signatures × Transport | Forgery after MITM key compromise | Team 10 |

---

## Dedup Strategy

| Scenario | Action |
|----------|--------|
| Domain + cross-domain find same issue | Cross-domain REFERENCES domain finding by ID |
| Chain escalates severity | Consolidated severity = highest in chain |
| Multiple chains share root cause | Single root cause, multiple chain references |
| Contradictory findings | Flag for manual review |

---

## Coverage Summary

| Standard | Coverage | Teams |
|----------|---------|-------|
| OWASP Top 10 (2021) | 10/10 | All domain teams |
| OWASP API Security Top 10 | 10/10 | Teams 2, 3, 4 |
| CWE Top 25 | 23/25 | All domain teams |
| CIS Docker Benchmark | Partial | Team 4 (Agent 5) |
| NIST 800-57 Key Management | Partial | Team 1 (Agents 1, 3) |
| RFC 6238 (TOTP) | Full | Agent 15 |
| Cross-domain attack chains | 16/16 pairwise | Teams 6-11 |
