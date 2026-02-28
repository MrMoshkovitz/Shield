# Shield Security Agent Map

> 16 security agents covering OWASP Top 10, API Security Top 10, and CWE Top 25
> Each agent: 1 domain team + 1-3 cross-domain teams

## Agent Registry

| # | Agent File | Priority | Domain Team | Cross-Domain Team(s) |
|---|-----------|----------|-------------|---------------------|
| 1 | `security-crypto-primitives.md` | CRITICAL | Team 1: Crypto Core | Team 6 (lead) |
| 2 | `security-cross-language.md` | CRITICAL | Team 1: Crypto Core | Team 8 (lead) |
| 3 | `security-memory-safety.md` | CRITICAL | Team 1: Crypto Core | Team 9 (lead) |
| 4 | `security-input-validation.md` | CRITICAL | Team 2: Protocol & Data | Team 6, Team 8, Team 3 (secondary) |
| 5 | `security-docker-container.md` | CRITICAL | Team 4: Infrastructure | Team 7, Team 11 (lead) |
| 6 | `security-web-integration.md` | HIGH | Team 3: Application | Team 6, Team 11 |
| 7 | `security-auth-session.md` | HIGH | Team 3: Application | Team 9, Team 10, Team 5 (secondary) |
| 8 | `security-transport-protocol.md` | HIGH | Team 2: Protocol & Data | Team 10 (lead) |
| 9 | `security-browser-wasm.md` | HIGH | Team 3: Application | Team 7, Team 9 |
| 10 | `security-cicd-supply-chain.md` | HIGH | Team 4: Infrastructure | Team 7 (lead), Team 11 |
| 11 | `security-error-disclosure.md` | HIGH | Team 3: Application | Team 6, Team 8, Team 11 |
| 12 | `security-mobile-platform.md` | MEDIUM | Team 5: Platform & HW | Team 9 |
| 13 | `security-confidential-tee.md` | MEDIUM | Team 5: Platform & HW | Team 9 |
| 14 | `security-streaming-group.md` | MEDIUM | Team 2: Protocol & Data | Team 8 |
| 15 | `security-signatures-2fa.md` | MEDIUM | Team 2: Protocol & Data | Team 10 |
| 16 | `security-fingerprint.md` | MEDIUM | Team 5: Platform & HW | Team 10 |

## Execution Phases

```
Phase 1 (BLOCKING):  Agents 1, 2, 3       → Core crypto + memory safety
    ↓
Phase 2 (PARALLEL):  Agents 4-11          → Protocol, app, infrastructure
    ↓
Phase 3 (PARALLEL):  Agents 12-16         → Platform & advanced features
    ↓
Phase 4 (PARALLEL):  Teams 6, 7, 8, 11    → Cross-domain batch 1
    ↓
Phase 5 (PARALLEL):  Teams 9, 10          → Cross-domain batch 2
    ↓
Phase 6 (FINAL):     Team 12              → Launch readiness go/no-go
```

## File Ownership Quick Reference

| Codebase Area | Primary Agent | Secondary |
|---------------|--------------|-----------|
| `shield-core/src/shield.rs` | 1 | 2, 3, 4 |
| `python/shield/core.py` | 1 | 2, 3, 4 |
| `javascript/src/shield.js` | 1 | 2, 4, 11 |
| `c/src/shield.c` | 1 | 2, 3 |
| `c/src/shield_fingerprint.c` | 3 | 16 |
| `go/shield/shield.go` | 2 | 1 |
| `java/.../Shield.java` | 2 | 1 |
| `csharp/Shield/Shield.cs` | 2 | 1 |
| `swift/.../Shield.swift` | 2 | 1 |
| `kotlin/.../Shield.kt` | 2 | 1 |
| `python/shield/integrations/fastapi.py` | 6 | 7, 11 |
| `python/shield/integrations/flask.py` | 6 | 7 |
| `python/shield/integrations/protection.py` | 7 | 6 |
| `python/shield/integrations/browser.py` | 9 | 6, 7 |
| `javascript/integrations/express.js` | 6 | 11 |
| `browser/js/fetch-hook.ts` | 9 | 6 |
| `browser/js/index.ts` | 9 | — |
| `shield-core/src/channel.rs` | 8 | — |
| `shield-core/src/channel_async.rs` | 8 | — |
| `shield-core/src/ratchet.rs` | 8 | 3 |
| `shield-core/src/exchange.rs` | 8 | — |
| `shield-core/src/stream.rs` | 14 | — |
| `shield-core/src/group.rs` | 14 | — |
| `shield-core/src/totp.rs` | 15 | 7 |
| `shield-core/src/signatures.rs` | 15 | — |
| `shield-core/src/identity.rs` | 7 | 11 |
| `shield-core/src/fingerprint.rs` | 16 | — |
| `shield-core/src/wasm.rs` | 9 | 3 |
| `shield-core/src/error.rs` | 11 | 4 |
| `shield-core/src/confidential/*.rs` | 13 | — |
| `python/.../confidential/*.py` | 13 | — |
| `shield-core/src/fido2/*.rs` | 7 | — |
| `android/.../shield/src/**` | 12 | — |
| `ios/Sources/Shield/**` | 12 | — |
| `Dockerfile` | 5 | — |
| `docker-compose.yml` | 5 | — |
| `examples/opaque-containers/*` | 5 | — |
| `.github/workflows/*.yml` | 10 | — |
| `shield-core/Cargo.toml` | 10 | — |
| `c/Makefile` | 10 | 3 |

## Coverage Validation

- **OWASP Top 10 (2021)**: 10/10 covered
- **OWASP API Security Top 10**: 10/10 covered
- **CWE Top 25**: 23/25 covered (N/A: SQL injection, file upload)
- **All entry points from SHIELD_SECURITY_CONTEXT.md**: covered
- **Cross-domain pairwise coverage**: 16/16 realistic pairs covered (Teams 6-11)
