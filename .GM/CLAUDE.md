# CLAUDE.md — Shield Security Assessment

**Project**: Shield — 12-language symmetric encryption library
**Crypto stack**: PBKDF2-SHA256 (100k iterations) → SHA256-CTR → HMAC-SHA256 (128-bit truncated)
**Wire format**: `nonce(16 bytes) || ciphertext || MAC(16 bytes)`

## Mission

Enterprise security assessment of Shield before launch. Zero-miss requirement.
16 agents audit individual domains. 7 cross-domain teams audit attack chains.
42 skills provide reusable procedures. All findings go to `findings/`.

---

## Repository Structure

| Directory | Focus |
|-----------|-------|
| `shield-core/` | Rust core library + CLI (single source of truth) |
| `browser/` | Browser SDK (auto-decrypt fetch with WASM) |
| `android/` | Android SDK (Keystore + biometric) |
| `ios/` | iOS SDK (Keychain + Face ID/Touch ID) |
| `python/` | Python package (pip install shield-crypto) |
| `javascript/` | JavaScript/Node.js (@guard8/shield) |
| `go/` | Go module |
| `c/` | C library (libshield) |
| `java/` | Java/Gradle |
| `csharp/` | C#/.NET |
| `swift/` | Swift Package |
| `kotlin/` | Kotlin/JVM |
| `wasm/` | WebAssembly (re-exports shield-core) |
| `examples/` | Usage examples (browser, hsm, confidential-computing) |
| `tests/` | Cross-language interoperability tests |
| `findings/` | **Security assessment output** |
| `.GM/` | **Recon docs, agent/team/skill maps** |

---

## Crypto Parameters

| Parameter | Value |
|-----------|-------|
| Key derivation | PBKDF2-SHA256, 100,000 iterations |
| Key size | 256 bits |
| Nonce | 128 bits (random per message) |
| MAC | HMAC-SHA256, truncated to 128 bits |
| Wire format | nonce(16) ‖ ciphertext ‖ MAC(16) |
| Encryption flow | Password → PBKDF2 → Key → SHA256-CTR + HMAC-SHA256 → Ciphertext |

---

## Running Tests

```bash
cd shield-core && cargo test --features confidential   # Rust (95 tests)
cd python && python -m pytest                           # Python (153 tests)
cd javascript && npm test                               # JavaScript (81 tests)
cd go && go test ./...                                  # Go (31 tests)
cd c && make test                                       # C (16 tests)
cd java && gradle test                                  # Java (19 tests)
cd wasm && cargo test                                   # WASM
```

---

## Assessment Arsenal

### Agents (16)

| # | Agent | Priority | File |
|---|-------|----------|------|
| 1 | Crypto Primitives | CRITICAL | `.claude/agents/security-crypto-primitives.md` |
| 2 | Cross-Language Parity | CRITICAL | `.claude/agents/security-cross-language.md` |
| 3 | Memory Safety | CRITICAL | `.claude/agents/security-memory-safety.md` |
| 4 | Input Validation | CRITICAL | `.claude/agents/security-input-validation.md` |
| 5 | Docker & Container | CRITICAL | `.claude/agents/security-docker-container.md` |
| 6 | Web Integration | HIGH | `.claude/agents/security-web-integration.md` |
| 7 | Auth & Session | HIGH | `.claude/agents/security-auth-session.md` |
| 8 | Transport Protocol | HIGH | `.claude/agents/security-transport-protocol.md` |
| 9 | Browser & WASM | HIGH | `.claude/agents/security-browser-wasm.md` |
| 10 | CI/CD & Supply Chain | HIGH | `.claude/agents/security-cicd-supply-chain.md` |
| 11 | Error Disclosure | HIGH | `.claude/agents/security-error-disclosure.md` |
| 12 | Mobile Platform | MEDIUM | `.claude/agents/security-mobile-platform.md` |
| 13 | Confidential TEE | MEDIUM | `.claude/agents/security-confidential-tee.md` |
| 14 | Streaming & Group | MEDIUM | `.claude/agents/security-streaming-group.md` |
| 15 | Signatures & 2FA | MEDIUM | `.claude/agents/security-signatures-2fa.md` |
| 16 | Fingerprint | MEDIUM | `.claude/agents/security-fingerprint.md` |

### Cross-Domain Teams (7)

| Team | Name | Priority | Phase | File |
|------|------|----------|-------|------|
| T6 | Crypto Oracle & Error Leakage | CRITICAL | 4 | `.claude/agents/team-6-crypto-oracle-error.md` |
| T7 | Supply Chain to Runtime | HIGH | 4 | `.claude/agents/team-7-supply-chain-runtime.md` |
| T8 | Cross-Language Interop Exploit | CRITICAL | 4 | `.claude/agents/team-8-cross-lang-interop.md` |
| T9 | Key Lifecycle & Exposure | CRITICAL | 5 | `.claude/agents/team-9-key-lifecycle.md` |
| T10 | Auth & Transport MITM | HIGH | 5 | `.claude/agents/team-10-auth-transport-mitm.md` |
| T11 | Config & Deployment Drift | HIGH | 4 | `.claude/agents/team-11-config-deployment-drift.md` |
| T12 | Launch Readiness (Go/No-Go) | CRITICAL | 6 | `.claude/agents/team-12-launch-readiness.md` |

### Skills (top 10 — full registry: `.GM/skills-map.md`, 42 skills)

| Need | Skill |
|------|-------|
| Navigate codebase | `/skill-shield-file-navigator` |
| Scan across languages | `/skill-multi-lang-symbol-scanner` |
| Detect CWE patterns | `/skill-cwe-pattern-detector` |
| Format a finding | `/skill-finding-formatter` |
| Generate finding ID | `/skill-finding-id-generator` |
| Collect evidence | `/skill-evidence-snapshot-collector` |
| Build attack chain | `/skill-attack-chain-builder` |
| Deduplicate findings | `/skill-finding-deduplicator` |
| Generate risk matrix | `/skill-risk-matrix-generator` |
| Track audit progress | `/skill-audit-progress-tracker` |

---

## How To Execute

### Run a Single Agent

1. Read agent file: `.claude/agents/security-{name}.md`
2. Read `.GM/SHIELD_SECURITY_CONTEXT.md` for recon data
3. Follow the Audit Checklist in agent file item by item
4. Use skills listed in the agent (invoke via Skill tool)
5. Generate finding IDs with `/skill-finding-id-generator`, format with `/skill-finding-formatter`
6. Write findings to `findings/agents/A{##}-{name}.md`

### Run a Cross-Domain Team

1. Read team file: `.claude/agents/team-{N}-{name}.md`
2. Read ALL input agent findings from `findings/agents/`
3. Follow the Coordination Flow in the team file
4. Build attack chains with `/skill-attack-chain-builder`
5. Cross-reference agent findings by `SHIELD-A##-###` ID — never duplicate
6. Write findings to `findings/teams/T{##}-{name}.md`

### Use a Skill

Invoke via the Skill tool: `/skill-name` (e.g., `/skill-cwe-pattern-detector`)

### Spawn Parallel Workers

Use the Agent tool with `subagent_type="general-purpose"`. Pass agent `.md` content as prompt instructions. Use `isolation: "worktree"` for file-writing agents.

---

## Execution Phases

```
Phase 1 (BLOCKING):  Agents 1, 2, 3         → Crypto Core
Phase 2 (PARALLEL):  Agents 4-11            → Protocol + App + Infra
Phase 3 (PARALLEL):  Agents 12-16           → Platform & HW
Phase 4 (PARALLEL):  Teams 6, 7, 8, 11      → Cross-domain batch 1
Phase 5 (PARALLEL):  Teams 9, 10            → Cross-domain batch 2
Phase 6 (FINAL):     Team 12                → Go/No-Go
```

**Dependencies**: Phase N+1 requires Phase N findings written. Teams consume agent findings as input. Team 12 consumes ALL team findings.

---

## Findings Directory & Output Format

### Directory Structure

```
findings/
  agents/          # A01-A16, one file per agent
  teams/           # T06-T12, one file per team
  SUMMARY.md       # Team 12 final output (go/no-go)
```

### Finding ID Format

`SHIELD-{SOURCE}-{SEQ}` — e.g., `SHIELD-A01-001`, `SHIELD-T08-003`

### Finding Template

```markdown
### SHIELD-A01-001: [Title]
- **Severity**: CRITICAL | HIGH | MEDIUM | LOW | INFO
- **CWE**: CWE-XXX
- **Location**: `file/path.ext:line`
- **Evidence**: code snippet or output
- **Impact**: what attacker achieves
- **Reproduction**: steps to reproduce
- **Fix Complexity**: LOW | MEDIUM | HIGH
- **Remediation**: specific fix steps
```

### Severity Criteria

| Severity | Criteria |
|----------|----------|
| CRITICAL | Direct key/plaintext exposure, authentication bypass, RCE |
| HIGH | Partial key leakage, timing oracle, weak crypto parameter |
| MEDIUM | Information disclosure, missing hardening, config drift |
| LOW | Minor best-practice deviation, defense-in-depth gap |

---

## Reference Files

| File | Contains |
|------|----------|
| `.GM/SHIELD_SECURITY_CONTEXT.md` | Full recon: tech inventory, architecture, attack surface, deps, risk hotspots |
| `.GM/agent-map.md` | Agent registry, execution phases, file ownership matrix |
| `.GM/agent-teams-map.md` | 12 teams, execution DAG, participation matrix, dedup strategy |
| `.GM/skills-map.md` | 42 skills, layer architecture, agent-to-skill mapping |

**When to read**: Read `SHIELD_SECURITY_CONTEXT.md` before any agent run. Read `agent-map.md` to understand phase dependencies. Read `skills-map.md` to find the right skill for a task.

---

## Rules of Engagement

1. **EVIDENCE OVER OPINION** — every finding requires `file:line` + code snippet
2. **CWE MAPPING REQUIRED** — no finding without a CWE ID
3. **CROSS-REFERENCE, NEVER DUPLICATE** — teams reference agent finding IDs, don't re-report
4. **SEVERITY ESCALATION** — cross-domain chains use highest component severity
5. **CONTRADICTIONS FLAGGED** — disagreements between agents flagged for manual review
6. **KNOWN FINDINGS FIRST** — verify known issues from recon before scanning for new ones
7. **SKILLS FOR HOW** — use the 42 skills, don't reinvent procedures
8. **WRITE AS YOU GO** — don't batch findings, write each as discovered
9. **PHASE GATES** — don't start Phase N+1 until Phase N findings are written
10. **NO FIXES WITHOUT APPROVAL** — findings only, no code changes unless explicitly approved
