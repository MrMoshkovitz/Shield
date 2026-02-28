# Shield Security Skills Map

> 42 security assessment skills organized by layer and category
> Skills are in `~/.claude/skills/{skill-name}/SKILL.md`

## Complete Skills Registry

| # | Skill Name | Category | Layer | Used By |
|---|-----------|----------|-------|---------|
| 1 | skill-pbkdf2-param-auditor | Crypto Validation | L2 | A1, A2, T8 |
| 2 | skill-function-diff-comparator | Code Analysis | L2 | A2, A14, T8 |
| 3 | skill-cwe-pattern-detector | Basic Scanning | L1 | A3, A4, A16, A11 |
| 4 | skill-error-message-cataloger | Code Analysis | L2 | A11, A6, T6 |
| 5 | skill-multi-lang-symbol-scanner | Basic Scanning | L1 | A1-A4, A14, A15, T8, T9 |
| 6 | skill-key-accessor-mapper | Basic Scanning | L1 | A3, A9, T9 |
| 7 | skill-constant-time-verifier | Code Analysis | L2 | A1, A2, A8, A11 |
| 8 | skill-cross-lang-constant-audit | Code Analysis | L2 | A1, A2, T8 |
| 9 | skill-ctr-mode-verifier | Crypto Validation | L2 | A1, A2, A14 |
| 10 | skill-mac-verification-auditor | Crypto Validation | L2 | A1, A2, A8 |
| 11 | skill-nonce-generation-auditor | Crypto Validation | L2 | A1, A2 |
| 12 | skill-zeroization-verifier | Crypto Validation | L2 | A3, T9 |
| 13 | skill-protocol-handshake-tracer | Protocol | L2 | A8, T10 |
| 14 | skill-dockerfile-security-auditor | Infrastructure | L2 | A5, T7, T11 |
| 15 | skill-github-actions-auditor | Infrastructure | L2 | A10, T7 |
| 16 | skill-shell-script-injection-checker | Infrastructure | L2 | A5, A10, A16 |
| 17 | skill-dependency-audit-scanner | Basic Scanning | L1 | A10, T7 |
| 18 | skill-cookie-security-auditor | Application | L2 | A6, A7 |
| 19 | skill-route-exclusion-bypass-checker | Application | L2 | A6 |
| 20 | skill-middleware-error-propagation-tracer | Application | L2 | A6, A11, T6 |
| 21 | skill-token-lifecycle-auditor | Application | L2 | A7, T10 |
| 22 | skill-totp-rfc-compliance-checker | Application | L2 | A7, A15 |
| 23 | skill-rate-limiter-bypass-analyzer | Application | L2 | A7, T6 |
| 24 | skill-android-keystore-auditor | Platform | L2 | A12, T9 |
| 25 | skill-ios-keychain-auditor | Platform | L2 | A12, T9 |
| 26 | skill-tee-attestation-auditor | Platform | L2 | A13, T9 |
| 27 | skill-fingerprint-security-assessor | Platform | L2 | A16, A3 |
| 28 | skill-wasm-memory-isolation-checker | Platform | L2 | A9, A3, T9 |
| 29 | skill-crypto-oracle-feasibility-assessor | Cross-Domain | L3 | T6 |
| 30 | skill-interop-exploit-matrix-builder | Cross-Domain | L3 | T8 |
| 31 | skill-key-exposure-surface-mapper | Cross-Domain | L3 | T9, A3 |
| 32 | skill-attack-chain-builder | Cross-Domain | L3 | T6-T12 |
| 33 | skill-config-drift-detector | Cross-Domain | L3 | T11 |
| 34 | skill-shield-file-navigator | Foundation | L0 | All agents, All teams |
| 35 | skill-finding-deduplicator | Reporting | L3 | T12 |
| 36 | skill-risk-matrix-generator | Reporting | L3 | T12 |
| 37 | skill-finding-formatter | Foundation | L0 | All agents, All teams |
| 38 | skill-remediation-roadmap-builder | Reporting | L3 | T12 |
| 39 | skill-finding-id-generator | Foundation | L0 | All agents, All teams |
| 40 | skill-test-vector-generator | Utility | L2 | A2, A4, T8 |
| 41 | skill-evidence-snapshot-collector | Foundation | L0 | All agents, All teams |
| 42 | skill-audit-progress-tracker | Reporting | L3 | T12, Orchestrator |

## Layer Architecture

```
L3: Cross-Domain & Reporting  (#29-33, #35-36, #38, #42)
    depends on
L2: Domain-Specific Skills     (#1-2, #4, #7-16, #18-28, #40)
    depends on
L1: Basic Scanning             (#3, #5, #6, #17)
    depends on
L0: Foundation                 (#34, #37, #39, #41)
```

| Layer | Count | Purpose |
|-------|-------|---------|
| L0 | 4 | Navigation, formatting, IDs, evidence -- used by everything |
| L1 | 4 | Pattern scanning, symbol search, dependency audit |
| L2 | 26 | Domain-specific auditors and validators |
| L3 | 8 | Cross-domain analysis, reporting, consolidation |

## Category Groupings

| Category | Skills | Count |
|----------|--------|-------|
| Foundation | #34, #37, #39, #41 | 4 |
| Basic Scanning | #3, #5, #6, #17 | 4 |
| Crypto Validation | #1, #9, #10, #11, #12 | 5 |
| Code Analysis | #2, #4, #7, #8 | 4 |
| Infrastructure | #14, #15, #16 | 3 |
| Application | #18, #19, #20, #21, #22, #23 | 6 |
| Platform | #24, #25, #26, #27, #28 | 5 |
| Protocol | #13 | 1 |
| Cross-Domain | #29, #30, #31, #32, #33 | 5 |
| Reporting | #35, #36, #38, #42 | 4 |
| Utility | #40 | 1 |

## Agent-to-Skill Coverage Matrix

| Agent | Primary Skills | Supporting Skills |
|-------|---------------|-------------------|
| A1 (Crypto Primitives) | #1, #9, #10, #11 | #5, #7, #8, #34 |
| A2 (Cross-Language) | #2, #8, #30 | #1, #5, #9, #10, #11, #40 |
| A3 (Memory Safety) | #3, #12, #27 | #5, #6, #31 |
| A4 (Input Validation) | #3, #40 | #4, #5 |
| A5 (Docker/Container) | #14 | #16 |
| A6 (Web Integration) | #18, #19, #20 | #4 |
| A7 (Auth & Session) | #21, #22, #23 | #18 |
| A8 (Transport Protocol) | #13 | #7, #10 |
| A9 (Browser & WASM) | #28 | #6 |
| A10 (CI/CD Supply Chain) | #15, #17 | #16 |
| A11 (Error Disclosure) | #4, #20 | #3, #7 |
| A12 (Mobile Platform) | #24, #25 | -- |
| A13 (Confidential TEE) | #26 | -- |
| A14 (Streaming/Group) | #9 | #2, #5 |
| A15 (Signatures/2FA) | #22 | #5 |
| A16 (Fingerprint) | #27 | #3, #16 |

## Team-to-Skill Coverage Matrix

| Team | Primary Skills | Supporting Skills |
|------|---------------|-------------------|
| T6 (Crypto Oracle) | #29 | #4, #20, #23, #32 |
| T7 (Supply Chain) | #14, #15, #17 | #32 |
| T8 (Cross-Lang Interop) | #30, #40 | #1, #2, #5, #8 |
| T9 (Key Lifecycle) | #31 | #6, #12, #24, #25, #26, #28 |
| T10 (Auth Transport MITM) | #13, #21 | #32 |
| T11 (Config Drift) | #33 | #14, #32 |
| T12 (Final Report) | #35, #36, #38, #42 | #32 |

## Dependency Map

```
skill-shield-file-navigator (#34) <-- used by all skills for navigation
skill-finding-formatter (#37) <-- used by all skills for output
skill-finding-id-generator (#39) <-- used by all skills for finding IDs
skill-evidence-snapshot-collector (#41) <-- used by all skills for evidence

skill-cwe-pattern-detector (#3) <-- used by #27 (fingerprint), #12 (zeroization)
skill-multi-lang-symbol-scanner (#5) <-- used by #2, #7, #8, #9, #10, #11
skill-key-accessor-mapper (#6) <-- used by #28 (WASM), #31 (key exposure)

skill-finding-deduplicator (#35) <-- feeds into #36, #38
skill-risk-matrix-generator (#36) <-- feeds into #38
skill-remediation-roadmap-builder (#38) <-- final output
skill-audit-progress-tracker (#42) <-- monitors all agents
```

## Quick Reference: Skill by Trigger

| When You Need To... | Use Skill |
|---------------------|-----------|
| Navigate Shield codebase | #34 skill-shield-file-navigator |
| Scan for a symbol across languages | #5 skill-multi-lang-symbol-scanner |
| Find CWE patterns in code | #3 skill-cwe-pattern-detector |
| Audit PBKDF2 parameters | #1 skill-pbkdf2-param-auditor |
| Check CTR mode implementation | #9 skill-ctr-mode-verifier |
| Verify MAC implementation | #10 skill-mac-verification-auditor |
| Check nonce/random generation | #11 skill-nonce-generation-auditor |
| Verify key zeroization | #12 skill-zeroization-verifier |
| Check constant-time operations | #7 skill-constant-time-verifier |
| Compare cross-language constants | #8 skill-cross-lang-constant-audit |
| Diff functions across languages | #2 skill-function-diff-comparator |
| Catalog error messages | #4 skill-error-message-cataloger |
| Trace error propagation | #20 skill-middleware-error-propagation-tracer |
| Audit Dockerfiles | #14 skill-dockerfile-security-auditor |
| Audit GitHub Actions | #15 skill-github-actions-auditor |
| Check shell script injection | #16 skill-shell-script-injection-checker |
| Audit dependencies | #17 skill-dependency-audit-scanner |
| Audit cookie security | #18 skill-cookie-security-auditor |
| Check route bypass | #19 skill-route-exclusion-bypass-checker |
| Audit token lifecycle | #21 skill-token-lifecycle-auditor |
| Check TOTP compliance | #22 skill-totp-rfc-compliance-checker |
| Analyze rate limiter bypass | #23 skill-rate-limiter-bypass-analyzer |
| Audit Android Keystore | #24 skill-android-keystore-auditor |
| Audit iOS Keychain | #25 skill-ios-keychain-auditor |
| Audit TEE attestation | #26 skill-tee-attestation-auditor |
| Assess fingerprint security | #27 skill-fingerprint-security-assessor |
| Check WASM memory isolation | #28 skill-wasm-memory-isolation-checker |
| Trace protocol handshake | #13 skill-protocol-handshake-tracer |
| Assess crypto oracle risk | #29 skill-crypto-oracle-feasibility-assessor |
| Build interop exploit matrix | #30 skill-interop-exploit-matrix-builder |
| Map key exposure surface | #31 skill-key-exposure-surface-mapper |
| Build attack chains | #32 skill-attack-chain-builder |
| Detect config drift | #33 skill-config-drift-detector |
| Generate test vectors | #40 skill-test-vector-generator |
| Deduplicate findings | #35 skill-finding-deduplicator |
| Generate risk matrix | #36 skill-risk-matrix-generator |
| Build remediation roadmap | #38 skill-remediation-roadmap-builder |
| Track audit progress | #42 skill-audit-progress-tracker |
| Find key accessors | #6 skill-key-accessor-mapper |
| Format findings | #37 skill-finding-formatter |
| Generate finding IDs | #39 skill-finding-id-generator |
| Collect evidence snapshots | #41 skill-evidence-snapshot-collector |
