---
name: skill-audit-progress-tracker
description: Track completion status across all 16 agents' audit checklists and 7 team assessments. Use for audit project management and status reporting.
---

# Audit Progress Tracker

Track audit completion across all agents and teams.

## When to Use
- Monitoring overall audit progress
- Identifying blocked or stalled audits
- Producing status reports for stakeholders

## Inputs
- Agent completion status
- Team completion status

## Procedure
1. Track each agent's progress:

### Agent Checklist Template
| Agent | Status | Findings | Skills Used | Blockers |
|-------|--------|----------|-------------|----------|
| A1: Crypto Primitives | Not Started / In Progress / Complete | 0 | — | — |
| A2: Cross-Language | Not Started | 0 | — | Waiting on A1 |
| A3: Memory Safety | Not Started | 0 | — | — |
| A4: Input Validation | Not Started | 0 | — | — |
| A5: Docker Security | Not Started | 0 | — | — |
| A6: Web Integration | Not Started | 0 | — | — |
| A7: Auth & Session | Not Started | 0 | — | — |
| A8: Transport Protocol | Not Started | 0 | — | — |
| A9: Browser & WASM | Not Started | 0 | — | — |
| A10: CI/CD Supply Chain | Not Started | 0 | — | — |
| A11: Error Disclosure | Not Started | 0 | — | — |
| A12: Mobile Platform | Not Started | 0 | — | — |
| A13: Confidential TEE | Not Started | 0 | — | — |
| A14: Streaming/Group | Not Started | 0 | — | — |
| A15: Signatures/2FA | Not Started | 0 | — | — |
| A16: Fingerprint | Not Started | 0 | — | — |

### Team Progress
| Team | Status | Depends On | Findings |
|------|--------|-----------|----------|
| T6: Crypto Oracle | Blocked | A1, A6, A11 | 0 |
| T7: Supply Chain | Blocked | A5, A10 | 0 |
| T8: Cross-Lang Interop | Blocked | A1, A2 | 0 |
| T9: Key Lifecycle | Blocked | A3, A9, A12 | 0 |
| T10: Auth Transport MITM | Blocked | A7, A8 | 0 |
| T11: Config Drift | Blocked | A5 | 0 |
| T12: Launch Readiness | Blocked | T6-T11 | 0 |

2. Calculate progress metrics:
   - Agent completion: X/16 (Y%)
   - Team completion: X/7 (Y%)
   - Total findings: N
   - Critical findings: N

3. Identify critical path:
   ```
   A1,A2 → T8 → T12
   A5,A10 → T7 → T12
   A1,A6,A11 → T6 → T12
   ```
   Longest path determines minimum audit duration.

4. Produce status dashboard

## Output Format
```
### Audit Progress Dashboard
**Date**: YYYY-MM-DD
**Overall**: X% complete

**Agents**: ████████░░ 12/16 complete
**Teams**:  ████░░░░░░ 3/7 complete
**Findings**: N total (C critical, H high, M medium, L low)

**Critical Path**: A1 → T8 → T12 (estimated X days remaining)

**Blockers**:
- T6 waiting on A11 (error disclosure)
- T9 waiting on A12 (mobile platform)
```

## Used By
- T12 (Launch Readiness), Orchestrator
