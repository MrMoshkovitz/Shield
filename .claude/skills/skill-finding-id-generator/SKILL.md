---
name: skill-finding-id-generator
description: Generate unique traceable finding IDs in SHIELD-{source}-{sequence} format. Use when creating any new security finding.
---

# Finding ID Generator

Generate unique, traceable identifiers for security findings.

## When to Use
- When creating any new security finding
- When referencing findings in reports or remediation plans
- When cross-referencing findings across agents/teams

## Inputs
- Source agent or team (e.g., A01, T06)
- Sequential number (auto-increment per source)

## Procedure
1. Determine source prefix from the auditing agent/team:
   - Agent findings: `A01` through `A16`
   - Team findings: `T06` through `T12`
   - Manual/ad-hoc: `M00`
2. Assign sequential number starting from `001`
3. Combine: `SHIELD-{source}-{sequence}`

### ID Format
```
SHIELD-A01-001
  |      |   |
  |      |   +-- Sequential number (001-999)
  |      +------ Source (A01-A16 agent, T06-T12 team)
  +------------- Project prefix
```

### Examples
| ID | Meaning |
|----|---------|
| SHIELD-A01-001 | First finding by Agent 1 (Crypto Primitives) |
| SHIELD-A03-012 | 12th finding by Agent 3 (Memory Safety) |
| SHIELD-T08-003 | 3rd finding by Team 8 (Cross-Lang Interop) |
| SHIELD-T12-001 | 1st finding by Team 12 (Launch Readiness) |

### Agent/Team Reference
| Code | Name |
|------|------|
| A01 | Crypto Primitives |
| A02 | Cross-Language Parity |
| A03 | Memory Safety |
| A04 | Input Validation |
| A05 | Docker Security |
| A06 | Web Integration |
| A07 | Auth & Session |
| A08 | Transport Protocol |
| A09 | Browser & WASM |
| A10 | CI/CD Supply Chain |
| A11 | Error Disclosure |
| A12 | Mobile Platform |
| A13 | Confidential TEE |
| A14 | Streaming/Group |
| A15 | Signatures/2FA |
| A16 | Fingerprint |
| T06 | Crypto Oracle |
| T07 | Supply Chain |
| T08 | Cross-Lang Interop |
| T09 | Key Lifecycle |
| T10 | Auth Transport MITM |
| T11 | Config Drift |
| T12 | Launch Readiness |

## Output Format
```
SHIELD-{SOURCE}-{SEQ}
```

## Used By
- All 16 agents (A1-A16)
- All 7 teams (T6-T12)
