---
name: skill-risk-matrix-generator
description: Generate a Likelihood x Impact risk matrix from deduplicated findings and produce a go/no-go launch recommendation. Use for executive-level risk assessment.
---

# Risk Matrix Generator

Generate risk matrix and launch readiness recommendation.

## When to Use
- Producing executive risk summary
- Making go/no-go launch decision
- Prioritizing remediation efforts

## Inputs
- Deduplicated finding list (from skill-finding-deduplicator)

## Procedure
1. Rate each finding on two dimensions:

### Likelihood (1-5)
| Score | Level | Criteria |
|-------|-------|---------|
| 5 | Almost Certain | Trivially exploitable, no auth needed, public-facing |
| 4 | Likely | Exploitable with moderate effort, known technique |
| 3 | Possible | Requires specific conditions or insider knowledge |
| 2 | Unlikely | Requires significant effort, multiple prerequisites |
| 1 | Rare | Theoretical only, no practical exploit path |

### Impact (1-5)
| Score | Level | Criteria |
|-------|-------|---------|
| 5 | Critical | Full key compromise, all data decryptable |
| 4 | Major | Partial key recovery, significant data exposure |
| 3 | Moderate | Limited data exposure, single session compromise |
| 2 | Minor | Information disclosure, no data compromise |
| 1 | Negligible | Best practice issue, no real-world impact |

2. Plot on risk matrix:
```
Impact →
  5 │ 5  10  15  20  25
  4 │ 4   8  12  16  20
  3 │ 3   6   9  12  15
  2 │ 2   4   6   8  10
  1 │ 1   2   3   4   5
    └─────────────────
      1   2   3   4   5
      Likelihood →
```

Risk score = Likelihood × Impact

| Risk Score | Level | Action |
|-----------|-------|--------|
| 20-25 | Critical | Must fix before launch |
| 12-19 | High | Should fix before launch |
| 6-11 | Medium | Fix within 30 days post-launch |
| 3-5 | Low | Fix within 90 days |
| 1-2 | Info | Accept or address in next release |

3. Generate go/no-go recommendation:
   - **NO GO**: Any finding with risk score >= 20
   - **CONDITIONAL GO**: Findings with risk 12-19, mitigations documented
   - **GO**: All findings risk <= 11

## Output Format
```
### Risk Matrix
| Finding ID | Title | Likelihood | Impact | Risk Score | Level |
|-----------|-------|-----------|--------|-----------|-------|
| SHIELD-A01-001 | Timing side-channel | 3 | 4 | 12 | High |
...

**Risk Distribution**:
- Critical (20-25): X findings
- High (12-19): Y findings
- Medium (6-11): Z findings
- Low (1-5): W findings

**Recommendation**: GO / CONDITIONAL GO / NO GO
**Rationale**: [explanation]
```

## Used By
- T12 (Launch Readiness)
