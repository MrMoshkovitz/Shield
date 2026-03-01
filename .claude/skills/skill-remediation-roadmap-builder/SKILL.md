---
name: skill-remediation-roadmap-builder
description: Generate a time-ordered remediation roadmap with effort estimates, dependencies, and milestones from prioritized security findings. Use for remediation planning.
---

# Remediation Roadmap Builder

Generate prioritized remediation plan with effort estimates.

## When to Use
- After risk matrix generation
- Planning security remediation sprints
- Creating actionable fix timeline

## Inputs
- Risk matrix results (from skill-risk-matrix-generator)
- Deduplicated findings with severity

## Procedure
1. Order findings by remediation priority:
   ```
   Priority = Risk Score × (1 + dependency_factor)
   ```
   Where dependency_factor increases if fixing this unblocks other fixes.

2. Estimate effort per finding:
   | Effort Level | Hours | Description |
   |-------------|-------|-----------|
   | Trivial | 1-2h | Config change, constant update |
   | Small | 2-8h | Single function fix in one language |
   | Medium | 1-3d | Fix across multiple languages |
   | Large | 3-5d | Architecture change, all languages |
   | XL | 1-2w | Fundamental design change |

3. Group into remediation phases:
   | Phase | Timeline | Criteria |
   |-------|---------|---------|
   | P0: Blockers | Before launch | Risk >= 20 |
   | P1: Critical | Week 1 post-launch | Risk 12-19 |
   | P2: Important | Month 1 | Risk 6-11 |
   | P3: Hardening | Quarter 1 | Risk 1-5 |

4. Identify dependencies:
   - Fix A must precede Fix B (e.g., fix MAC before fix oracle)
   - Cross-language fixes (fix in Rust reference, then propagate)
   - Test infrastructure needed before verification

5. Generate milestone checklist

## Output Format
```
### Remediation Roadmap

#### P0: Launch Blockers (X findings, ~Y hours)
| Priority | Finding | Fix Description | Effort | Dependencies | Owner |
|----------|---------|----------------|--------|-------------|-------|
| 1 | SHIELD-A03-002 | Add bounds check in C | Small | None | — |
| 2 | SHIELD-A01-001 | Add constant-time MAC compare | Medium | All langs | — |

#### P1: Critical (Post-Launch Week 1)
...

#### P2: Important (Month 1)
...

#### P3: Hardening (Quarter 1)
...

**Total Effort**: ~X person-days
**Milestones**:
- [ ] All P0 fixes verified
- [ ] Cross-language regression tests pass
- [ ] All P1 fixes deployed
```

## Used By
- T12 (Launch Readiness)
