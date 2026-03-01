---
name: skill-finding-deduplicator
description: Deduplicate security findings across multiple agents and teams using CWE grouping, location matching, and reference rules. Use when consolidating audit results.
---

# Finding Deduplicator

Deduplicate findings across agents and teams.

## When to Use
- Consolidating findings from multiple agents
- Preparing final audit report
- Reducing noise in finding lists

## Inputs
- Finding list from multiple agents/teams (with SHIELD-* IDs)

## Procedure
1. Group findings by deduplication criteria:

### Primary Grouping: Same Issue
| Criteria | Match Rule | Action |
|----------|-----------|--------|
| Same CWE + same file:line | Exact duplicate | Merge, keep earliest ID |
| Same CWE + same function | Likely duplicate | Review, merge if same root cause |
| Same CWE + different file | Pattern (not duplicate) | Keep both, note pattern |
| Different CWE + same file:line | Different issues at same location | Keep both |

### Secondary Grouping: Cross-Language Variants
| Criteria | Action |
|----------|--------|
| Same CWE in all 12 langs | Consolidate into single finding with "affects all implementations" |
| Same CWE in N langs | Consolidate with "affects N implementations" |
| Unique to one lang | Keep as language-specific finding |

2. Merge rules:
   - Keep the **earliest** finding ID as primary
   - List all duplicate IDs as "also reported as"
   - Use the **highest** severity from duplicates
   - Combine evidence from all reporters
   - Credit all discovering agents

3. Produce deduplicated list with:
   - Unique findings count
   - Duplicates removed count
   - Cross-references maintained

## Output Format
```
### Deduplication Results
**Input**: X findings from Y agents
**Output**: Z unique findings (removed N duplicates)

| Primary ID | Also Reported As | CWE | Severity | Scope |
|-----------|-----------------|-----|----------|-------|
| SHIELD-A01-001 | A02-003, A11-005 | CWE-208 | High | All langs |
| SHIELD-A03-002 | — | CWE-120 | Critical | C only |
...

**Dedup Summary**:
- Exact duplicates removed: N
- Cross-language consolidated: N
- Unique findings: Z
```

## Used By
- T12 (Launch Readiness)
