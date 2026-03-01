---
name: skill-attack-chain-builder
description: Build multi-step attack chains from individual findings, assessing combined severity and realistic exploit paths. Use when consolidating findings into attack narratives.
---

# Attack Chain Builder

Build multi-step attack chains from individual findings.

## When to Use
- Combining individual findings into realistic attack scenarios
- Assessing combined impact of multiple medium findings
- Building attack narratives for executive reporting

## Inputs
- List of individual findings (with IDs, severity, type)
- System architecture context

## Procedure
1. Categorize findings by attack enablement:
   | Category | Enables |
   |----------|---------|
   | Information disclosure | Reconnaissance step |
   | Weak authentication | Initial access |
   | Injection | Code execution |
   | Crypto weakness | Data compromise |
   | Missing validation | Bypass controls |
   | Configuration issue | Expand access |

2. Build attack chains by linking findings:
   ```
   Chain: Finding A (info disclosure)
     -> Finding B (bypass with disclosed info)
       -> Finding C (escalate with bypass)
         -> Impact: Full data compromise
   ```

3. Assess combined severity:
   - Individual: each finding may be Medium
   - Combined: chain may be Critical
   - Use CVSS chaining rules:
     - If A enables B: combined = max(A, B) + 1 level
     - If A required for B: B's severity assumes A is exploited

4. Build attack tree:
   ```
   Goal: Decrypt protected data
   |-- Path 1: Oracle attack (Finding X + Y)
   |   |-- Prerequisite: Network access
   |   +-- Steps: 3, Queries: 2^17
   |-- Path 2: Key extraction (Finding Z)
   |   |-- Prerequisite: Local access
   |   +-- Steps: 1
   +-- Path 3: Implementation bypass (Finding W)
       |-- Prerequisite: Cross-language interop
       +-- Steps: 2
   ```

5. Rank chains by:
   - Likelihood (prerequisites x steps)
   - Impact (what's compromised)
   - Effort (attacker resources needed)

## Output Format
```
### Attack Chain Analysis
| Chain # | Findings | Steps | Prerequisites | Impact | Likelihood | Combined Severity |
|---------|----------|-------|--------------|--------|-----------|------------------|
| 1 | A01-003 -> A11-001 | 2 | Network | Decrypt | Medium | High |
| 2 | A03-002 | 1 | Local | Key extract | High | Critical |

**Highest Risk Chain**: Chain 2
**Narrative**: [step-by-step description]
```

## Used By
- T6-T12 (All cross-domain teams)
