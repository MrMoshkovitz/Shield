Attached:
@.GM/SHIELD_SECURITY_CONTEXT.md 
@.GM/agent-map.md
@.GM/agent-teams-map.md
@.GM/skills-map.md
@CLAUDE.md


## PROTOCOLS
1. **ULTRATHINK** - Deep reasoning before action
2. **ACCURACY**: Read source code + docs. Validate yourself. Accuracy is critical.
3. **READ FIRST**: Start by reading @CLAUDE.md instruction file (if it exists)
4. **AGENT ROUTER**: Use @agent-router to identify best agent for task
5. **SKILLS**: Use every relevant skill from ./.claude/skills/*
6. **AGENTS**: Use every relevant agent from ./.claude/agents/*
7. **TEAMS**: Use every relevant team from ./.claude/agent-teams/*
8. **FINDINGS**: Write every finding in .GM/findings/ with full evidence and reproduction steps
9. **DEDUPE**: If multiple agents/teams find the same issue, write one finding and note all sources
10. **NO FIXES WITHOUT APPROVAL**: Do not implement any fixes until without explicit approval from project lead (ME THE USER) - ONLY write findings with evidence and reproduction steps, fix complexity estimate, and impact assessment and Remediation and Mitigation setp-by-step instructions and strategy. I will review and decide which findings to fix and how.
11. **SCOPE**: The entire codebase, infrastructure, CI/CD pipelines, and documentation related to the Shield project. Assume everything is in scope unless explicitly told otherwise. - Highest risk areas are likely to be enterprise API code, Docker configuration, and Confidential Computing implementation, but review everything with a security mindset.
12. **TIMELINE**: Shield launches in 2 days. We have 48 hours to complete a comprehensive security assessment. Prioritize speed and accuracy. Focus on critical paths first, but review everything as time allows - Don't miss anything critical, but also don't get bogged down in low-risk details. We need to find and report all critical, high-severity and even medium-severity issues before launch. We can triage and prioritize fixes after the assessment is complete, but we must find everything, not just the low-hanging fruit. This is a zero-miss mission.
13. **COMMUNICATION**: After every Ralph iteration, provide a concise summary of what was done, what was found, and what the next steps are (Save as file including Start and end full date and time (Jerusalem time)). Be transparent about any blockers or uncertainties. I will be available to review findings and provide guidance after each iteration, so keep me in the loop.
14. **ETHICS**: This is a security assessment for a product about to launch. The goal is to find and report vulnerabilities, not to exploit them. Do not attempt to access any systems or data beyond what is necessary for the assessment, and do not use any findings for personal gain. This is a professional engagement with the goal of improving security for users.

---

## RALPH WIGGUM AUTONOMOUS SECURITY ASSESSMENT — ITERATION PROMPT

You are one iteration of an autonomous security assessment loop.
Previous iterations may have already completed work. Your job:
find the next task, execute it, write findings, update state, exit cleanly.

**CRITICAL**: You do NOT fix code. You do NOT change source. You FIND
vulnerabilities, VERIFY them, and WRITE findings. That's it.

**MOST CRITICAL FOCUS**: Docker & Confidential Computing. But cover EVERYTHING.

## STEP 0: ORIENT (do this EVERY iteration, no exceptions)

Your prompt already contains these files inline — do NOT re-read them:
- `RALPH_STATE.md` — current loop state (phase, task, iteration count)
- `RALPH_TASKS.md` — full 66-task state machine with statuses and dependencies
- `findings/SECURITY_REPORT.md` — cumulative findings report
- **Agent/Team/Skill Maps Digest** (`.GM/agent-skills-maps.txt`) — see below

`CLAUDE.md` is auto-loaded by Claude Code as project instructions.

If any state file appears missing or corrupted, recreate from `.GM/` reference docs.

### YOUR ARSENAL (from maps digest included below)

**16 Security Agents** — each audits a specific domain. Agent files at `.claude/agents/security-*.md`:
| # | Agent | Priority | File |
|---|-------|----------|------|
| 1 | Crypto Primitives | CRITICAL | `security-crypto-primitives.md` |
| 2 | Cross-Language Parity | CRITICAL | `security-cross-language.md` |
| 3 | Memory Safety | CRITICAL | `security-memory-safety.md` |
| 4 | Input Validation | CRITICAL | `security-input-validation.md` |
| 5 | Docker & Container | CRITICAL | `security-docker-container.md` |
| 6 | Web Integration | HIGH | `security-web-integration.md` |
| 7 | Auth & Session | HIGH | `security-auth-session.md` |
| 8 | Transport Protocol | HIGH | `security-transport-protocol.md` |
| 9 | Browser & WASM | HIGH | `security-browser-wasm.md` |
| 10 | CI/CD & Supply Chain | HIGH | `security-cicd-supply-chain.md` |
| 11 | Error Disclosure | HIGH | `security-error-disclosure.md` |
| 12 | Mobile Platform | MEDIUM | `security-mobile-platform.md` |
| 13 | Confidential TEE | MEDIUM | `security-confidential-tee.md` |
| 14 | Streaming & Group | MEDIUM | `security-streaming-group.md` |
| 15 | Signatures & 2FA | MEDIUM | `security-signatures-2fa.md` |
| 16 | Fingerprint | MEDIUM | `security-fingerprint.md` |

**7 Cross-Domain Teams** — each builds attack chains. Team files at `.claude/agents/team-*.md`:
| Team | Name | Priority | Phase |
|------|------|----------|-------|
| T6 | Crypto Oracle & Error Leakage | CRITICAL | 4 |
| T7 | Supply Chain to Runtime | HIGH | 4 |
| T8 | Cross-Language Interop Exploit | CRITICAL | 4 |
| T9 | Key Lifecycle & Exposure | CRITICAL | 5 |
| T10 | Auth & Transport MITM | HIGH | 5 |
| T11 | Config & Deployment Drift | HIGH | 4 |
| T12 | Launch Readiness (Go/No-Go) | CRITICAL | 6 |

**Key Skills** (42 total, invoke via Skill tool `/skill-name`):
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
| Full skill registry | See maps digest below or `.GM/skills-map.md` |

The full maps digest (`.GM/agent-skills-maps.txt`) with file ownership matrix,
execution DAG, pairwise coverage, and all 42 skills is included at the bottom of this prompt.

### TOKEN-SAVING: Use `gitingest` for source code exploration
When a task requires reading source code, use `gitingest` via Bash to digest
entire directories into one compact file instead of reading files one-by-one:
```bash
gitingest shield-core/src/ --output .GM/task-digest.txt --exclude-pattern "branding/*"
gitingest python/shield/ --output .GM/task-digest.txt --exclude-pattern "branding/*"
gitingest c/src/ --output .GM/task-digest.txt --exclude-pattern "branding/*"
```
Then read `.GM/task-digest.txt`. ALWAYS exclude `branding/*`.

Full repo digest is pre-built at `.GM/Digest.txt` — read it only when you need
broad codebase context, not every iteration.

## STEP 1: IDENTIFY NEXT TASK

Parse `RALPH_TASKS.md` and find the next task to execute using this priority:
1. Any task marked `[R] RESUME` (interrupted last iteration) → resume it
2. Any task marked `[~] IN-PROGRESS` for >1 iteration → likely stalled, resume it
3. First `[ ] PENDING` task whose ALL `Depends On` tasks are `[x] DONE`
4. Among eligible PENDING tasks, pick by: CRITICAL > HIGH > MEDIUM priority
5. Within same priority, pick Docker (A05) and TEE (A13) tasks first

If NO eligible task exists:
- If blocked tasks remain → log blocker in RALPH_STATE.md, attempt to unblock
- If ALL tasks are DONE → proceed to STEP 5 (finalization)

## STEP 2: EXECUTE THE TASK

Update the task status to `[~] IN-PROGRESS` and set `Started: {timestamp}` in RALPH_TASKS.md.
Update RALPH_STATE.md with current task.

### For AGENT tasks:
1. Read the agent file: `.claude/agents/{agent-file}.md`
2. Read `.GM/SHIELD_SECURITY_CONTEXT.md` for recon data on the agent's target files
3. Follow the agent's Audit Checklist item by item — DO NOT SKIP ITEMS
4. For EACH file in the agent's ownership (from agent-map.md):
   a. READ the actual source code — not just the recon summary
   b. Analyze for every vulnerability class the agent covers
   c. If you find something suspicious: VERIFY it by reading surrounding code, checking if it's exploitable
   d. For each confirmed finding, classify:
      - **VULN** — confirmed exploitable vulnerability
      - **VERIFIED** — verified as real security issue
      - **UN-VERIFIED** — looks suspicious but can't confirm from static analysis
      - **NOT-SURE** — needs manual review or dynamic testing
      - **NON-VULN** — investigated, determined safe (document WHY)
5. Use skills listed in the agent file (invoke via skill tool)
6. Generate finding IDs: `SHIELD-A{##}-{SEQ}` using /skill-finding-id-generator
7. Format findings using /skill-finding-formatter
8. Write findings to `findings/agents/A{##}-{agent-name}.md`

### For TEAM tasks:
1. Read the team file: `.claude/agents/team-{N}-{name}.md`
2. Read ALL input agent findings from `findings/agents/` that this team consumes
3. Follow the team's Coordination Flow
4. Build attack chains using /skill-attack-chain-builder
5. Look for CROSS-DOMAIN vulnerabilities that no single agent could find
6. Cross-reference agent findings by SHIELD-A##-### ID — NEVER duplicate
7. Any NEW cross-domain finding gets a TEAM finding ID: `SHIELD-T{##}-{SEQ}`
8. Write findings to `findings/teams/T{##}-{team-name}.md`

### For META tasks (setup, checkpoint, dedup, report):
- Follow the specific instructions in the task description
- Checkpoint tasks: verify all phase findings are written, count findings, update report
- Dedup tasks: run /skill-finding-deduplicator across all findings
- Report tasks: update SECURITY_REPORT.md with latest findings

## STEP 3: UPDATE FINDINGS — IMMEDIATELY

After EACH finding (not after all findings):
1. Write finding to the agent/team output file
2. Append finding summary to `findings/SECURITY_REPORT.md` in the correct section
3. Update the Verification Matrix in the report with the finding's status tag
4. If finding is CRITICAL or HIGH → also add to the Docker & Confidential Computing section if relevant
5. Update finding counters in the report header

### Finding Template (MANDATORY format):
```markdown
### SHIELD-{SOURCE}-{SEQ}: {Title}
- **Tag**: VULN | VERIFIED | UN-VERIFIED | NOT-SURE | NON-VULN
- **Severity**: CRITICAL | HIGH | MEDIUM | LOW | INFO
- **CWE**: CWE-XXX
- **Location**: `file/path.ext:line`
- **Evidence**: {code snippet or output proving the issue}
- **Impact**: {what an attacker achieves}
- **Reproduction**: {steps to reproduce / verify}
- **Fix Complexity**: LOW | MEDIUM | HIGH
- **Remediation**: {specific fix — but DO NOT implement it}
- **Verification Notes**: {why this tag — what you checked to confirm/deny}
```

## STEP 4: COMPLETE THE TASK

1. Mark task as `[x] DONE` in RALPH_TASKS.md
2. Set `Completed: {timestamp}` and `Findings Count: {N}`
3. Update RALPH_STATE.md:
   - Increment `Total Iterations`
   - Set `Last Iteration: {timestamp}`
   - Update `Findings Total`
   - Set `Resume Point` to next eligible task
   - Update `Current Phase` if phase just completed
4. If this was the LAST task in a phase:
   - Log phase completion in RALPH_STATE.md
   - Run a quick checkpoint: are all phase findings written? Any gaps?

## STEP 5: FINALIZATION (only when ALL tasks are DONE)

If every task in RALPH_TASKS.md is `[x] DONE`:
1. Run /skill-finding-deduplicator across ALL findings
2. Run /skill-risk-matrix-generator for final risk matrix
3. Update SECURITY_REPORT.md:
   - Write Executive Summary
   - Write Go/No-Go Recommendation
   - Update all counters to final numbers
   - Set Status: COMPLETE
4. Write `findings/SUMMARY.md` — the Team 12 launch readiness output
5. Update RALPH_STATE.md: set `Current Phase: COMPLETE`
6. Log: "RALPH LOOP COMPLETE — ALL TASKS DONE — {total findings} findings across {total tasks} tasks"

## RULES OF ENGAGEMENT
1. **EVIDENCE OVER OPINION** — every finding requires file:line + code snippet
2. **CWE MAPPING REQUIRED** — no finding without a CWE ID
3. **VERIFY BEFORE TAGGING** — read the actual code, don't guess from function names
4. **CROSS-REFERENCE, NEVER DUPLICATE** — teams reference agent finding IDs
5. **WRITE AS YOU GO** — don't batch findings, write each immediately
6. **NO CODE CHANGES** — findings only, zero fixes, zero patches
7. **DOCKER & TEE FIRST** — when choosing between equal-priority tasks, pick these domains
8. **COMPLETE > PERFECT** — a finding tagged UN-VERIFIED is better than a finding not reported
9. **ONE TASK PER ITERATION** — execute exactly one task, update state, exit cleanly
10. **STATE IS SACRED** — always update RALPH_TASKS.md and RALPH_STATE.md before exiting

## ANTI-PATTERNS TO AVOID
- Do NOT skip the ORIENT step. Ever. Even if you "remember" from last iteration. You don't. Read the files.
- Do NOT mark a task DONE without writing at least the output file (even if 0 findings)
- Do NOT start Phase N+1 tasks before ALL Phase N tasks are DONE
- Do NOT re-analyze files already covered by a completed agent (teams reference, not re-audit)
- Do NOT spend an entire iteration on setup/orientation — reserve 80%+ for actual analysis
