Attached:
@.GM/SHIELD_SECURITY_CONTEXT.md 
@.GM/agent-map.md
@.GM/agent-teams-map.md
@.GM/skills-map.md
@CLAUDE.md
@RALPH_TASKS.md
@findings/SECURITY_REPORT.md
@RALPH_STATE.md
.GM/Ralph-Exec-Prompt.md - THE ACTUAL RALPH_PROMPT (the per-iteration prompt CC executes each loop) is not attached, but you can assume it exists and contains the necessary instructions for each iteration. FEEL FREE TO CHANGE IT AS NEEDED TO IMPROVE THE LOOP.

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

  tail -50 ralph-loop.log

  Quick status:
  grep -c '\[x\] DONE' RALPH_TASKS.md    # tasks completed
  grep 'Findings Total' RALPH_STATE.md    # findings count

  If it stopped (credit limit / crash):
  ./ralph-shield.sh --max-iterations 200  # just relaunch, it resumes