---
name: skill-mapper
description: Auto-route to the correct skill based on user intent. Use at conversation start or when unsure which skill applies.
---

# Skill Mapper

Route user requests to the optimal skill. **Invoke relevant skill immediately after matching.**

## Quick Routing Table

| User Intent | Skill | Invoke |
|-------------|-------|--------|
| "jailbreak", "adversarial prompt", "attack vector" | `red-team-prompt-generator` | `/red-team-prompt-generator` |
| "Garak", "LLM vulnerability scan" | `garak-integration` | `/garak-integration` |
| "Promptfoo", "eval", "red team test" | `promptfoo-evaluation` | `/promptfoo-evaluation` |
| "attack dataset", "CSV prompts" | `attack-dataset-curator` | `/attack-dataset-curator` |
| "bug bounty", "vulnerability report" | `bug-bounty-reporter` | `/bug-bounty-reporter` |
| "Guard8", "FAI", "content filter", "guardrail" | `fai-development` | `/fai-development` |
| "classifier", "content classification" | `classifier-development` | `/classifier-development` |
| "generate docs", "API documentation" | `documentation-generator` | `/documentation-generator` |
| "report", "findings", "analysis summary" | `report-generator` | `/report-generator` |
| "handoff", "issue transfer", "context for next session" | `issue-handoff-generator` | `/issue-handoff-generator` |
| "create skill", "new skill", "update skill" | `skill-creator` | `/skill-creator` |
| "MCP server", "tool integration" | `mcp-server-builder` | `/mcp-server-builder` |
| "setup env", "venv", "API keys config" | `env-setup-automation` | `/env-setup-automation` |
| "search sessions", "find past conversation" | `session-search` | `/session-search` |
| "commit message" | `commit-helper` | `/commit-helper` |
| "interview", "presentation", "talking points" | `interview-prep` | `/interview-prep` |
| "frontend", "UI component", "web design" | `frontend-design` | `/frontend-design` |

## Routing Rules

1. **Exact match** → Invoke skill immediately
2. **Partial match** → Confirm with user, then invoke
3. **No match** → List top 3 candidates, ask user
4. **Multiple matches** → Present options with 1-line descriptions

## Domain Categories

### 🔴 Offensive Security
- `red-team-prompt-generator` - Generate adversarial prompts
- `garak-integration` - LLM vulnerability scanning
- `promptfoo-evaluation` - Red team testing framework
- `attack-dataset-curator` - Manage attack datasets

### 🔵 Defensive Security
- `fai-development` - Build content filters/guardrails
- `classifier-development` - Content classification systems
- `bug-bounty-reporter` - Vulnerability documentation

### 📊 Analysis & Evaluation
- `report-generator` - Analysis reports
- `promptfoo-evaluation` - LLM evaluation metrics

### 📝 Documentation
- `documentation-generator` - Technical docs
- `issue-handoff-generator` - Cross-session context
- `skill-creator` - Create/update skills

### 🛠️ Dev Tools
- `mcp-server-builder` - MCP server development
- `env-setup-automation` - Environment setup
- `session-search` - Session history search
- `commit-helper` - Commit messages

### 🎯 Communication
- `interview-prep` - Interview/presentation prep

## Usage

**Auto-invoke**: When user request matches a skill trigger
**Manual**: `/skill-mapper` to see full routing table
**Search**: "which skill for X?" → returns best match

## Integration

Add to CLAUDE.md:
```markdown
## Skill Routing
Use `skill-mapper` to route requests to the correct skill.
When unsure which skill applies, invoke `/skill-mapper` first.
```
