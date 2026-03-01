---
name: skill-evidence-snapshot-collector
description: Collect code evidence with git blame, commit hash, and surrounding context for security findings. Use when documenting any finding.
---

# Evidence Snapshot Collector

Capture verifiable code evidence for security findings with full provenance.

## When to Use
- When documenting code-level security findings
- When evidence needs to be traceable to specific commits
- When building audit trail for remediation tracking

## Inputs
- File path (relative to repo root)
- Line number or line range
- Finding context (what to look for)

## Procedure
1. Read the target file at the specified lines (±5 lines context)
2. Run `git blame` on the affected lines to get:
   - Commit hash
   - Author
   - Date
   - Original line content
3. Run `git log --oneline -1 {commit_hash}` for commit message
4. Capture language-specific context:
   - Function/method name containing the line
   - Class/module name
   - Import context if relevant
5. Package as evidence block

## Output Format
```
#### Evidence: [description]
- **File**: `path/to/file.ext:L42-L48`
- **Commit**: `abc1234` — "commit message" (Author, YYYY-MM-DD)
- **Context**: `ClassName.methodName()`
```lang
// surrounding code with issue highlighted
>>> ISSUE LINE HERE <<<
// more context
```
```

## Used By
- All 16 agents (A1-A16)
- All 7 teams (T6-T12)
