---
name: skill-github-actions-auditor
description: Audit GitHub Actions workflows for SHA pinning, secret handling, permissions, and artifact signing. Use when auditing CI/CD supply chain security.
---

# GitHub Actions Auditor

Audit GitHub Actions workflows for supply chain and secret management risks.

## When to Use
- Auditing CI/CD pipeline security
- Checking for supply chain attack vectors in workflows
- Reviewing secret handling in automation

## Inputs
- Workflow file path(s) or `.github/workflows/` directory
- Scope: "pinning" | "secrets" | "permissions" | "all"

## Procedure
1. Locate workflow files: `.github/workflows/*.yml`
2. Audit each workflow:

### Action Pinning
| Check | Bad | Good | Risk |
|-------|-----|------|------|
| Tag pinning | `uses: actions/checkout@v4` | `uses: actions/checkout@abc123...` | High |
| Branch pinning | `uses: owner/action@main` | `uses: owner/action@sha256:...` | Critical |
| No pinning | `uses: owner/action` | Pin to full SHA | Critical |
| Third-party actions | Any non-`actions/` org | Verify + pin SHA | High |

### Secret Handling
| Check | Pattern | Risk | CWE |
|-------|---------|------|-----|
| Secret in logs | `echo ${{ secrets.* }}` | Critical | CWE-532 |
| Secret in env | `env: KEY=${{ secrets.* }}` without masking | High | CWE-200 |
| Hardcoded secrets | `password:`, `token:` in YAML | Critical | CWE-798 |
| Secret in artifact | Secrets written to uploaded artifacts | Critical | CWE-538 |

### Permissions
| Check | Pattern | Risk |
|-------|---------|------|
| Write-all default | Missing `permissions:` (defaults to write-all) | High |
| Excessive permissions | `permissions: write-all` | High |
| Contents write | `contents: write` without need | Medium |
| Pull-request write | `pull-requests: write` on fork PRs | High |

### Workflow Triggers
| Check | Pattern | Risk |
|-------|---------|------|
| pull_request_target | `on: pull_request_target` | Critical |
| workflow_dispatch without auth | Manual trigger without checks | Medium |
| Untrusted input | `${{ github.event.*.body }}` | High |

## Output Format
```
### GitHub Actions Audit: {workflow_file}
| # | Line | Check | Status | Risk |
|---|------|-------|--------|------|
| 1 | 12 | Action not SHA-pinned | FAIL | High |
...

**Summary**: X actions unpinned, Y secret risks, Z permission issues
```

## Used By
- A10 (CI/CD Supply Chain)
- T07 (Supply Chain)
