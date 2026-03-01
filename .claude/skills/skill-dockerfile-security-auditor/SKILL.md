---
name: skill-dockerfile-security-auditor
description: Audit Dockerfiles and docker-compose files against CIS Docker Benchmark for security misconfigurations. Use when auditing container security.
---

# Dockerfile Security Auditor

Audit Dockerfiles, docker-compose files, and container configs against CIS Docker Benchmark.

## When to Use
- Auditing container security configuration
- Reviewing Docker build pipeline for supply chain risks
- Checking runtime security settings

## Inputs
- Dockerfile path(s)
- docker-compose.yml path(s)
- Scope: "build" | "runtime" | "all"

## Procedure
1. Locate Docker files: `Dockerfile`, `docker-compose.yml`, `.dockerignore`
2. Check against CIS Docker Benchmark:

### Build-Time Checks
| Check | Pattern | Risk | CWE |
|-------|---------|------|-----|
| Root user | Missing `USER` directive | High | CWE-250 |
| Unpinned base | `FROM image:latest` | High | CWE-829 |
| Unpinned packages | `apt-get install pkg` (no version) | Medium | CWE-829 |
| Secrets in build | `ENV.*PASSWORD\|KEY\|SECRET\|TOKEN` | Critical | CWE-798 |
| COPY sensitive | `COPY .env\|*.key\|*.pem` | Critical | CWE-538 |
| Missing .dockerignore | No `.dockerignore` file | Medium | CWE-538 |
| ADD remote | `ADD http://` | High | CWE-829 |
| Excessive permissions | `chmod 777` | Medium | CWE-732 |
| Missing health check | No `HEALTHCHECK` | Low | - |

### Runtime Checks (docker-compose)
| Check | Pattern | Risk | CWE |
|-------|---------|------|-----|
| Privileged mode | `privileged: true` | Critical | CWE-250 |
| Host network | `network_mode: host` | High | CWE-668 |
| No resource limits | Missing `mem_limit`, `cpus` | Medium | CWE-400 |
| Host volumes | Mounting `/`, `/etc`, `/var/run/docker.sock` | Critical | CWE-668 |
| No read-only root | Missing `read_only: true` | Low | CWE-732 |
| Exposed ports | Unnecessary port mappings | Medium | CWE-668 |

3. Check `.dockerignore` covers: `.git`, `.env`, `*.key`, `*.pem`, `node_modules`, `target/`

## Output Format
```
### Docker Security Audit
| # | File:Line | Check | Status | Risk | CWE |
|---|-----------|-------|--------|------|-----|
| 1 | Dockerfile:1 | Unpinned base image | FAIL | High | CWE-829 |
...

**Score**: X/Y checks passed
```

## Used By
- A05 (Docker Security)
- T07 (Supply Chain)
- T11 (Config Drift)
