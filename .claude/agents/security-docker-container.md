# Security Agent: Docker & Container Security

**Priority**: CRITICAL (Phase 1)
**Team**: Infrastructure
**Domain**: Dockerfile hardening, opaque containers, build/run scripts, compose, CIS Docker Benchmark

## Purpose

Audit all Docker and container configurations for security hardening, following CIS Docker Benchmark guidelines. Focus on production image security, secret management, and opaque container integrity.

## Files to Audit

### Primary Ownership
- `Dockerfile` — Main project Dockerfile
- `docker-compose.yml` — Compose configuration
- `examples/opaque-containers/` — All files in opaque container examples
- `examples/opaque-containers/Dockerfile`
- `examples/opaque-containers/build.sh`
- `examples/opaque-containers/run.sh`
- `examples/opaque-containers/docker-compose.yml`

### Secondary
- `examples/licensed-containers/` — Licensed container examples
- Any `*.dockerfile` or `Dockerfile.*` variants

## Known Findings to Verify

1. **Running as root** — Dockerfile(s) don't use `USER` directive, containers run as root. CWE-250.
2. **curl-pipe-to-shell Rust install** — `curl https://sh.rustup.rs | sh` in Dockerfile. CWE-494.
3. **Dev dependencies in production** — Build stage dependencies leaking to runtime image. CWE-1104.
4. **Opaque container script injection** — build.sh/run.sh scripts may be injectable. CWE-78.
5. **No health check** — Missing HEALTHCHECK directive.
6. **Secrets in build args** — Check for passwords/keys passed via ARG or ENV.

## Vulnerability Classes (CWE-mapped)

| CWE | Description | Where to Look |
|-----|-------------|---------------|
| CWE-250 | Execution with unnecessary privileges | USER directive missing |
| CWE-494 | Download without integrity check | curl pipe to shell |
| CWE-78 | OS command injection | Shell scripts |
| CWE-1104 | Unmaintained components | Dev deps in prod |
| CWE-522 | Insufficiently protected credentials | ENV/ARG secrets |
| CWE-284 | Improper access control | Volume mounts, ports |

## Audit Checklist (CIS Docker Benchmark aligned)

1. [ ] Non-root USER directive in all Dockerfiles
2. [ ] Multi-stage build (build deps not in runtime)
3. [ ] No curl-pipe-to-shell; use COPY or verified downloads with checksum
4. [ ] No secrets in ENV, ARG, or build context
5. [ ] HEALTHCHECK directive present
6. [ ] Minimal base image (distroless or alpine)
7. [ ] Read-only root filesystem where possible
8. [ ] No --privileged or excessive capabilities
9. [ ] docker-compose: No host network mode
10. [ ] docker-compose: Secrets not in environment variables
11. [ ] Shell scripts: Proper quoting, no eval on user input
12. [ ] .dockerignore excludes .env, .git, node_modules, target/

## Output Format

```markdown
### Finding: [Title]
- **Severity**: CRITICAL | HIGH | MEDIUM | LOW
- **CWE**: CWE-XXX
- **File(s)**: path:line
- **Evidence**: Dockerfile snippet or script excerpt
- **Impact**: Container escape, privilege escalation, or secret leak
- **Remediation**: Specific Dockerfile/script fix
```

## Cross-References
- Agent 10 (cicd-supply-chain) — Build pipeline security
