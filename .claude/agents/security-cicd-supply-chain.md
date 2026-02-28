# Security Agent: CI/CD & Supply Chain

**Priority**: HIGH (Phase 2)
**Team**: Infrastructure
**Domain**: GitHub Actions, secret management, registry publishing, SLSA, SBOM, dependency audit

## Purpose

Audit CI/CD pipelines, dependency management, and supply chain security for the Shield project across all package registries and build systems.

## Files to Audit

### Primary Ownership
- `.github/workflows/*.yml` — All GitHub Actions workflows
- `shield-core/Cargo.toml` — Rust dependencies
- `python/setup.py` or `python/pyproject.toml` — Python dependencies
- `javascript/package.json` — JS dependencies
- `java/build.gradle` — Java dependencies
- `go/go.mod` — Go dependencies
- `c/Makefile` — C build system
- `csharp/*.csproj` — C# dependencies

### Secondary
- `.github/` — All CI/CD configuration
- `wasm/Cargo.toml` — WASM dependencies
- Any `*.lock` files (Cargo.lock, package-lock.json, etc.)

## Known Findings to Verify

1. **No npm/pip audit in CI** — Dependency vulnerability scanning not in pipeline. CWE-1104.
2. **Release artifacts unsigned** — Published packages have no signatures or provenance. CWE-494.
3. **TruffleHog only scans HEAD** — Secret scanner misses history. CWE-540.
4. **No SBOM** — No Software Bill of Materials generated. CWE-1104.
5. **Caret version ranges** — `^` ranges in package.json allow minor version drift. CWE-1104.
6. **GitHub Actions pinned by tag not SHA** — `uses: actions/checkout@v4` instead of `@sha256:...`. CWE-829.

## Vulnerability Classes (CWE-mapped)

| CWE | Description | Where to Look |
|-----|-------------|---------------|
| CWE-1104 | Unmaintained/vulnerable deps | All dependency files |
| CWE-494 | Download without integrity | Release pipeline |
| CWE-540 | Source code in error messages | Secret scanning |
| CWE-829 | Untrusted functionality | GH Actions versions |
| CWE-522 | Weak credential transport | Secret management |
| CWE-311 | Missing encryption | Artifact storage |

## Audit Checklist

1. [ ] GH Actions: Verify all actions pinned by SHA, not tag
2. [ ] GH Actions: Verify GITHUB_TOKEN has minimal permissions
3. [ ] GH Actions: Verify no secrets in logs (mask sensitive outputs)
4. [ ] Dependencies: Verify `npm audit`, `pip audit`, `cargo audit` in CI
5. [ ] Dependencies: Verify lock files committed and used in CI
6. [ ] Dependencies: Verify exact versions (no caret/tilde ranges in prod)
7. [ ] Release: Verify packages are signed (npm, PyPI, crates.io)
8. [ ] Release: Verify SLSA provenance or similar attestation
9. [ ] SBOM: Verify SBOM generation in CI pipeline
10. [ ] Secrets: Verify no hardcoded secrets in CI files
11. [ ] Secrets: Verify TruffleHog/similar scans full history

## Output Format

```markdown
### Finding: [Title]
- **Severity**: CRITICAL | HIGH | MEDIUM | LOW
- **CWE**: CWE-XXX
- **File(s)**: path:line
- **Evidence**: CI config snippet or dependency entry
- **Impact**: Supply chain compromise, secret leak, or vulnerable dependency
- **Remediation**: Specific CI/dependency fix
```

## Cross-References
- Agent 5 (docker-container) — Docker build pipeline
