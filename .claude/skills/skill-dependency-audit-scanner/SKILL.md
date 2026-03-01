---
name: skill-dependency-audit-scanner
description: Audit dependency manifests across 8+ package managers for known vulnerabilities, unpinned versions, and supply chain risks. Use when auditing dependencies.
---

# Dependency Audit Scanner

Audit dependency manifests across Shield's package managers for vulnerabilities and supply chain risks.

## When to Use
- Auditing dependencies for known CVEs
- Checking version pinning across package managers
- Reviewing supply chain attack surface

## Inputs
- Target language(s) or "all"
- Check type: "versions" | "vulns" | "pinning" | "all"

## Procedure
1. Locate dependency manifests:

### Package Manager Matrix
| Language | Manifest | Lock File |
|----------|----------|-----------|
| Rust | `Cargo.toml` | `Cargo.lock` |
| Python | `requirements.txt`, `pyproject.toml`, `setup.py` | `requirements.txt` (pinned) |
| JavaScript | `package.json` | `package-lock.json` |
| Go | `go.mod` | `go.sum` |
| Java | `build.gradle` | `gradle.lockfile` |
| C# | `*.csproj` | `packages.lock.json` |
| Swift | `Package.swift` | `Package.resolved` |
| Kotlin | `build.gradle.kts` | `gradle.lockfile` |

2. Check each manifest:

### Version Pinning
| Pattern | Risk | Example |
|---------|------|---------|
| No version | Critical | `requests` |
| Range specifier | High | `^1.0.0`, `>=2.0`, `~3.1` |
| Wildcard | Critical | `*`, `latest` |
| Exact pin | Safe | `==1.2.3`, `=1.2.3` |
| Lock file missing | High | No lock file present |

### Supply Chain Checks
| Check | What to Look For |
|-------|-----------------|
| Typosquatting | Similar names to popular packages |
| Maintainer count | Single-maintainer critical deps |
| Install scripts | `postinstall`, `preinstall` hooks |
| Native compilation | Packages requiring native build tools |
| Transitive deps | High-risk transitive dependencies |

3. For crypto-specific deps, verify:
   - Using well-known crypto libraries (not custom implementations)
   - No deprecated crypto packages
   - Versions without known crypto vulnerabilities

## Output Format
```
### Dependency Audit: [language]
| # | Package | Version Spec | Pinned? | Lock? | Risk |
|---|---------|-------------|---------|-------|------|
| 1 | sha2 | "0.10" | Range | Yes | Medium |
...

**Summary**: X deps, Y unpinned, Z without lock
```

## Used By
- A10 (CI/CD Supply Chain)
- T07 (Supply Chain)
