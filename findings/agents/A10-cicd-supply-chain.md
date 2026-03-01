# Agent 10: CI/CD & Supply Chain Security Findings

**Agent**: A10 — CI/CD & Supply Chain
**Files Audited**: `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `.github/workflows/npm-publish.yml`, `.github/ISSUE_TEMPLATE/security_vulnerability.md`
**Date**: 2026-03-02
**Findings**: 15 (2 HIGH, 8 MEDIUM, 4 LOW, 1 INFO)

---

### SHIELD-A10-001: All GitHub Actions Pinned by Tag/Branch — Not SHA
- **Tag**: VERIFIED
- **Severity**: HIGH
- **CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
- **Location**: `.github/workflows/ci.yml:24,27,33,64,89,109,130,148,154,186,189,197,218,254,275,301,325,338,356,364,375,402` (all `uses:` lines), `.github/workflows/release.yml:56,59,72,102,112,115,132,146,151,169,248,251,265,270,291,295` (all `uses:` lines), `.github/workflows/npm-publish.yml:15,17`
- **Evidence**:
  ```yaml
  # ci.yml — ALL 50+ action references use mutable tags:
  - uses: actions/checkout@v4           # tag, not SHA
  - uses: dtolnay/rust-toolchain@stable # branch, not SHA
  - uses: actions/cache@v4
  - uses: actions/setup-python@v5
  - uses: actions/setup-node@v4
  - uses: actions/setup-go@v5
  - uses: actions/setup-java@v4
  - uses: gradle/actions/setup-gradle@v3
  - uses: android-actions/setup-android@v3
  - uses: swift-actions/setup-swift@v2
  - uses: actions/setup-dotnet@v4
  - uses: trufflesecurity/trufflehog@main  # MUTABLE BRANCH
  - uses: codecov/codecov-action@v4
  - uses: softprops/action-gh-release@v1
  - uses: actions/upload-artifact@v4
  - uses: actions/download-artifact@v4
  ```
- **Impact**: Tag-based pinning allows upstream compromises to inject malicious code into CI/CD pipelines. A compromised `@v4` tag could exfiltrate `CARGO_REGISTRY_TOKEN`, `PYPI_API_TOKEN`, `NPM_TOKEN`, and `GITHUB_TOKEN` secrets. Supply chain attack vector — attacker moves a tag to a malicious commit on any of the 13 distinct third-party actions used. `dtolnay/rust-toolchain@stable` is pinned to a mutable BRANCH (not even a tag). The security scanner itself (`trufflehog@main`) tracks a mutable branch — the one action that should be most trustworthy is the least pinned.
- **Reproduction**: 1. Enumerate all `uses:` directives across 3 workflow files. 2. Verify ZERO use SHA-based pinning (`@sha256:...` or `@{full-sha}`). 3. Count 50+ action references across 13 distinct third-party actions, all using mutable references.
- **Fix Complexity**: MEDIUM (pin all 13 actions to SHAs, set up Dependabot for updates)
- **Remediation**: Pin all actions to full SHA hashes. Example: `actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11` instead of `@v4`. Use Dependabot or Renovate to auto-update SHA pins. Priority: `trufflehog@main` (security tool), `dtolnay/rust-toolchain@stable` (mutable branch), `softprops/action-gh-release@v1` (release creation).
- **Verification Notes**: Manually inspected all `uses:` lines across all 3 workflow files. Zero SHA pins found. This is confirmed CWE-829.

---

### SHIELD-A10-002: TruffleHog Pinned to @main Branch — Security Scanner Most Vulnerable
- **Tag**: VERIFIED
- **Severity**: HIGH
- **CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
- **Location**: `.github/workflows/ci.yml:364`
- **Evidence**:
  ```yaml
  - name: Check for secrets
    uses: trufflesecurity/trufflehog@main   # Mutable branch ref
    with:
      path: ./
      base: ${{ github.event.repository.default_branch }}
      head: HEAD
  ```
- **Impact**: The security scanning action is itself the least securely pinned action in the entire pipeline. An upstream compromise of `trufflesecurity/trufflehog` `main` branch would execute arbitrary code with full repo access on every CI run. The action receives `path: ./` (full repo read) and runs before any security gate. Additionally, the scan only compares `base` (default branch) to `HEAD` — meaning it only scans the diff, not full git history. Historical secrets in older commits are never detected.
- **Reproduction**: 1. Check `ci.yml:364` — `@main` is a mutable branch, not SHA or even a tagged version. 2. Verify `base`/`head` configuration only scans diff, not `--since-commit=0` or similar full-history option.
- **Fix Complexity**: LOW
- **Remediation**: 1. Pin to a specific SHA: `trufflesecurity/trufflehog@<sha>`. 2. For full history scanning, add `--since-commit` or use `extra_args: --only-verified` with periodic full scans. 3. Consider adding `--results=verified` to reduce false positives while ensuring real secrets are caught.
- **Verification Notes**: Confirmed `@main` is a branch ref. Confirmed `base`/`head` parameters limit to diff scanning only. Escalated to HIGH because this is the security scanner — the one tool that should be most trustworthy.

---

### SHIELD-A10-003: No Dependency Vulnerability Scanning for Python, JavaScript, Go, Java
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-1104 (Use of Unmaintained Third-Party Components)
- **Location**: `.github/workflows/ci.yml` (entire file — no `pip audit`, `npm audit`, `govulncheck`, or Gradle dependency check)
- **Evidence**:
  ```yaml
  # ci.yml security job only covers Rust:
  security:
    name: Security Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run cargo audit
        run: |
          cargo install cargo-audit
          cd shield-core && cargo audit
      # No pip audit, npm audit, govulncheck, or gradle audit
  ```
- **Impact**: Vulnerable dependencies in Python, JavaScript, Go, Java, C#, Kotlin, or Swift SDKs will not be detected in CI. Only Rust crate vulnerabilities are scanned. Shield publishes to PyPI, npm, and Go module registries — vulnerable transitive dependencies could ship to users.
- **Reproduction**: 1. Search all 3 workflow files for `pip audit`, `npm audit`, `govulncheck`, `gradle dependencyCheckAnalyze`, `dotnet list package --vulnerable`. 2. Confirm zero results. Only `cargo audit` exists.
- **Fix Complexity**: LOW
- **Remediation**: Add to the `security` job: `pip install pip-audit && pip-audit`, `cd javascript && npm audit --audit-level=high`, `go install golang.org/x/vuln/cmd/govulncheck@latest && cd go && govulncheck ./...`. Consider adding OWASP dependency-check for Java/Gradle.
- **Verification Notes**: Grep confirmed no dependency scanning commands exist for any non-Rust language.

---

### SHIELD-A10-004: Release Binaries Not Signed — No Provenance Attestation
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-494 (Download of Code Without Integrity Check)
- **Location**: `.github/workflows/release.yml:80-106` (build steps), `.github/workflows/release.yml:168-240` (release creation)
- **Evidence**:
  ```yaml
  # release.yml — binary built and uploaded with NO signing:
  - name: Build release binary
    run: |
      cd shield-core
      cargo build --release --target ${{ matrix.target }} --features cli

  # No cosign, GPG, or sigstore signing step

  # Checksums generated but NOT included in release files:
  - name: Generate checksums
    run: |
      cd artifacts
      echo "## SHA256 Checksums" > ../checksums.md
      # ...

  # Release files list — NO checksums.md included:
  - name: Create Release
    uses: softprops/action-gh-release@v1
    with:
      files: |
        artifacts/**/*.tar.gz
        artifacts/**/*.zip
      # checksums.md is NOT in this list
  ```
- **Impact**: Users downloading release binaries have no way to verify integrity or provenance. SHA256 checksums are generated (line 159-166) but written to `checksums.md` which is NOT uploaded as a release asset — it's only embedded in the release body text. No GPG signatures, no cosign, no SLSA provenance for CLI binaries. An attacker who compromises the GitHub release page could replace binaries.
- **Reproduction**: 1. Check release.yml `files:` block (line 234-236) — only `*.tar.gz` and `*.zip`. No `checksums.txt`, no `.sig`, no `.pem`. 2. Verify no `cosign`, `gpg`, `slsa-*`, or `sigstore` steps exist. 3. Note checksums in release body are not machine-verifiable (embedded in markdown).
- **Fix Complexity**: MEDIUM
- **Remediation**: 1. Upload `checksums.txt` as a release asset (add to `files:` block). 2. Add cosign signing: `cosign sign-blob --yes --oidc-issuer=... artifact.tar.gz`. 3. Consider SLSA provenance generation using `slsa-framework/slsa-github-generator`. 4. npm-publish.yml already uses `--provenance` — extend this model to other registries.
- **Verification Notes**: Confirmed checksums.md generated but not in release files list. Confirmed zero signing steps across all workflows.

---

### SHIELD-A10-005: No SBOM Generated in CI/CD Pipeline
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-1104 (Use of Unmaintained Third-Party Components)
- **Location**: `.github/workflows/ci.yml`, `.github/workflows/release.yml` (absence)
- **Evidence**: Searched all 3 workflow files for: `sbom`, `cyclonedx`, `spdx`, `syft`, `trivy`. Zero results.
- **Impact**: No Software Bill of Materials generated or published with releases. Enterprise consumers cannot verify the complete dependency tree. Compliance gap for NIST EO 14028, CIS, and emerging EU CRA requirements. Shield ships to 4 registries (crates.io, PyPI, npm, GitHub Releases) with no SBOM for any.
- **Reproduction**: Grep all workflow files for SBOM-related tooling names. Confirm zero matches.
- **Fix Complexity**: LOW
- **Remediation**: Add to release pipeline: `cargo install cargo-cyclonedx && cargo cyclonedx --format json > sbom.json`, or use `anchore/sbom-action` GitHub Action. Upload SBOM as release artifact alongside binaries.
- **Verification Notes**: Confirmed absence across all workflows and CI configs.

---

### SHIELD-A10-006: `cargo publish --allow-dirty` Publishes from Unclean Working Directory
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-494 (Download of Code Without Integrity Check)
- **Location**: `.github/workflows/release.yml:256`
- **Evidence**:
  ```yaml
  - name: Publish to crates.io
    env:
      CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}
    run: cd shield-core && cargo publish --allow-dirty
    continue-on-error: true
  ```
- **Impact**: `--allow-dirty` bypasses Cargo's working directory cleanliness check, meaning the published crate could contain uncommitted modifications, debug artifacts, or test files. Combined with `continue-on-error: true`, even if the publish partially fails or includes unexpected content, the pipeline continues silently.
- **Reproduction**: 1. Observe `--allow-dirty` flag at release.yml:256. 2. Verify no preceding `cargo verify-project` or `git status --porcelain` check.
- **Fix Complexity**: LOW
- **Remediation**: Remove `--allow-dirty`. If CI requires it due to generated files, add an explicit `git status` check and allowlist specific generated files. Add `cargo package --list` to verify published content matches expectations.
- **Verification Notes**: Confirmed `--allow-dirty` is present. This flag is a Cargo safety bypass.

---

### SHIELD-A10-007: All Three Registry Publish Steps Use `continue-on-error: true`
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-390 (Detection of Error Condition Without Action)
- **Location**: `.github/workflows/release.yml:257,283,306`
- **Evidence**:
  ```yaml
  # Rust publish
  run: cd shield-core && cargo publish --allow-dirty
  continue-on-error: true    # line 257

  # Python publish
  run: cd python && twine upload dist/*
  continue-on-error: true    # line 283

  # npm publish
  run: cd javascript && npm publish --access public
  continue-on-error: true    # line 306
  ```
- **Impact**: Failed publishes to crates.io, PyPI, or npm are silently swallowed. A version mismatch, authentication failure, tampered package, or partial upload would not fail the release pipeline. The GitHub Release would be marked successful even if zero packages were actually published. Users might download outdated or inconsistent versions across registries.
- **Reproduction**: Check release.yml lines 257, 283, 306 — all three publish jobs use `continue-on-error: true`.
- **Fix Complexity**: LOW
- **Remediation**: Remove `continue-on-error: true` from all publish steps. If idempotency is needed (re-running a release), use version-already-exists detection instead of blanket error suppression. Add a final verification step that checks each registry for the expected version.
- **Verification Notes**: Confirmed on all three publish steps. This masks supply chain failures.

---

### SHIELD-A10-008: Unpinned `cargo install` Commands in CI
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
- **Location**: `.github/workflows/ci.yml:343,360,383`
- **Evidence**:
  ```yaml
  # WASM build:
  - name: Install wasm-pack
    run: cargo install wasm-pack           # line 343 - latest version

  # Security scan:
  - name: Run cargo audit
    run: |
      cargo install cargo-audit            # line 360 - latest version
      cd shield-core && cargo audit

  # Coverage:
  - name: Install cargo-llvm-cov
    run: cargo install cargo-llvm-cov      # line 383 - latest version
  ```
- **Impact**: Three `cargo install` commands fetch the latest version from crates.io on every CI run without version pinning. A compromised or backdoored version of `wasm-pack`, `cargo-audit`, or `cargo-llvm-cov` would be automatically installed in the CI environment, with access to all secrets and source code. The security auditor (`cargo-audit`) is particularly ironic — the tool meant to find vulnerabilities is itself unpinned.
- **Reproduction**: Search ci.yml for `cargo install` — find 3 occurrences, none with `--version X.Y.Z`.
- **Fix Complexity**: LOW
- **Remediation**: Pin to specific versions: `cargo install wasm-pack --version 0.12.1`, `cargo install cargo-audit --version 0.20.0`, `cargo install cargo-llvm-cov --version 0.6.0`. Update periodically via PR.
- **Verification Notes**: Confirmed all three `cargo install` commands lack `--version` pinning.

---

### SHIELD-A10-009: Release Workflow Permissions Too Broad — `contents: write` Global
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-250 (Execution with Unnecessary Privileges)
- **Location**: `.github/workflows/release.yml:17`
- **Evidence**:
  ```yaml
  permissions:
    contents: write    # Global for ALL jobs in this workflow
  ```
  The `build-binaries` and `build-wasm` jobs only need `contents: read` — they compile and upload artifacts. Only the `release` job needs `contents: write` to create the GitHub Release. Publish jobs (`publish-rust`, `publish-python`, `publish-npm`) only need `contents: read`.
- **Impact**: All 7 jobs in the release workflow run with `contents: write` permission, but only 1 job (`release`) actually needs write access. If any of the 6 non-release jobs are compromised (via unpinned actions or `cargo install`), they could modify repository contents, create tags, or tamper with releases.
- **Reproduction**: 1. Check release.yml:17 — global `permissions: contents: write`. 2. Verify no job-level permission overrides. 3. Note only `release` job creates the GitHub Release.
- **Fix Complexity**: LOW
- **Remediation**: Move `permissions: contents: write` to the `release` job only. Set workflow-level to `contents: read`. Each job should declare its own minimal permissions.
- **Verification Notes**: Confirmed global write permissions. No job-level permission scoping exists in release.yml.

---

### SHIELD-A10-010: `workflow_dispatch` Accepts Unvalidated Version Input
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-20 (Improper Input Validation)
- **Location**: `.github/workflows/release.yml:8-11`
- **Evidence**:
  ```yaml
  workflow_dispatch:
    inputs:
      version:
        description: 'Version tag (e.g., v0.1.0)'
        required: true
        # No pattern/regex validation
  ```
  The `version` input is used in the release workflow but there's no validation that it matches a semver pattern. While the tag trigger (`v*`) provides some format enforcement, `workflow_dispatch` allows arbitrary strings. The version string is interpolated into release notes which could enable markdown injection.
- **Impact**: A user with write access could trigger a manual release with arbitrary version strings. While not directly exploitable for code injection (GitHub sanitizes markdown in release bodies), it could cause confusion with non-standard version tags or break downstream version parsing.
- **Reproduction**: 1. Navigate to Actions → Release → Run workflow. 2. Enter any string as version (e.g., `not-a-version`). 3. Observe no validation error.
- **Fix Complexity**: LOW
- **Remediation**: Add a validation step at the start of the workflow: `if: github.event_name == 'workflow_dispatch' && !startsWith(github.event.inputs.version, 'v')` → fail. Or validate with regex in a script step.
- **Verification Notes**: Confirmed no input validation on workflow_dispatch version parameter.

---

### SHIELD-A10-011: Duplicate npm Publish Workflows — Inconsistent Configuration
- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-1188 (Initialization with Hard-Coded Network Resource Configuration)
- **Location**: `.github/workflows/release.yml:286-306` AND `.github/workflows/npm-publish.yml:1-35`
- **Evidence**:
  ```yaml
  # release.yml (publish-npm job):
  run: cd javascript && npm publish --access public
  # NO --provenance flag
  # NO tests before publish
  # continue-on-error: true

  # npm-publish.yml (publish job):
  run: npm publish --access public --provenance
  # HAS --provenance flag
  # Runs npm test before publish
  # NO continue-on-error
  ```
- **Impact**: Two separate workflows publish to npm with different security postures. `npm-publish.yml` correctly uses `--provenance` and runs tests before publishing. `release.yml`'s npm publish step does NOT use `--provenance` and does NOT run tests. Depending on which workflow is triggered, npm packages may or may not have provenance attestation. The release workflow (tag-triggered) likely runs more frequently than the npm-specific one (release-event-triggered), meaning most publishes lack provenance.
- **Reproduction**: 1. Compare `release.yml:305` (`npm publish --access public`) with `npm-publish.yml:32` (`npm publish --access public --provenance`). 2. Note `npm-publish.yml` runs on `release.types: [published]` which fires AFTER `release.yml` creates the release — both could attempt to publish.
- **Fix Complexity**: LOW
- **Remediation**: Remove the `publish-npm` job from `release.yml` and rely solely on `npm-publish.yml` which fires on `release.types: [published]`. Or consolidate into one workflow with `--provenance` flag.
- **Verification Notes**: Confirmed duplicate publish paths with different configurations. Race condition possible.

---

### SHIELD-A10-012: `pip install -e ".[dev]"` in CI — Editable Install Not Reproducible
- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-1104 (Use of Unmaintained Third-Party Components)
- **Location**: `.github/workflows/ci.yml:71`
- **Evidence**:
  ```yaml
  - name: Install dependencies
    run: |
      cd python
      pip install -e ".[dev]"   # Editable install, no lock file
  ```
  No `requirements.txt` or `pip freeze` lock file is used. The Python SDK tests install dependencies using editable mode with version ranges from `pyproject.toml`. This means each CI run may install slightly different dependency versions.
- **Impact**: Non-reproducible Python builds. A compromised or vulnerable version of a transitive dependency could be silently pulled into CI. `pip install -e` also installs the package as a development reference, not a wheel — different from what users get via `pip install shield-crypto`.
- **Reproduction**: 1. Check ci.yml:71 — `pip install -e ".[dev]"`. 2. Verify no `requirements-lock.txt` or `pip freeze` step. 3. Python has zero runtime dependencies, but dev dependencies (`pytest`, `pytest-cov`) are unpinned.
- **Fix Complexity**: LOW
- **Remediation**: Use `pip install --constraint constraints.txt -e ".[dev]"` with a committed constraints file, or generate and commit a `requirements-dev.txt` lock file.
- **Verification Notes**: Confirmed no lock file usage for Python CI. Runtime deps are zero, but dev deps are unpinned.

---

### SHIELD-A10-013: Browser SDK Uses `npm install` Instead of `npm ci`
- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-1104 (Use of Unmaintained Third-Party Components)
- **Location**: `.github/workflows/ci.yml:114`
- **Evidence**:
  ```yaml
  # Browser SDK job:
  - name: Install dependencies
    run: cd browser && npm install    # line 114 — npm install, NOT npm ci

  # JavaScript SDK job (correct):
  - name: Install dependencies
    run: cd javascript && npm ci      # line 96 — npm ci (correct)
  ```
- **Impact**: `npm install` may modify `package-lock.json` in-flight if package.json ranges resolve to newer versions than what's locked. `npm ci` is designed for CI — it strictly installs from the lock file and fails if it doesn't match. The JavaScript SDK correctly uses `npm ci`, but the Browser SDK does not.
- **Reproduction**: Compare ci.yml:96 (`npm ci`) with ci.yml:114 (`npm install`).
- **Fix Complexity**: LOW
- **Remediation**: Change `npm install` to `npm ci` for the browser SDK job.
- **Verification Notes**: Confirmed inconsistency between JavaScript and Browser SDK install commands.

---

### SHIELD-A10-014: No Rust Crate or Python Package Signing for PyPI/crates.io
- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-494 (Download of Code Without Integrity Check)
- **Location**: `.github/workflows/release.yml:253-256` (Rust), `.github/workflows/release.yml:275-282` (Python)
- **Evidence**:
  ```yaml
  # Rust — no signing:
  run: cd shield-core && cargo publish --allow-dirty
  # No --signed flag, no GPG key configuration

  # Python — no signing:
  run: cd python && twine upload dist/*
  # No --sign flag, no GPG key configuration
  # No Trusted Publisher / OIDC flow for PyPI
  ```
  Contrast with npm-publish.yml which uses `--provenance` (OIDC-based attestation). Rust and Python publishes have zero signing or attestation.
- **Impact**: crates.io and PyPI packages have no cryptographic signature or provenance attestation. Users cannot verify the published package was built from the claimed source. npm is the only registry with provenance (via npm-publish.yml's `--provenance` flag).
- **Reproduction**: Check release.yml publish steps for `--sign`, `--signed`, GPG config, or OIDC provenance. Confirm absent for Rust and Python.
- **Fix Complexity**: MEDIUM
- **Remediation**: For PyPI: Migrate to Trusted Publishers (OIDC) — no API token needed, automatic provenance. For crates.io: Use `cargo-vet` or wait for crates.io signing support. Add cosign signing as a fallback.
- **Verification Notes**: Only npm has provenance. Rust and Python registries have zero signing.

---

### SHIELD-A10-015: Security Vulnerability Disclosure Process Properly Configured
- **Tag**: NON-VULN
- **Severity**: INFO
- **CWE**: N/A
- **Location**: `.github/ISSUE_TEMPLATE/security_vulnerability.md`
- **Evidence**:
  ```markdown
  ## STOP - Do Not Use This Template
  **Security vulnerabilities should NOT be reported via GitHub issues.**
  Please report security vulnerabilities privately to:
  **Email: security@guard8.ai**
  ```
- **Impact**: N/A — this is a positive finding. The security disclosure template correctly redirects vulnerability reports to a private email channel instead of public GitHub issues.
- **Reproduction**: Read `.github/ISSUE_TEMPLATE/security_vulnerability.md`.
- **Fix Complexity**: N/A
- **Remediation**: N/A. Consider also adding a `SECURITY.md` at repo root with the same information, and enabling GitHub's private vulnerability reporting feature.
- **Verification Notes**: Template confirmed. Correctly prevents public vulnerability disclosure via issues.

---

## Summary

| Severity | Count | Finding IDs |
|----------|-------|-------------|
| HIGH | 2 | A10-001, A10-002 |
| MEDIUM | 8 | A10-003, A10-004, A10-005, A10-006, A10-007, A10-008, A10-009, A10-010 |
| LOW | 4 | A10-011, A10-012, A10-013, A10-014 |
| INFO | 1 | A10-015 |
| **Total** | **15** | |

## Audit Checklist Results

| # | Check | Result |
|---|-------|--------|
| 1 | GH Actions pinned by SHA | **FAIL** — 0/50+ actions pinned (A10-001, A10-002) |
| 2 | GITHUB_TOKEN minimal permissions | **PARTIAL** — ci.yml good (read), release.yml too broad (A10-009) |
| 3 | No secrets in logs | **PASS** — secrets properly masked via standard env patterns |
| 4 | Dependency audit in CI | **PARTIAL** — Rust only, 4+ languages missing (A10-003) |
| 5 | Lock files used | **PARTIAL** — JS uses npm ci, Browser uses npm install (A10-013) |
| 6 | Exact versions | **PARTIAL** — cargo install unpinned (A10-008), pip unpinned (A10-012) |
| 7 | Packages signed | **PARTIAL** — npm only via provenance (A10-014), Rust/Python unsigned (A10-004) |
| 8 | SLSA provenance | **FAIL** — No SLSA for binaries or non-npm packages (A10-004) |
| 9 | SBOM generated | **FAIL** — No SBOM at all (A10-005) |
| 10 | No hardcoded secrets | **PASS** — All secrets via GitHub Secrets |
| 11 | TruffleHog full history | **FAIL** — Diff-only scanning (A10-002) |
