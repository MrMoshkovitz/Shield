# Team 7: Supply Chain to Runtime — Cross-Domain Chain Analysis

**Team**: T07 — Supply Chain to Runtime
**Phase**: 4 (Cross-Domain Batch 1)
**Priority**: HIGH
**Date**: 2026-03-03
**Input Findings**: A10 (CI/CD Supply Chain), A05 (Docker & Container), A09 (Browser & WASM)

---

## Chain Question

**Can a supply chain compromise propagate through CI/CD and deployment to silently corrupt runtime crypto?**

---

## Summary

| Severity | Count | Finding IDs |
|----------|-------|-------------|
| HIGH | 3 | SHIELD-T07-001, SHIELD-T07-002, SHIELD-T07-003 |
| MEDIUM | 3 | SHIELD-T07-004, SHIELD-T07-005, SHIELD-T07-006 |
| LOW | 1 | SHIELD-T07-007 |
| **Total** | **7** | |

---

## Supply Chain Attack Tree

```
                    ┌─────────────────────────────┐
                    │   SUPPLY CHAIN ENTRY POINTS   │
                    └─────────────────────────────┘
                           │
           ┌───────────────┼───────────────┐
           ▼               ▼               ▼
  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
  │ BUILD PHASE  │ │ PUBLISH PHASE│ │ DEPLOY PHASE │
  │              │ │              │ │              │
  │ GH Actions   │ │ crates.io   │ │ Docker pull  │
  │ tag-pinned   │ │ --allow-    │ │ no digest    │
  │ (A10-001)    │ │ dirty       │ │ (A05-004)    │
  │              │ │ (A10-006)   │ │              │
  │ cargo install│ │              │ │ Opaque       │
  │ unpinned     │ │ PyPI legacy │ │ containers   │
  │ (A10-008)    │ │ token       │ │ SHIELD_PASS  │
  │              │ │ (A10-026)   │ │ in env       │
  │ No Cargo.lock│ │              │ │ (A05-006)    │
  │ (A10-017/025)│ │ npm no      │ │              │
  │              │ │ provenance  │ │ Browser WASM │
  │ TruffleHog   │ │ (A10-011)   │ │ no SRI hash  │
  │ @main        │ │              │ │ (A09-004)    │
  │ (A10-002)    │ │ continue-on │ │              │
  │              │ │ -error:true │ │ npm install  │
  └──────────────┘ │ (A10-007)   │ │ not npm ci   │
                   └──────────────┘ │ (A10-013)    │
                                    └──────────────┘
                           │
                           ▼
              ┌───────────────────────┐
              │    RUNTIME IMPACT      │
              │                       │
              │ Corrupted crypto in:  │
              │ - CLI binaries        │
              │ - WASM module         │
              │ - npm/PyPI/crate pkgs │
              │ - Docker containers   │
              └───────────────────────┘
```

---

## Cross-Domain Findings

### SHIELD-T07-001: Full CI/CD to Registry to Runtime Attack Chain via Unpinned Actions + Silent Publish Failures

- **Tag**: VERIFIED
- **Severity**: HIGH
- **CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
- **Component Findings**: SHIELD-A10-001 (HIGH), SHIELD-A10-002 (HIGH), SHIELD-A10-007 (MEDIUM), SHIELD-A10-006 (MEDIUM)
- **Location**: `.github/workflows/release.yml` (entire pipeline), `.github/workflows/ci.yml` (build pipeline)
- **Evidence**:
  The release pipeline has no integrity verification at ANY stage of the build-publish-deploy chain:
  1. **Build**: 50+ GH Actions pinned by mutable tags (A10-001), 3x `cargo install` unpinned (A10-008), TruffleHog security scanner itself on `@main` branch (A10-002)
  2. **Artifact transfer**: No checksums between build-release jobs (A10-027)
  3. **Publish**: `cargo publish --allow-dirty` (A10-006), all 3 registry publishes use `continue-on-error: true` (A10-007)
  4. **No post-publish verification**: No step checks that published packages match built artifacts

  ```
  ATTACK CHAIN:
  1. Attacker compromises a single GH Action upstream (e.g., moves actions/checkout@v4 tag)
  2. Compromised action runs in build job with access to CARGO_REGISTRY_TOKEN, PYPI_API_TOKEN, NPM_TOKEN
  3. Attacker modifies crypto implementation during build (e.g., weakens PBKDF2 iterations, backdoors key generation)
  4. cargo publish --allow-dirty publishes modified crate with no integrity check
  5. continue-on-error: true masks partial failures
  6. No post-publish verification - corrupted packages are live on 3 registries
  7. Downstream users install corrupted shield-core/shield-crypto/@guard8/shield
  8. All encrypted data uses attacker-weakened crypto - recoverable plaintext
  ```

- **Impact**: A single compromised upstream GH Action can propagate through the entire release pipeline to publish backdoored packages to crates.io, PyPI, and npm simultaneously. The `continue-on-error: true` on all publish steps means even partial corruption goes undetected. Combined with no Cargo.lock (A10-017/A10-025), the builds are non-reproducible making forensic analysis of "was this the intended build?" impossible. The chain reaches ALL Shield users across all registries.
- **Reproduction**:
  1. Enumerate mutable action refs in release.yml - 16+ uses: lines with `@v4`, `@stable`, `@v5`, `@main`
  2. Verify `continue-on-error: true` on release.yml lines 257, 283, 306
  3. Verify no checksums in artifact upload (line 101-105) vs download (line 150-153)
  4. Verify no post-publish registry verification step
- **Fix Complexity**: MEDIUM
- **Remediation**:
  1. SHA-pin all actions (A10-001 fix)
  2. Remove `continue-on-error: true` from publish steps
  3. Add build-time checksums to artifacts, verify at release time (A10-027 fix)
  4. Add post-publish verification: `cargo info shield-core`, `pip index versions shield-crypto`, `npm view @guard8/shield version`
  5. Scope permissions per-job (A10-009 fix)
- **Verification Notes**: Each component verified individually in A10 findings. This chain analysis confirms they combine into a single exploitable path from upstream action compromise to end-user runtime crypto corruption.

---

### SHIELD-T07-002: WASM Binary Supply Chain Has No Integrity From Build to Browser Runtime

- **Tag**: VERIFIED
- **Severity**: HIGH
- **CWE**: CWE-494 (Download of Code Without Integrity Check)
- **Component Findings**: SHIELD-A09-004 (MEDIUM), SHIELD-A10-013 (LOW), SHIELD-A10-021 (LOW), SHIELD-A10-008 (MEDIUM)
- **Location**: `browser/js/index.ts:19-20`, `.github/workflows/ci.yml:114,343`, `browser/package.json:47-56`
- **Evidence**:
  The WASM binary (`shield_browser_bg.wasm`) has zero integrity verification across its entire lifecycle:

  ```
  BUILD:
    ci.yml:343  -> cargo install wasm-pack (unpinned version from crates.io)
    ci.yml:114  -> npm install (not npm ci - can resolve different deps)
    browser/    -> devDeps all use ^caret ranges

  PUBLISH:
    npm-publish.yml -> --provenance covers JS wrapper but NOT WASM binary
    WASM .wasm file -> bundled as asset in npm package, no separate hash

  RUNTIME:
    index.ts:19 -> import init from '../pkg/shield_browser.js'
                -> loads .wasm file with no SRI hash
                -> no Content-Security-Policy require-sri-for enforcement
                -> no checksum verification before init()

  ATTACK:
    CDN compromise -> serve modified .wasm -> weak crypto in browser
    npm cache poison -> modified package -> .wasm with backdoor
    DNS hijack -> different .wasm binary served
  ```

- **Impact**: An attacker who compromises ANY point in the WASM build-publish-deploy chain can replace the WASM binary with one that has weakened crypto (e.g., static nonce, known key, reduced iterations). The browser SDK has NO mechanism to detect this. Combined with A09-001 (key transported in plaintext), the attacker can: (1) serve a WASM module that exfiltrates keys, or (2) serve one that uses a predictable keystream, making all "encrypted" browser-side data recoverable.
- **Reproduction**:
  1. Build modified WASM: change `PBKDF2_ITERATIONS` to 1 in `wasm.rs`, build with `wasm-pack`
  2. Replace `shield_browser_bg.wasm` in npm package or CDN
  3. SDK loads modified WASM without error
  4. All browser-side encryption uses 1-iteration key derivation - trivially brute-forceable
- **Fix Complexity**: MEDIUM
- **Remediation**:
  1. Generate SHA-384 hash of WASM binary at build time
  2. Embed hash in JS wrapper: `const WASM_INTEGRITY = "sha384-..."`
  3. Verify hash in `init()` before execution
  4. Add `integrity` attribute when loading WASM if using `<script>` tags
  5. Use `npm ci` for browser build (fixes A10-013)
  6. Pin wasm-pack version (fixes A10-008)
  7. Document CSP headers: `require-sri-for script`
- **Verification Notes**: End-to-end chain verified. WASM binary has zero integrity checks from build through runtime. npm provenance only covers the JS package metadata, not the WASM binary contents.

---

### SHIELD-T07-003: Opaque Container Pipeline Has Password Exposure + Manifest Tampering + Unprotected Plaintext

- **Tag**: VERIFIED
- **Severity**: HIGH
- **CWE**: CWE-522 (Insufficiently Protected Credentials), CWE-312 (Cleartext Storage of Sensitive Information)
- **Component Findings**: SHIELD-A05-006 (MEDIUM), SHIELD-A05-021 (MEDIUM), SHIELD-A05-022 (MEDIUM), SHIELD-A05-024 (MEDIUM), SHIELD-A05-025 (MEDIUM)
- **Location**: `examples/opaque-containers/build-opaque.sh:104-117`, `examples/opaque-containers/run-opaque.sh:113-118`, `examples/opaque-containers/build-opaque.sh:138-153`
- **Evidence**:
  The opaque container workflow has a chained supply-chain vulnerability path:

  ```
  BUILD PHASE (build-opaque.sh):
    Line 112: echo "$SHIELD_PASSWORD" | shield encrypt ...
              -> Password in process list (ps aux), shell history if not from env
    Line 159: rm -f "${OUTPUT_NAME}.tar"
              -> Plaintext tar deleted with rm, not secure wipe
              -> Recoverable from disk with forensic tools
    Line 138-153: Manifest created from shell variables via heredoc
              -> No integrity protection on manifest
              -> IMAGE_NAME/IMAGE_VERSION come from user input (line 68-69)
              -> $IMAGE_NAME injected into JSON without escaping (line 140)

  DEPLOY PHASE (run-opaque.sh):
    Line 115: echo "$SHIELD_PASSWORD" | shield decrypt ...
              -> Same password exposure as build phase
    Line 148-150: IMAGE_NAME/VERSION read from manifest via jq
              -> Tampered manifest -> docker load arbitrary image tag
              -> Attacker changes "name" in manifest.json -> different image loaded
    Line 189: docker run --rm $RUN_OPTS "$IMAGE_TAG"
              -> $RUN_OPTS unquoted -> word splitting
              -> If manifest provides malicious image tag, arbitrary container runs

  FULL CHAIN:
    1. Attacker intercepts manifest.json (distributed alongside .enc file)
    2. Changes "name" to "attacker/malicious:1.0"
    3. Pre-pulls attacker image to target Docker daemon
    4. run-opaque.sh reads tampered manifest -> loads legitimate .enc
    5. But docker load of legitimate .tar + tampered tag = tag collision
    6. Or: attacker modifies sha256 file to match modified .enc -> full replacement
  ```

- **Impact**: The opaque container pipeline has multiple supply-chain weaknesses that chain together: (1) Password exposure via process list during both build and run, (2) Plaintext tar recoverable from disk after `rm -f`, (3) Manifest has no integrity protection - attacker can redirect image loading, (4) SHA256 checksum file stored alongside encrypted file with no signing - attacker can replace both. For enterprise customers using opaque containers to protect IP, this means: the encryption password can be captured from the process list, the plaintext container can be recovered from disk forensics, and a MITM can swap the entire encrypted container + checksum without detection.
- **Reproduction**:
  1. Run `build-opaque.sh myapp:1.0` with `SHIELD_PASSWORD=secret`
  2. In parallel: `ps aux | grep shield` to observe password in process arguments
  3. After build: `extundelete` or `debugfs` to recover deleted `.tar`
  4. Modify `myapp-1.0.manifest.json`: change `name` to `attacker-image`
  5. Recompute SHA256 of swapped `.enc`: update `.sha256` file
  6. Run `run-opaque.sh myapp-1.0.enc` to verify SHA256 (of tampered file), loads tampered container
- **Fix Complexity**: MEDIUM
- **Remediation**:
  1. Use `--password-from-fd 3` instead of `echo` piping (avoids process list exposure)
  2. Replace `rm -f` with `shred -uz` or overwrite for secure deletion
  3. Sign manifest with HMAC using Shield's own key: `shield encrypt --input manifest.json --output manifest.json.enc`
  4. Include manifest SHA256 INSIDE the encrypted container (before encryption), verify after decryption
  5. Quote `$RUN_OPTS` in `docker run` to prevent word splitting
- **Verification Notes**: Each component verified via source code reading. Chain analysis confirms the combination creates a complete supply-chain attack path against the opaque container feature.

---

### SHIELD-T07-004: Non-Reproducible Builds Across All Rust Artifacts (CLI + WASM + Library)

- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-1104 (Use of Unmaintained Third-Party Components)
- **Component Findings**: SHIELD-A10-017 (MEDIUM), SHIELD-A10-025 (MEDIUM), SHIELD-A10-008 (MEDIUM)
- **Location**: `.gitignore:3`, `shield-core/Cargo.toml`, `browser/Cargo.toml`
- **Evidence**:
  `.gitignore:3` explicitly excludes `Cargo.lock`, making ALL Rust builds non-reproducible:

  ```
  CHAIN:
  1. .gitignore:3 -> Cargo.lock excluded from git
  2. Cargo.toml uses loose ranges: ring = "0.17", serde = "1.0", etc.
  3. Each CI build resolves potentially different exact dependency versions
  4. cargo publish --allow-dirty publishes from this non-deterministic build
  5. No way to determine which exact versions shipped in a given release
  6. cargo audit in CI checks whatever versions happen to resolve - not what shipped
  7. release.yml:78 uses hashFiles('**/Cargo.lock') -> evaluates to empty string
     -> CI cache key is non-deterministic

  IMPACT ON FORENSICS:
  - If a vulnerability is found in ring 0.17.5 but not 0.17.4
  - Cannot determine which ring version was used in shield-core v2.1.0
  - Cannot reproduce the exact binary that was published
  - Incident response is blind: "was our release affected?" -> unanswerable
  ```

- **Impact**: Three security-critical artifacts (CLI binary, WASM module, Rust crate) are built non-reproducibly. If a dependency vulnerability is discovered (e.g., in `ring`, `subtle`, or `zeroize`), there is no way to determine which exact versions were included in which Shield release. This blocks effective incident response and makes supply-chain forensics impossible.
- **Reproduction**:
  1. `grep "Cargo.lock" .gitignore` line 3 confirms exclusion
  2. Build shield-core twice from same commit, compare binary hashes - differ
  3. Check release.yml:78 cache key uses `hashFiles('**/Cargo.lock')` which returns empty
- **Fix Complexity**: LOW
- **Remediation**:
  1. Remove `Cargo.lock` from `.gitignore`
  2. Run `cd shield-core && cargo generate-lockfile && git add Cargo.lock`
  3. Same for `browser/` directory
  4. Set up Dependabot for Cargo lock file updates
  5. Fix `release.yml:78` cache key to use actual lock file hash
- **Verification Notes**: Confirmed `.gitignore:3` contains `Cargo.lock`. Confirmed `hashFiles` evaluates to empty for missing files. Cross-references A10-017 and A10-025 root cause findings.

---

### SHIELD-T07-005: Registry Token Exfiltration Path via Static Long-Lived Tokens + Broad Job Permissions

- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-522 (Insufficiently Protected Credentials)
- **Component Findings**: SHIELD-A10-009 (MEDIUM), SHIELD-A10-026 (MEDIUM), SHIELD-A10-001 (HIGH)
- **Location**: `.github/workflows/release.yml:17,255,281,304`
- **Evidence**:
  ```
  SECRETS AT RISK:
    CARGO_REGISTRY_TOKEN (release.yml:255) - crates.io publish
    PYPI_API_TOKEN (release.yml:281) - PyPI publish
    NPM_TOKEN (release.yml:304) - npm publish
    GITHUB_TOKEN (release.yml:240) - release creation

  ACCESS SCOPE:
    release.yml:17 -> permissions: contents: write (GLOBAL to all 7 jobs)
    ALL jobs have access to all secrets via secrets.*
    Only 3 jobs actually need registry tokens

  EXFILTRATION PATH:
    1. Compromised action in build-binaries or build-wasm job (tag-pinned, A10-001)
    2. Job has contents:write (A10-009) + access to all secrets
    3. Action exfiltrates CARGO_REGISTRY_TOKEN + PYPI_API_TOKEN + NPM_TOKEN
    4. Attacker now has persistent publish access to all 3 registries
    5. PyPI token is long-lived static token (A10-026) - no expiry
    6. Attacker publishes backdoored packages at will

  PERSISTENCE:
    - PYPI_API_TOKEN has unlimited lifetime (A10-026)
    - NPM_TOKEN likely long-lived (standard npm auth token)
    - CARGO_REGISTRY_TOKEN long-lived
    - Even after fixing the action compromise, tokens remain valid
    - Must be manually rotated to revoke attacker access
  ```

- **Impact**: The combination of broad job permissions (A10-009), tag-pinned actions (A10-001), and static long-lived tokens (A10-026) creates a persistent exfiltration path. A single compromised upstream action can extract all three registry tokens. Unlike OIDC/Trusted Publisher tokens which are short-lived and scoped, these static tokens grant indefinite publish access. The attacker retains publishing capability even after the upstream compromise is fixed until all tokens are manually rotated.
- **Reproduction**:
  1. Verify global `permissions: contents: write` at release.yml:17
  2. Verify secrets available to all jobs (GitHub Actions default behavior)
  3. Verify PyPI uses static token (not OIDC Trusted Publisher) at line 281
  4. Note: npm-publish.yml uses `id-token: write` for npm provenance but release.yml's publish-npm does NOT
- **Fix Complexity**: MEDIUM
- **Remediation**:
  1. Scope permissions per-job, not globally
  2. Use GitHub Environments with required reviewers for publish jobs
  3. Migrate PyPI to Trusted Publishers (OIDC) to eliminate static token
  4. Add OIDC to release.yml npm publish (not just npm-publish.yml)
  5. Use `github.event_name` conditions to restrict which jobs run on which triggers
- **Verification Notes**: Each component verified in A10 findings. Chain analysis confirms the combined attack path creates persistent registry access for an attacker.

---

### SHIELD-T07-006: Docker Container Deployment Has No Artifact Integrity Chain

- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-494 (Download of Code Without Integrity Check)
- **Component Findings**: SHIELD-A05-004 (MEDIUM), SHIELD-A05-001 (HIGH), SHIELD-A05-002 (HIGH), SHIELD-A05-003 (MEDIUM)
- **Location**: `Dockerfile:1`, `docker-compose.yml`, `examples/opaque-containers/Dockerfile.example:1`
- **Evidence**:
  ```
  DEPLOYMENT PATH (Docker):
    Dockerfile:1 -> FROM ubuntu:22.04 (no digest, mutable tag)
    Dockerfile.example:1 -> FROM alpine:latest (mutable tag)

    No docker-content-trust = true in any config
    No --verify-tls in Docker commands
    No image signing (cosign, Notary)

  COMBINED WITH BUILD:
    Dockerfile:30 -> curl | sh (no checksum)
    All containers run as root (A05-001)
    Dev toolchains in production (A05-003)

  CHAIN:
    1. Compromised ubuntu:22.04 tag (or DNS -> malicious registry)
    2. Base image includes backdoored OpenSSL/libcrypto
    3. Shield builds on top with curl|sh Rust install (no verification)
    4. Container runs as root with dev tools
    5. All Shield crypto operations in the container use backdoored primitives
    6. For opaque containers: encrypted containers built with weak crypto
       -> customer's "protected" IP is recoverable
  ```

- **Impact**: Docker deployment has no integrity verification from base image through to running container. A supply chain attack on the Docker Hub `ubuntu:22.04` tag or `alpine:latest` tag would silently compromise all Shield Docker builds. For the opaque container use case, this means customer proprietary algorithms could be encrypted with compromised crypto defeating the entire product promise.
- **Reproduction**:
  1. Check `Dockerfile:1` for digest pinning - absent (`ubuntu:22.04`, no `@sha256:...`)
  2. Check `Dockerfile.example:1` - `alpine:latest` (mutable)
  3. Grep for `DOCKER_CONTENT_TRUST` - not set in any script or CI config
  4. Note: `docker-compose.yml` also uses `image: shield-dev` without pinning
- **Fix Complexity**: MEDIUM
- **Remediation**:
  1. Pin base images by digest: `FROM ubuntu:22.04@sha256:...`
  2. Replace curl|sh with official Rust Docker image multi-stage build
  3. Add `DOCKER_CONTENT_TRUST=1` to CI environment
  4. Add Dockerfile linting (hadolint) to CI
  5. Implement multi-stage build to separate build tools from runtime
- **Verification Notes**: Each component verified in A05 findings. Docker images confirmed unpinned. No content trust configuration found in any project file.

---

### SHIELD-T07-007: Security Scanner Itself Is the Least Secure Component in Pipeline

- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
- **Component Findings**: SHIELD-A10-002 (HIGH), SHIELD-A10-008 (MEDIUM)
- **Location**: `.github/workflows/ci.yml:364`, `.github/workflows/ci.yml:360`
- **Evidence**:
  ```
  IRONIC CHAIN:
    ci.yml:364 -> trufflesecurity/trufflehog@main (mutable BRANCH, not even a tag)
    ci.yml:360 -> cargo install cargo-audit (unpinned version)

  Both security tools - the secret scanner and the vulnerability scanner -
  are the LEAST securely pinned components in the entire pipeline.

  ATTACK SCENARIO:
    1. Attacker compromises trufflehog@main branch
    2. Modified trufflehog receives path: ./ (full repo access)
    3. Exfiltrates: source code, workflow secrets in environment
    4. Or: modified trufflehog silently suppresses real secret findings
    5. Similarly: compromised cargo-audit suppresses vulnerability reports

  DEFENSE EVASION:
    - Compromised trufflehog -> won't report leaked secrets
    - Compromised cargo-audit -> won't report vulnerable deps
    - Both tools are trusted to FIND problems -> if compromised, problems are HIDDEN
  ```

- **Impact**: The two security tools meant to catch supply chain problems are themselves the weakest links. A compromised TruffleHog could suppress secret leak findings, and a compromised cargo-audit could suppress vulnerability reports. The attacker doesn't need to disable security scanning they just need to compromise the scanner to make it silently pass.
- **Reproduction**:
  1. ci.yml:364: `trufflehog@main` - branch ref, not SHA
  2. ci.yml:360: `cargo install cargo-audit` - no `--version`
  3. Note both tools have full repo access and run before other checks
- **Fix Complexity**: LOW
- **Remediation**:
  1. Pin TruffleHog to SHA: `trufflesecurity/trufflehog@<sha>`
  2. Pin cargo-audit: `cargo install cargo-audit --version 0.20.0`
  3. Consider running security tools in a separate, more restricted job
  4. Add secondary scanning tool (e.g., GitHub's built-in secret scanning, `osv-scanner`)
- **Verification Notes**: Cross-references A10-002 (TruffleHog) and A10-008 (cargo-audit). Combined finding highlights the defense-evasion risk when security tools are the least secure components.

---

## Overall Assessment

### Risk Summary

The Shield supply chain has **no end-to-end integrity verification** from source code through to user runtime. The attack surface is broad:

| Stage | Integrity Mechanism | Status |
|-------|-------------------|--------|
| Source to Build | GH Actions pinning | **FAIL** - all tag/branch pinned |
| Build tools | Version pinning | **FAIL** - 3x unpinned cargo install |
| Build to Artifact | Checksums | **FAIL** - no build-time checksums |
| Artifact to Registry | Signing/provenance | **PARTIAL** - npm only (one of two workflows) |
| Registry to User | Package verification | **PARTIAL** - npm provenance, no Rust/Python |
| CDN to Browser | SRI/integrity | **FAIL** - no WASM integrity verification |
| Docker build | Image pinning | **FAIL** - mutable tags, curl-pipe-sh |
| Opaque containers | Manifest integrity | **FAIL** - unsigned, tamperable |

**Key risk**: A single compromised upstream GitHub Action can propagate through to all 3 registries + WASM binary + Docker containers, corrupting crypto for ALL Shield users across ALL platforms.

### Practical Exploitability

| Chain | Likelihood | Impact | Risk |
|-------|-----------|--------|------|
| GH Action to Registry tokens | MEDIUM | CRITICAL | HIGH |
| WASM binary tampering | LOW | HIGH | MEDIUM |
| Opaque container MITM | LOW | HIGH | MEDIUM |
| Non-reproducible build forensics | HIGH | MEDIUM | MEDIUM |
| Security scanner evasion | LOW | HIGH | LOW |

### Recommendations Priority

1. **IMMEDIATE**: SHA-pin all GH Actions, remove `continue-on-error: true` from publish steps
2. **WEEK 1**: Commit Cargo.lock files, migrate PyPI to Trusted Publishers (OIDC)
3. **WEEK 2**: Add WASM integrity verification (SRI hash), Docker image digest pinning
4. **WEEK 4**: SBOM generation, opaque container manifest signing, Dependabot setup
