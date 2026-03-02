# T11 — Configuration & Deployment Drift Chain Analysis

> **Team**: Team 11 — Config & Deployment Drift
> **Phase**: 4 (Cross-Domain Batch 1)
> **Priority**: HIGH
> **Auditor**: Ralph Loop — Iteration 47
> **Date**: 2026-03-04
> **Input Findings**: A05 (30), A06 (26), A10 (35), A11 (35)
> **Chain**: Dev configuration differences → production security gaps

---

## Summary

| Severity | Count | Finding IDs |
|----------|-------|-------------|
| HIGH | 2 | SHIELD-T11-001, SHIELD-T11-002 |
| MEDIUM | 4 | SHIELD-T11-003, SHIELD-T11-004, SHIELD-T11-005, SHIELD-T11-006 |
| LOW | 2 | SHIELD-T11-007, SHIELD-T11-008 |
| **Total** | **8** | |

---

## Cross-Domain Attack Chain 1: Dev Config → Production Deployment → Crypto Oracle

**Chain**: Docker dev config (A05) → No CI/CD enforcement (A10) → Verbose errors in production (A11) → Crypto oracle (T06)

### SHIELD-T11-001: No Production Configuration Mode — Dev Defaults Ship to Production

- **Tag**: VERIFIED
- **Severity**: HIGH
- **CWE**: CWE-489 (Active Debug Code) / CWE-1188 (Initialization with an Insecure Default)
- **Location**: `python/shield/integrations/fastapi.py:82-90`, `python/shield/integrations/flask.py:76-85`, `javascript/integrations/express.js:46-50`, `python/shield/integrations/confidential/middleware.py:89-99`
- **Evidence**:
```python
# FastAPI — default exclude routes include API documentation endpoints
self.exclude_routes = exclude_routes or ["/docs", "/redoc", "/openapi.json"]

# Flask — default exclude routes
self.exclude_routes = exclude_routes or ["/static", "/health", "/favicon.ico"]

# Confidential middleware — ALSO excludes docs/redoc
self.exclude_routes = exclude_routes or ["/docs", "/redoc", "/openapi.json", "/health"]
```

Cross-reference:
- **SHIELD-A05-016**: `uvicorn --reload` in docker-compose.yml — auto-reload mode for development
- **SHIELD-A11-005**: FastAPI `shield_protected` leaks raw decrypt exception to HTTP response
- **SHIELD-A11-006**: Express `shieldRequired` leaks `err.message` in HTTP response
- **SHIELD-A10-005**: No CI/CD step validates that release builds use production configuration

**Impact**: Shield middleware has ZERO concept of a "production mode". There is no environment variable, no configuration flag, and no detection mechanism to distinguish development from production deployment. This means:

1. **Error verbosity**: `f"Decryption failed: {e}"` (SHIELD-A11-005) is the ONLY error handling path — no "production" variant exists that strips details. Every deployment gets verbose crypto errors.
2. **Debug endpoints**: FastAPI `exclude_routes` defaults expose `/docs`, `/redoc`, `/openapi.json` — full API schema documentation is unprotected in production. The confidential computing middleware (TEE-protected!) also exposes docs.
3. **Auto-reload**: `docker-compose.yml:71` uses `--reload` with no conditional for production. If docker-compose is used in staging/CI, code changes trigger immediate hot-reload.
4. **No CI enforcement**: No CI/CD step (SHIELD-A10-005) checks configuration before publishing packages to PyPI/npm. Whatever defaults exist in the source code ship directly to users.

**Attack chain**: Attacker discovers Shield-protected API in production → `/docs` endpoint reveals full API schema including encrypted endpoints → sends crafted requests → verbose error messages (SHIELD-A11-005, A11-006) reveal crypto internals → enables crypto oracle probing (cross-ref SHIELD-T06-001, T06-002).

- **Reproduction**:
  1. `pip install shield-crypto` and deploy with FastAPI middleware using defaults
  2. Access `https://production-api.com/docs` — full Swagger UI visible
  3. Access `https://production-api.com/redoc` — full ReDoc visible
  4. Send malformed encrypted request → receive `"Decryption failed: MAC verification failed"` in response
  5. No configuration change needed — these are the defaults
- **Fix Complexity**: MEDIUM
- **Remediation**: Add `production_mode` parameter to all middleware constructors. In production mode: (1) exclude `/docs`, `/redoc`, `/openapi.json` automatically, (2) use generic error messages, (3) disable `--reload`. Add `SHIELD_ENVIRONMENT` environment variable detection. Document production configuration requirements prominently.

---

### SHIELD-T11-002: Replay Protection Disableable Without Warning — Silent Security Downgrade

- **Tag**: VERIFIED
- **Severity**: HIGH
- **CWE**: CWE-1188 (Initialization with an Insecure Default) / CWE-294 (Authentication Bypass by Capture-replay)
- **Location**: `python/shield/core.py:66,77,252`, `shield-core/src/shield.rs:168`, `javascript/src/shield.js:226`, `tests/test_cross_language_v2.py:106`
- **Evidence**:
```python
# core.py:66 — constructor
max_age_ms: Optional[int] = 60_000,

# core.py:77 — docstring
max_age_ms: Maximum message age in milliseconds for replay protection
            (default: 60000 = 60 seconds, None = disabled)

# core.py:252 — the disable gate
if self._max_age_ms is not None:
    # ... timestamp validation ...
    if timestamp_ms > now_ms + 5000 or age > self._max_age_ms:
        return None
```
```rust
// shield.rs:168
/// * `max_age_ms` - Maximum age in milliseconds, or None to disable replay protection
```
```python
# test_cross_language_v2.py:106 — test confirms disabling works
shield = Shield("test-password", "test.example.com", max_age_ms=None)
```

Cross-reference:
- **SHIELD-A10-005**: No CI/CD validation of security configuration before release
- **SHIELD-A10-034**: No SAST rules to detect weakened security configuration

**Impact**: Setting `max_age_ms=None` completely disables V2 replay protection — the timestamp validation at `core.py:252` is skipped entirely. This is:

1. **A one-parameter downgrade**: A single constructor argument silently disables a core security feature
2. **No warning emitted**: No log message, no deprecation warning, no "are you sure" — just silent disable
3. **No CI detection**: No SAST rule, no linter, no test prevents `max_age_ms=None` from shipping to production
4. **Documented and tested**: The feature is documented as a valid option (`None = disabled`) and has dedicated tests
5. **All implementations affected**: Rust, Python, JavaScript all support `None`/`null`/`Option::None`

A developer debugging a timing issue might set `max_age_ms=None`, forget to revert, and ship to production. No safety net catches this. All encrypted messages become replayable indefinitely. Combined with no audit logging of security configuration (SHIELD-A10-005), this downgrade is invisible.

- **Reproduction**:
  1. Create Shield instance: `Shield("password", "service", max_age_ms=None)`
  2. Encrypt a message, capture the ciphertext
  3. Wait arbitrarily long (days, months)
  4. Decrypt the same ciphertext — succeeds (no replay rejection)
  5. No warning in logs, no error, no indication that security feature is disabled
- **Fix Complexity**: LOW
- **Remediation**: Emit a warning when `max_age_ms=None` is used: `warnings.warn("Replay protection disabled. Not recommended for production.", SecurityWarning)`. Add minimum value validation: `if max_age_ms is not None and max_age_ms < 1000: raise ValueError("max_age_ms must be >= 1000ms")`. Add SAST rule to flag `max_age_ms=None` in non-test code.

---

## Cross-Domain Attack Chain 2: Docker Dev → Volume Mount → Source Tampering

### SHIELD-T11-003: Docker-Compose Config Ships as Development-Only with No Production Alternative

- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-489 (Active Debug Code)
- **Location**: `docker-compose.yml:1-76` (entire file)
- **Evidence**:
```yaml
# docker-compose.yml — labeled as development
# Shield - Docker Compose for Development and Testing

# BUT: No docker-compose.production.yml exists
# AND: No .env file templates for dev vs prod
# AND: No docker-compose.override.yml for dev-specific overrides
```

Cross-reference:
- **SHIELD-A05-001**: Containers run as root
- **SHIELD-A05-003**: Dev toolchains in image (build-essential, git, npm, pip, gradle)
- **SHIELD-A05-015**: Entire repo mounted read-write
- **SHIELD-A05-016**: `uvicorn --host 0.0.0.0 --reload`
- **SHIELD-A05-009**: No resource limits
- **SHIELD-A05-010**: No security hardening (cap_drop, read_only, no-new-privileges)
- **SHIELD-A05-014**: No network segmentation

**Impact**: The project provides a SINGLE `docker-compose.yml` file labeled "Development and Testing" with every convenience pattern enabled (root, full toolchains, RW mounts, reload mode, no resource limits, no network isolation). There is no:
- `docker-compose.production.yml` — production-hardened override
- `.env.production` — production environment template
- Documentation on "how to deploy for production"
- CI/CD step that generates a production config

When users deploy Shield's Docker setup in staging or CI environments, they get the full development configuration with all its vulnerabilities. The `fastapi-example` service binds to `0.0.0.0:8000` with `--reload` and runtime `pip install` — if used as a reference for production deployment, it creates immediate exposure.

**Chain**: Developer copies `docker-compose.yml` to staging → root + RW mount + --reload + 0.0.0.0 → attacker on network accesses port 8000 → modifies mounted source via RW volume → uvicorn auto-reloads → arbitrary code execution as root in container.

- **Reproduction**:
  1. `docker compose up fastapi-example` on a server with network access
  2. From another machine: `curl http://<server>:8000/docs` — accessible
  3. If volume mount exists: modify `examples/fastapi/main.py` → auto-reload executes changes as root
- **Fix Complexity**: LOW
- **Remediation**: Create `docker-compose.production.yml` with hardened defaults (non-root, read-only FS, no volumes, no reload, localhost-only ports, resource limits, network segmentation). Add `Makefile` targets: `make dev` vs `make production`. Document the distinction in README.

---

## Cross-Domain Attack Chain 3: Error Verbosity → No Mode Switch → Persistent Info Leak

### SHIELD-T11-004: Error Messages Cannot Be Configured — No Verbosity Control

- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-209 (Generation of Error Message Containing Sensitive Information) / CWE-1188
- **Location**: `python/shield/integrations/fastapi.py:174`, `python/shield/integrations/flask.py:112-118`, `javascript/integrations/express.js:142-144,163-169`, `python/shield/integrations/confidential/middleware.py:132-138`
- **Evidence**:
```python
# FastAPI — ONLY error handling path (no production mode)
except (json.JSONDecodeError, KeyError, ValueError) as e:
    raise HTTPException(status_code=400, detail=f"Decryption failed: {e}")
```
```javascript
// Express — ONLY error handling path
} catch (err) {
    return res.status(400).json({
        error: `Decryption failed: ${err.message}`
    });
}
```
```python
# Confidential middleware — ONLY path
except Exception as e:
    return JSONResponse(status_code=401, content={"error": "attestation_failed", "message": str(e)})
```

Cross-reference:
- **SHIELD-A11-005**: FastAPI leaks raw Python exceptions (HIGH)
- **SHIELD-A11-006**: Express leaks err.message (HIGH)
- **SHIELD-A11-007**: Express shieldErrorHandler also leaks (MEDIUM)
- **SHIELD-A11-008**: Confidential middleware leaks exception details (MEDIUM)
- **SHIELD-T06-001**: These errors create binary oracle for crypto probing (HIGH)

**Impact**: Every web integration middleware has a SINGLE error handling code path — the verbose one. There is:
- No `debug` parameter to toggle error verbosity
- No `SHIELD_DEBUG` environment variable check
- No `app.debug` / `app.config['DEBUG']` integration (Flask has this, Shield ignores it)
- No production error handler wrapper option

This is a **permanent information disclosure by design**. Unlike typical applications where debug mode is a configuration choice, Shield middleware ALWAYS returns detailed crypto error messages. Users cannot opt out without modifying the Shield package source code. Combined with the crypto oracle findings (SHIELD-T06-001, T06-002), this means every Shield deployment is an information-leaking crypto oracle by default, with no knob to turn it off.

- **Reproduction**:
  1. Deploy any Flask/FastAPI/Express app with Shield middleware
  2. Set `FLASK_DEBUG=0` or equivalent production mode
  3. Send malformed encrypted request
  4. Observe: Shield still returns `f"Decryption failed: {e}"` — ignores Flask's debug setting
- **Fix Complexity**: MEDIUM
- **Remediation**: Add `verbose_errors: bool = False` to all middleware constructors. In non-verbose mode, return generic messages only. Integrate with framework debug settings: `verbose_errors = verbose_errors or app.debug`. Document that production deployments should set `verbose_errors=False`.

---

## Cross-Domain Attack Chain 4: Default Excluded Routes → API Schema Exposure → Targeted Attack

### SHIELD-T11-005: FastAPI and TEE Middleware Default-Exclude Swagger Docs from Encryption

- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-16 (Configuration) / CWE-200 (Exposure of Sensitive Information)
- **Location**: `python/shield/integrations/fastapi.py:90`, `python/shield/integrations/confidential/middleware.py:99`
- **Evidence**:
```python
# FastAPI ShieldMiddleware — docs excluded by default
self.exclude_routes = exclude_routes or ["/docs", "/redoc", "/openapi.json"]

# Confidential Computing AttestationMiddleware — ALSO excludes docs
self.exclude_routes = exclude_routes or ["/docs", "/redoc", "/openapi.json", "/health"]
```

Cross-reference:
- **SHIELD-A06-013**: Route exclusion bypass via path encoding (MEDIUM)
- **SHIELD-A06-014**: Express path matching bypass (MEDIUM)

**Impact**: By default, FastAPI's Swagger UI (`/docs`), ReDoc (`/redoc`), and OpenAPI JSON schema (`/openapi.json`) are excluded from both encryption middleware AND attestation middleware. This means:

1. **API reconnaissance**: An attacker accessing any Shield-protected FastAPI app sees the complete API schema — all endpoints, parameters, request/response models, authentication requirements — without any encryption or attestation.
2. **TEE bypass for schema**: Even in confidential computing deployments where attestation is required, `/docs` and `/redoc` are excluded by default. The API schema of TEE-protected endpoints is visible to unauthenticated, unattested clients.
3. **Information for targeted attacks**: Full schema enables crafting precise malformed requests to trigger specific error paths (feeding into SHIELD-T06 crypto oracle chain).

This is particularly dangerous because FastAPI auto-generates OpenAPI schemas that include request body models — revealing exactly what encrypted payload format is expected.

- **Reproduction**:
  1. Deploy FastAPI app with `ShieldMiddleware(app, password="secret", service="api")`
  2. Access `/openapi.json` — complete API schema in plaintext
  3. Schema reveals: endpoint paths, required encrypted fields, response models
  4. Use schema to craft precise payloads for crypto oracle probing
- **Fix Complexity**: LOW
- **Remediation**: Change default `exclude_routes` to empty list `[]` or `["/health"]` only. Add `include_docs: bool = False` parameter that, when True, adds docs routes. For confidential middleware, docs should NEVER be excluded by default — attestation should be required for everything. Document that exposing API schema is a deliberate opt-in.

---

### SHIELD-T11-006: Example Code Contains Hardcoded Credentials That Users Copy to Production

- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-798 (Use of Hard-coded Credentials) / CWE-1188
- **Location**: `examples/browser-integration/server.py:41`, `examples/confidential-computing/aws-nitro/fastapi_enclave.py:57`, `examples/confidential-computing/gcp-sev/fastapi_confidential.py:72`, `examples/confidential-computing/azure-acc/fastapi_confidential.py:71`, `examples/confidential-computing/intel-sgx/fastapi_enclave.py:70`, `python/shield/integrations/pgvector_api.py:218`
- **Evidence**:
```python
# browser-integration/server.py:41
PASSWORD = "demo-secret-password"

# aws-nitro/fastapi_enclave.py:57
password="your-secure-password",  # In production, get from KMS after attestation

# gcp-sev/fastapi_confidential.py:72
password="bootstrap-password",  # Will be replaced with secret from Secret Manager

# azure-acc/fastapi_confidential.py:71
password="bootstrap-password",

# pgvector_api.py:218 — ALSO contains production-unsafe code
"plaintext": request.vector,  # For testing (remove in production)
```

Cross-reference:
- **SHIELD-A05-027**: Documentation encourages `export SHIELD_PASSWORD="my-secure-password-123"` (LOW)
- **SHIELD-A06-018**: Flask decorators encourage hardcoded passwords in source (MEDIUM)
- **SHIELD-A10-005**: No CI/CD scanning for hardcoded credentials in example code

**Impact**: Seven separate example files contain hardcoded passwords. The comments say "In production, use KMS/Secret Manager" but:

1. **Copy-paste culture**: Developers routinely copy example code as starting points. The hardcoded password is the path of least resistance.
2. **"Bootstrap" passwords**: Multiple confidential computing examples use `"bootstrap-password"` — a placeholder that sounds intentionally temporary but has no enforcement mechanism to replace it.
3. **Testing code in production paths**: `pgvector_api.py:218` stores plaintext vectors alongside encrypted ones "for testing" — this is in the integration module that ships to PyPI, not in a test file.
4. **No git-secrets/trufflehog coverage**: While `trufflehog` is in CI (SHIELD-A10-020), it scans the repo — but example passwords are intentional, so they wouldn't be flagged. The risk is users copying them.

**Chain**: User copies confidential computing example → deploys with `password="bootstrap-password"` → TEE attestation works but encryption uses trivially guessable password → all "encrypted" data is trivially decryptable.

- **Reproduction**:
  1. Copy `examples/confidential-computing/aws-nitro/fastapi_enclave.py` to production
  2. Deploy without changing `password="your-secure-password"`
  3. Attacker: `Shield("your-secure-password", "your-service").decrypt(ciphertext)` — trivially decrypts
- **Fix Complexity**: LOW
- **Remediation**: Replace all hardcoded passwords in examples with environment variable reads: `password=os.environ["SHIELD_PASSWORD"]`. Add startup check: `if password in ["bootstrap-password", "your-secure-password", "demo-secret-password"]: raise ValueError("Replace placeholder password")`. Remove `"plaintext"` field from pgvector_api.py.

---

## Cross-Domain Attack Chain 5: CI/CD Publishes Without Config Validation

### SHIELD-T11-007: Zero CI/CD Gates for Security Configuration — Packages Ship with Any Defaults

- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-1068 (Inconsistency Between Implementation and Documented Design)
- **Location**: `.github/workflows/ci.yml` (entire file), `.github/workflows/release.yml` (entire file)
- **Evidence**:
```yaml
# ci.yml — tests run but NO configuration validation:
# - No check for hardcoded credentials in source
# - No check that exclude_routes defaults are production-safe
# - No check that error messages are generic
# - No check that max_age_ms != None in non-test code
# - No SAST rules for security configuration

# release.yml — publishes to registries with ZERO security validation:
# - cargo publish (crates.io)
# - twine upload (PyPI)
# - npm publish (npm)
# All triggered by git tag, no security review gate
```

Cross-reference:
- **SHIELD-A10-001**: All GitHub Actions pinned by tag, not SHA (HIGH)
- **SHIELD-A10-005**: No release signing or provenance (MEDIUM)
- **SHIELD-A10-034**: No SAST tooling beyond Clippy (LOW)

**Impact**: The CI/CD pipeline runs tests and publishes packages but performs ZERO security configuration validation. This means:

1. A PR that changes `max_age_ms` default from `60_000` to `None` would pass CI and merge
2. A PR that changes error messages from generic to verbose would pass CI and merge
3. A PR that adds `"*"` to default CORS origins would pass CI and merge
4. Published packages (on PyPI, npm, crates.io) carry whatever defaults the code has — no security gate

Combined with SHIELD-A10-001 (Actions pinned by tag), a compromised GitHub Action could modify security defaults during the build, and the release pipeline would publish the tampered package without detection.

- **Reproduction**:
  1. Create PR changing `self.exclude_routes` default to `[]` (or add `/admin` to exclude list)
  2. CI passes — no test covers default configuration security
  3. Merge + tag → published to PyPI/npm/crates.io with altered defaults
- **Fix Complexity**: MEDIUM
- **Remediation**: Add CI step that validates security-critical defaults:
  ```bash
  # Verify no hardcoded passwords outside test/example dirs
  grep -rn 'password.*=.*"' python/shield/ --include='*.py' | grep -v test | grep -v example
  # Verify error messages don't contain format strings in non-test code
  grep -rn 'f".*{e}"' python/shield/integrations/ --include='*.py'
  # Verify max_age_ms default is not None
  grep -n 'max_age_ms.*None' python/shield/core.py | grep -v 'Optional\|if.*None'
  ```

---

### SHIELD-T11-008: Dev-Only Test Helpers and Plaintext APIs Ship in Production Packages

- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-489 (Active Debug Code)
- **Location**: `python/shield/integrations/pgvector_api.py:218`, `python/shield/integrations/fido2_api.py:92,159,250`
- **Evidence**:
```python
# pgvector_api.py:218 — plaintext stored alongside encrypted
"plaintext": request.vector,  # For testing (remove in production)

# pgvector_api.py:268 — plaintext used instead of decryption
decrypted = vector_data["plaintext"]  # In production, decrypt from encrypted

# fido2_api.py:92
# In-memory storage (production should use Redis)

# fido2_api.py:159
# In production, verify attestation object and signature

# fido2_api.py:250
# In production: verify signature with public key
```

Cross-reference:
- **SHIELD-A10-005**: No CI gate to prevent test code in production packages

**Impact**: Two integration modules (`pgvector_api.py`, `fido2_api.py`) contain development-only code paths that ship in the `shield-crypto` PyPI package:

1. **pgvector_api**: Stores vectors in plaintext ("for testing") and reads them back without decryption. If a developer imports this module in production, vectors are stored unencrypted.
2. **fido2_api**: Skips attestation verification and signature validation. Comments say "In production" but the code as shipped IS the version that reaches production via `pip install shield-crypto`.

These are not example files — they are in `python/shield/integrations/` which is part of the published package.

- **Reproduction**:
  1. `pip install shield-crypto`
  2. `from shield.integrations.pgvector_api import PgVectorAPI`
  3. Store a vector → plaintext stored in memory alongside encrypted version
  4. The "remove in production" code IS the production code
- **Fix Complexity**: LOW
- **Remediation**: Either: (a) Remove test-only code paths and use proper implementations, or (b) Move these modules to a `shield.integrations.dev` subpackage not included in the published wheel, or (c) Add runtime check: `if "plaintext" in vector_data: warnings.warn("Development mode: plaintext vectors stored. Not for production.", SecurityWarning)`.

---

## Consolidated Drift Matrix

| Drift Dimension | Dev Setting | Production Default | Safety Net | Gap |
|----------------|-------------|-------------------|------------|-----|
| Error verbosity | `f"Decryption failed: {e}"` | Same (no prod mode) | None | **SHIELD-T11-004** |
| API docs exposure | `/docs`, `/redoc` excluded | Same (excluded by default) | None | **SHIELD-T11-005** |
| Replay protection | `max_age_ms=60000` | `max_age_ms=None` possible | None | **SHIELD-T11-002** |
| Docker privileges | Root, RW volumes, --reload | Same (single compose file) | None | **SHIELD-T11-003** |
| Hardcoded passwords | `"demo-secret-password"` | Copied as-is | None | **SHIELD-T11-006** |
| CI/CD security gate | None | None | None | **SHIELD-T11-007** |
| Test code in packages | In-memory, plaintext | Ships to PyPI | None | **SHIELD-T11-008** |
| Production mode | Does not exist | N/A | N/A | **SHIELD-T11-001** |

**Key insight**: The word "production" appears 18 times across Shield's codebase — always in comments saying "In production, do X" or "remove in production". There is zero code that implements a production mode. Every configuration is either development-only or the same for both environments. There is no safety net at any layer (code, CI/CD, deployment, documentation) to prevent development configuration from reaching production.

---

## Cross-Domain References

| T11 Finding | Root Agent Findings | Escalation |
|-------------|--------------------|-----------:|
| SHIELD-T11-001 | SHIELD-A05-016, SHIELD-A11-005, SHIELD-A11-006, SHIELD-A10-005 | New chain: dev defaults → crypto oracle |
| SHIELD-T11-002 | SHIELD-A10-005, SHIELD-A10-034 | Elevated from LOW (feature) to HIGH (silent security downgrade) |
| SHIELD-T11-003 | SHIELD-A05-001, A05-003, A05-009, A05-010, A05-014, A05-015, A05-016 | Combines 7 findings into exploitable chain |
| SHIELD-T11-004 | SHIELD-A11-005, A11-006, A11-007, A11-008, SHIELD-T06-001, T06-002 | Escalates A11 findings: not just bugs, systemic by design |
| SHIELD-T11-005 | SHIELD-A06-013, SHIELD-A06-014 | New finding: default excludes create reconnaissance surface |
| SHIELD-T11-006 | SHIELD-A05-027, SHIELD-A06-018, SHIELD-A10-005 | Combines: hardcoded creds + no CI detection |
| SHIELD-T11-007 | SHIELD-A10-001, SHIELD-A10-005, SHIELD-A10-034 | New chain: CI gaps → config drift ships |
| SHIELD-T11-008 | SHIELD-A10-005 | New finding: test code in production packages |

---

## Verdict

**Config drift severity**: HIGH — Shield has no production configuration mode at any layer. Development defaults are production defaults. There is no safety net (CI/CD gates, runtime warnings, documentation) to prevent insecure development patterns from reaching production. The combination of verbose errors, exposed API schemas, disableable replay protection, and hardcoded example credentials creates a systemic risk where every Shield deployment starts in an insecure state by default.

**Recommended priority**: Fix SHIELD-T11-001 (production mode) and SHIELD-T11-002 (replay protection warning) before launch. These are foundational — without them, all other hardening is opt-in with no defaults.
