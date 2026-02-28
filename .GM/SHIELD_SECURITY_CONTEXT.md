# SHIELD SECURITY CONTEXT MAP

**Generated**: 2026-02-28
**Scope**: Full codebase reconnaissance (Phase 0)
**Method**: Static analysis of 167+ source files across 12 language implementations
**Purpose**: Foundation for enterprise security assessment

---

## 1. EXECUTIVE SUMMARY

Shield is a **symmetric-only EXPTIME-secure encryption library** implemented in 12 languages (Rust, Python, JavaScript, Go, C, Java, C#, Swift, Kotlin, Android, iOS, WebAssembly) with a Browser SDK. Architecture is a **single-crate Rust core** (`shield-core`) plus independent reimplementations in each language producing byte-identical ciphertext. The project ships as:

- **CLI tool** (multi-platform binaries via GitHub Releases)
- **Library packages** (crates.io, PyPI, npm, Go modules, NuGet, CocoaPods, Gradle)
- **WASM module** (browser-side decryption)
- **Web framework middleware** (FastAPI, Flask, Django, Express)
- **Mobile SDKs** (Android Keystore, iOS Keychain/Secure Enclave)

**Deployment model**: Library consumed by applications. No standalone server/service. Docker exists only for development/testing. CI/CD via GitHub Actions publishes to 4 registries (crates.io, PyPI, npm, GitHub Releases).

**Crypto stack**: PBKDF2-SHA256 (100k iterations) → SHA256-CTR stream cipher → HMAC-SHA256 (128-bit truncated). Zero asymmetric cryptography. Zero external crypto dependencies in most languages.

**Audit status**: Internal review only. No external third-party audit completed. Budget allocated ($33-52k) but not executed.

---

## 2. TECHNOLOGY INVENTORY

### Languages & Versions

| SDK | Language | Runtime/SDK | Build System | External Crypto Deps |
|-----|----------|-------------|--------------|---------------------|
| shield-core | Rust 2021 | stable/beta | Cargo | `ring` 0.17, `subtle` 2.5, `zeroize` 1.7 |
| python | Python 3.8-3.12 | CPython | pyproject.toml | **None** (stdlib only) |
| javascript | JavaScript | Node.js 16-20 | npm | **None** (stdlib `crypto`) |
| browser | Rust+TypeScript | WASM+Rollup | Cargo+npm | shield-core (WASM) |
| go | Go 1.24 | stdlib | go mod | `golang.org/x/crypto` v0.47.0 (PBKDF2 only) |
| c | C (C99) | GCC | Makefile | **None** (inline SHA256/HMAC) |
| java | Java 11-21 | JDK | Gradle | **None** (javax.crypto) |
| csharp | C# | .NET 6-8 | dotnet | **None** (System.Security.Cryptography) |
| swift | Swift 5.7+ | Foundation | SPM | **None** (CommonCrypto) |
| kotlin | Kotlin 1.9 | JVM 11 | Gradle | **None** (javax.crypto) |
| android | Kotlin 2.1 | API 23+ | Gradle | `androidx.security:security-crypto:1.1.0-alpha06` |
| ios | Swift 5.7+ | iOS 13+ | SPM/CocoaPods | **None** (CommonCrypto + Security.framework) |

### Infrastructure

| Component | Technology | Version |
|-----------|-----------|---------|
| CI/CD | GitHub Actions | v4 actions |
| Container | Docker (ubuntu:22.04) | Compose 3.8 |
| Secret scanning | TruffleHog | @main |
| Dependency audit | cargo-audit | latest |
| Coverage | cargo-llvm-cov + pytest-cov | Codecov |
| Linting | Clippy (-D warnings), cargo fmt | stable |
| Release | Multi-platform binaries (5 targets) | softprops/action-gh-release |

### Feature Flags (Rust)

| Feature | Adds | Network I/O | Default |
|---------|------|-------------|---------|
| `std` | Standard library | No | Yes |
| `cli` | CLI binary (rpassword, getrandom) | No | Yes |
| `wasm` | WASM bindings | No | No |
| `async` | tokio + reqwest | Yes | No |
| `confidential` | TEE attestation (ciborium, async-trait) | Yes | No |
| `openapi` | API schema generation (utoipa) | No | No |
| `fido2` | WebAuthn (webauthn-rs) | No | No |
| `pgvector` | Postgres vectors (tokio-postgres) | Yes | No |

---

## 3. ARCHITECTURE MAP

### Encryption Flow (All Implementations)

```
Password + Service
       ↓
  salt = SHA256("shield:" + service)
       ↓
  master_key = PBKDF2-SHA256(password, salt, 100_000 iterations, 32 bytes)
       ↓
  encryption_key = master_key[0:32]
  mac_key = SHA256(master_key || "mac")
       ↓
  nonce = random(16 bytes)
       ↓
  [V2] inner = counter(8) || timestamp_ms(8) || pad_len(1) || random_padding(32-128) || plaintext
       ↓
  keystream = SHA256-CTR(encryption_key, nonce)   // SHA256(key || nonce || counter++) per block
  ciphertext = inner XOR keystream
       ↓
  mac = HMAC-SHA256(mac_key, nonce || ciphertext)[0:16]
       ↓
  output = nonce(16) || ciphertext || mac(16)
```

### Module Architecture (per implementation)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          SHIELD CORE                                     │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌─────────────────────┐   │
│  │  Shield   │  │ StreamCipher│ │ RatchetSession│ │ ShieldChannel      │   │
│  │ encrypt() │  │ chunk enc  │  │ forward sec│  │ PAKE+Ratchet TLS  │   │
│  │ decrypt() │  │ per-chunk  │  │ key ratchet│  │ sync + async      │   │
│  └──────────┘  │ auth       │  └──────────┘  └─────────────────────┘   │
│                 └───────────┘                                            │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌─────────────────────┐   │
│  │  TOTP     │  │ Signatures │  │ Exchange  │  │ Group/Broadcast    │   │
│  │ RFC 6238  │  │ HMAC+Lamport│ │ PAKE+QR   │  │ Multi-recipient   │   │
│  │ Recovery  │  │ post-quantum│ │ KeySplit  │  │ Subgroup encrypt  │   │
│  └──────────┘  └───────────┘  └──────────┘  └─────────────────────┘   │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌─────────────────────┐   │
│  │ Identity  │  │ Rotation   │  │ Fingerprint│ │ Password Checker   │   │
│  │ SSO/tokens│  │ versioned  │  │ device bind│ │ entropy calc      │   │
│  │ sessions  │  │ zero-down  │  │ HW binding │ │ strength rating   │   │
│  └──────────┘  └───────────┘  └──────────┘  └─────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                     WEB INTEGRATIONS (Python)                            │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌─────────────────────┐   │
│  │ FastAPI   │  │ Flask      │  │ Django    │  │ Express (JS)       │   │
│  │ Middleware│  │ Extension  │  │ Middleware│  │ Middleware          │   │
│  │ Auth deps │  │ Decorators │  │ Sessions  │  │ Route protection   │   │
│  └──────────┘  └───────────┘  └──────────┘  └─────────────────────┘   │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐                            │
│  │ Browser   │  │ Protection │  │ Cookies   │                            │
│  │ Bridge    │  │ RateLimiter│  │ Encrypted │                            │
│  │ Key exch  │  │ TokenBucket│  │ SameSite  │                            │
│  └──────────┘  └───────────┘  └──────────┘                            │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                 CONFIDENTIAL COMPUTING (Rust + Python)                    │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌─────────────────────┐   │
│  │ AWS Nitro │  │ GCP SEV    │  │ Azure MAA │  │ Intel SGX          │   │
│  │ COSE/PCR  │  │ AMD SEV-SNP│  │ JWT/AKV   │  │ DCAP/Sealed       │   │
│  │ Vsock     │  │ vTPM       │  │ Sidecar   │  │ Gramine           │   │
│  └──────────┘  └───────────┘  └──────────┘  └─────────────────────┘   │
│  TEEKeyManager: Attestation-gated key release with policy enforcement   │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                      BROWSER SDK (WASM)                                  │
│  ShieldBrowser.init(keyEndpoint) → fetch key → store in WASM memory     │
│  Monkey-patch window.fetch() → detect {encrypted:true,data:"..."} →    │
│  WASM quick_decrypt() → return plaintext response to application        │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                        MOBILE SDKs                                       │
│  Android: Shield + SecureKeyStore (Keystore/TEE/StrongBox) + Biometric  │
│  iOS: Shield + SecureKeychain (Keychain/Secure Enclave) + FaceID/Touch  │
└─────────────────────────────────────────────────────────────────────────┘
```

### Trust Boundaries

```
UNTRUSTED                          TRUST BOUNDARY                    TRUSTED
─────────────────────────────────┬──────────────────────────────────────────
User input (password, plaintext) │ → PBKDF2 key derivation         Key material
Network traffic (ciphertext)     │ → HMAC verification             Decrypted data
Browser fetch responses          │ → WASM decrypt envelope         Plaintext JSON
API request bodies               │ → Middleware decrypt            Application data
Cookie values                    │ → EncryptedCookie decode        Session data
Token strings                    │ → HMAC verify + JSON parse      Identity claims
Attestation evidence             │ → Provider verify               TEE measurements
Hardware fingerprint             │ → OS system calls               Device identity
```

---

## 4. ATTACK SURFACE CATALOG

### Entry Points

| Entry Point | Type | Languages | Auth Required | Input Vectors |
|-------------|------|-----------|---------------|---------------|
| `Shield.encrypt()` | Library API | All 12 | Password/Key | plaintext bytes, password string, service string |
| `Shield.decrypt()` | Library API | All 12 | Password/Key | ciphertext bytes (nonce+ct+mac) |
| `quick_encrypt/decrypt()` | Library API | All 12 | Pre-shared key [u8;32] | plaintext/ciphertext bytes |
| `shield encrypt <file>` | CLI | Rust | Password prompt | file path, password, service, output path |
| `shield decrypt <file>` | CLI | Rust | Password prompt | file path, password, output path |
| `shield check <pass>` | CLI | Rust | None | password string (command-line arg) |
| `shield keygen` | CLI | Rust | None | None |
| `shield text` | CLI | Rust | Password | text string, password, service |
| `ShieldMiddleware` | HTTP Middleware | Python (FastAPI/Flask/Django) | Configurable | HTTP request/response bodies |
| `shieldMiddleware` | HTTP Middleware | JavaScript (Express) | Configurable | HTTP request/response bodies |
| `shield_protected()` | Decorator | Python | Token/API key | Endpoint-specific |
| `shield_required()` | Decorator | Python | Encrypted body | Request body |
| `ShieldTokenAuth` | Dependency | Python (FastAPI) | Bearer token | Authorization header |
| `ShieldAPIKeyAuth` | Dependency | Python (FastAPI) | API key header | X-API-Key header |
| `BrowserBridge.generate_client_key()` | HTTP endpoint | Python | Session cookie | session_id, TTL |
| `ShieldBrowser.init(endpoint)` | Browser API | TypeScript/WASM | same-origin | key endpoint URL |
| `fetch()` interceptor | Browser hook | TypeScript | Auto (key valid) | All fetch responses |
| `ShieldChannel` | TCP socket | Rust/Python/JS/Go | PAKE password | Raw TCP stream |
| `AsyncShieldChannel` | TCP socket | Rust (tokio) | PAKE password | Raw TCP stream |
| `PAKEExchange` | Protocol | All | Shared password | Contributions (32 bytes) |
| `IdentityProvider.register()` | Library API | All | None (registration) | user_id, password, display_name |
| `IdentityProvider.authenticate()` | Library API | All | Password | user_id, password |
| `IdentityProvider.validate_token()` | Library API | All | Token string | Base64-encoded token |
| `TOTP.verify()` | Library API | All | Secret | 6-8 digit code |
| `Fido2Manager` | Library API | Rust | Challenge/Response | WebAuthn attestation |
| `SecureKeyStore` (Android) | System API | Kotlin | Optional biometric | Key alias |
| `SecureKeychain` (iOS) | System API | Swift | Optional biometric | Key alias |
| `AttestationMiddleware` | HTTP Middleware | Python/Rust | TEE attestation | Evidence bytes, PCR values |
| `collect_fingerprint()` | System API | All | OS access | Platform-specific system calls |

### Input Validation Summary

| Input | Validation | Gap |
|-------|-----------|-----|
| Password | `check_password()` entropy calculator (advisory only) | Not enforced on encrypt |
| Ciphertext | Length check (min 40 bytes), HMAC verification | None identified |
| Nonce | Fixed 16 bytes, extracted from ciphertext | None |
| MAC | 16-byte constant-time comparison | None |
| Pad length (v2) | Range check 32-128 after decryption | CVE-PENDING (see below) |
| Timestamp (v2) | Range 2020-2100, age check vs max_age_ms | 5s future clock skew |
| Token strings | Base64 decode + JSON parse + HMAC verify | None identified |
| File paths (CLI) | Standard OS file I/O | No path traversal protection |
| Session IDs | String, used as HMAC key derivation input | No format validation |
| API keys | Encrypted comparison | None identified |

---

## 5. DEPENDENCY MANIFEST

### Rust Core (shield-core/Cargo.toml)

| Dependency | Version | Purpose | Always Loaded |
|------------|---------|---------|---------------|
| ring | 0.17 | PBKDF2, HMAC, SHA256, SystemRandom | Yes |
| zeroize | 1.7 | Secure memory wipe (derive macros) | Yes |
| subtle | 2.5 | Constant-time comparison | Yes |
| thiserror | 1.0 | Error enum macros | Yes |
| serde + serde_json | 1.0 | JSON serialization | Yes |
| base64 | 0.21 | Base64 encoding | Yes |
| hex | 0.4 | Hex encoding | Yes |
| md5 | 0.7 | Hardware fingerprinting hash | Yes |
| rpassword | 7.3 | CLI password prompt | cli feature |
| getrandom | 0.2 | System RNG | cli/wasm feature |
| tokio | 1.0 | Async runtime | async feature |
| reqwest | 0.11 | HTTP client | async feature |
| ciborium | 0.2 | CBOR encoding | confidential feature |
| async-trait | 0.1 | Async trait support | confidential feature |
| webauthn-rs | 0.4 | FIDO2/WebAuthn | fido2 feature |
| tokio-postgres | 0.7 | PostgreSQL driver | pgvector feature |
| utoipa | 4.2 | OpenAPI schemas | openapi feature |
| wasm-bindgen | 0.2 | WASM JavaScript FFI | wasm feature |
| js-sys + web-sys | 0.3 | Browser API bindings | wasm feature |

### Python (pyproject.toml)

| Dependency | Version | Purpose |
|------------|---------|---------|
| **None** | - | Pure Python, stdlib only |
| pytest | >= 7.0 | Dev dependency |
| pytest-cov | >= 4.0 | Dev dependency |

### JavaScript (package.json)

| Dependency | Version | Purpose |
|------------|---------|---------|
| **None** | - | Node.js `crypto` module only |

### Go (go.mod)

| Dependency | Version | Purpose |
|------------|---------|---------|
| golang.org/x/crypto | v0.47.0 | PBKDF2 (stdlib for everything else) |

### Android (build.gradle.kts)

| Dependency | Version | Purpose |
|------------|---------|---------|
| androidx.security:security-crypto | 1.1.0-alpha06 | EncryptedSharedPreferences |
| androidx.core:core-ktx | 1.12.0 | Kotlin extensions |

### Browser SDK (package.json + Cargo.toml)

| Dependency | Version | Purpose |
|------------|---------|---------|
| shield-core | path | Core crypto (Rust→WASM) |
| wasm-bindgen | 0.2 | JS↔WASM bridge |
| web-sys | 0.3 | Browser APIs |
| getrandom | 0.2 (js) | WASM-compatible RNG |

### All Other Languages (C, Java, C#, Swift, Kotlin)

**Zero external dependencies.** All use platform-provided crypto primitives.

---

## 6. SECURITY MECHANISM INVENTORY

### Cryptographic Parameters

| Parameter | Value | Standard |
|-----------|-------|----------|
| Key derivation | PBKDF2-SHA256 | RFC 8018 |
| KDF iterations (core) | 100,000 | OWASP minimum |
| KDF iterations (PAKE) | 200,000 | Higher for exchange |
| Key size | 256 bits (32 bytes) | NIST approved |
| Encryption | SHA256-CTR (custom) | SHA256 = FIPS 180-4 |
| Authentication | HMAC-SHA256 | RFC 2104 |
| MAC output | 128 bits (truncated) | Adequate for auth |
| Nonce | 128 bits (random per message) | Probabilistic uniqueness |
| TOTP | HMAC-SHA1 (RFC required) | RFC 6238 |
| Lamport signatures | 256-bit chains | Post-quantum safe |

### Memory Protection

| Language | Mechanism | Automatic |
|----------|-----------|-----------|
| Rust | `Zeroize + ZeroizeOnDrop` on Shield, RatchetSession, SymmetricSignature, TOTP | Yes |
| Rust | `#![forbid(unsafe_code)]` in lib.rs | Compile-time |
| Python | No explicit zeroization (GC dependent) | No |
| JavaScript | No explicit zeroization (V8 GC) | No |
| Go | No explicit zeroization (Go GC) | No |
| C | `memset(0)` caller responsibility | Manual |
| Java | `Arrays.fill(key, (byte)0)` caller responsibility | Manual |
| Android | `Arrays.fill(0)` + Keystore hardware | Partial |
| iOS | Keychain + Secure Enclave hardware | Partial |

### Timing Attack Protection

| Implementation | MAC Comparison Method |
|----------------|---------------------|
| Rust | `subtle::ConstantTimeEq` (16 sites) |
| Python | `hmac.compare_digest()` |
| JavaScript | `crypto.timingSafeEqual()` |
| Go | `crypto/subtle.ConstantTimeCompare()` |
| C | Loop-based XOR accumulation (custom) |
| Java | Loop-based OR accumulation (custom) |
| C# | Loop-based XOR accumulation (custom) |
| Swift | Bitwise OR accumulation (custom) |
| Kotlin | Same as Java |

### Rate Limiting (Python integrations)

| Mechanism | Location | Details |
|-----------|----------|---------|
| RateLimiter | integrations/protection.py | Per-user/IP, encrypted counters |
| TokenBucket | integrations/protection.py | Configurable refill rate |
| APIProtector | integrations/protection.py | Combined: rate limit + IP filter + audit log |

### Authentication Mechanisms

| Mechanism | Location | Details |
|-----------|----------|---------|
| ShieldTokenAuth | Python FastAPI | Bearer token, HMAC-verified, TTL-enforced |
| ShieldAPIKeyAuth | Python FastAPI | Header-based, encrypted key comparison |
| FlaskAPIKeyAuth | Python Flask | Same as above for Flask |
| IdentityProvider | All languages | PBKDF2-derived user keys, session tokens |
| TOTP | All languages | RFC 6238, ±1 interval window |
| RecoveryCodes | All languages | 10 one-time codes, 8 hex chars each |
| FIDO2/WebAuthn | Rust (fido2 feature) | Challenge-response, encrypted credential store |
| BrowserBridge | Python + Browser SDK | Session-derived keys, TTL-based |
| EncryptedCookie | Python | Shield-encrypted, HttpOnly, SameSite=Strict |
| SecureCORS | Python | HMAC-signed origin verification |
| TEE Attestation | Rust + Python | Hardware-based identity verification |

### Replay Protection

| Layer | Mechanism | Default Window |
|-------|-----------|---------------|
| V2 messages | Timestamp validation | 60 seconds (configurable) |
| V2 messages | Future clock skew rejection | 5 seconds |
| RatchetSession | Monotonic counter | Strict sequence |
| ShieldChannel | Counter per message | Strict sequence |
| Tokens | Expiration timestamp | 3600 seconds |
| Sessions | TTL + refresh | Configurable |
| Recovery codes | One-time use flag | Single use |

---

## 7. RISK HOTSPOTS

### Known Vulnerabilities

| ID | Severity | Description | Affected | Status |
|----|----------|-------------|----------|--------|
| CVE-PENDING | MEDIUM | Missing padding length validation in v2 decryption. `pad_len` extracted from byte 16 of decrypted data without bounds checking (32-128). | Python, JS, Go, Java, C (all 5 checked implementations) | Fix merged (validation added), CVE not yet published |
| C-MAC-01 | LOW | C implementation uses custom loop-based MAC comparison instead of `memcmp_s()` or `CRYPTO_memcmp()`. Correct constant-time pattern but not using a vetted library function. | C only | Needs verification |
| C-TIMESTAMP-01 | LOW | C uses `time(NULL)` with 1-second precision (multiplied by 1000) instead of millisecond-precision clock. Reduces replay protection granularity. | C only | Needs `clock_gettime()` |

### Memory Safety Concerns

| Concern | Affected | Details |
|---------|----------|---------|
| No key zeroization | Python, JavaScript, Go, Java, C# | Relies on garbage collection; keys may persist in memory |
| C buffer management | C | Caller must `free()` all returned buffers; `strcat()` used in fingerprint.c (lines 47, 54, 56) without bounds |
| WASM `.unwrap()` | Rust WASM bindings | 4 instances of `.unwrap()` on `try_into()` (wasm.rs:67, 104, 115, 226); should return JsError |

### Missing Tests

| Area | Status |
|------|--------|
| Padding validation fuzzing | Missing across all languages |
| Boundary cases (pad_len = 0, 31, 129, 255) | Missing |
| Malformed ciphertext fuzzing | Missing |
| Memory leak / zeroization verification | Missing |
| Concurrent access / thread safety | Not tested |

### Code Quality Flags

| Pattern | Count | Locations |
|---------|-------|-----------|
| TODO/FIXME/HACK | 1 | release.yml:141 "TODO: Re-add build-wasm when ring WASM support is fixed" |
| CVE-PENDING comments | 5 | core.py:242, shield.js:209, shield.go:282, Shield.java:246, shield.c:500 |
| MD5 usage | 1 | shield-core fingerprint.rs:59, c/shield_fingerprint.c:65 (for device fingerprinting hash, not crypto) |
| HMAC-SHA1 | 1 | shield-core totp.rs:69 (RFC 6238 required, ring warns "LEGACY_USE_ONLY") |

### Code-Level Crypto Observations (from direct source reads)

**Rust `shield.rs`:**
- Line 83: `NonZeroU32::new(PBKDF2_ITERATIONS).unwrap()` — safe since constant is 100,000, but unwrap in crypto path
- Line 197-199: Timestamp from `SystemTime::now()` uses `.unwrap_or_default()` — if system clock fails, timestamp = 0 (would fall outside v2 range, treated as v1)
- Line 204: `pad_len` calculated as `(random_byte % 97) + 32` — modulo bias: 256 % 97 = 62, so values 32-93 are slightly more probable than 94-128. Not a security-critical bias but imperfect uniformity.
- Line 224: HMAC key is the raw encryption key — same key used for both encryption and authentication. Not separated. (Python identical at line 197, JS identical at line 159)
- Line 280: Constant-time comparison via `subtle::ConstantTimeEq` — correct
- Line 295: `try_into().unwrap()` on timestamp bytes — safe since slice is exactly 8 bytes from bounds check at line 293
- Line 300: `pad_len` as `usize` — no bounds validation in Rust impl (unlike Python/JS/Go/C/Java which have CVE-PENDING fix). **Rust is the ONLY implementation missing the padding validation.**
- Line 381-383: `.key()` method exposes the derived key — available in ALL implementations for "testing/debugging"

**Python `core.py`:**
- Line 175-176: Counter incremented per encryption (Rust does NOT increment — always 0). Counter mismatch across implementations.
- Line 183: Same modulo bias as Rust for padding length
- Line 197: HMAC uses `self._key` directly as both enc and mac key (no key separation)
- Line 242-244: Padding bounds check present (CVE-PENDING fix applied)

**JavaScript `shield.js`:**
- Line 39: `Buffer.concat()` in tight loop for keystream — O(n²) allocation pattern, potential DoS vector on very large messages
- Line 66-68: `options.salt` — if caller passes truthy non-Buffer value, salt derivation is bypassed (type confusion)
- Line 131: `BigInt()` conversion for counter — potential issues on older Node.js versions
- Line 189: `crypto.timingSafeEqual()` — correct constant-time comparison
- Line 207-212: Padding bounds check present
- Line 343-348: `generateKeystream` is EXPORTED in module.exports — exposes internal crypto primitive to consumers

**C `shield.c`:**
- Line 249-256: `shield_secure_compare()` — uses `volatile uint8_t result` with XOR accumulation. Correct constant-time pattern.
- Line 258-263: `shield_secure_wipe()` — uses `volatile` pointer write. Standard pattern but compiler may still optimize away.
- Line 265-288: Random from `/dev/urandom` — single `read()` call returns error on partial read (line 283 checks `n != len`). Robust but does not retry on EINTR/partial; production hardening would loop until full read.
- Line 294: Keystream buffer is stack-allocated `uint8_t block[32 + NONCE_SIZE + 4]` — fixed size, safe
- Line 468: `shield_secure_compare()` used for MAC — correct
- Line 498: `pad_len = decrypted[16]` is `uint8_t` — naturally bounded to 0-255
- Line 500-505: Bounds check on pad_len 32-128 present
- Line 517: `time(NULL) * 1000` — 1-second precision timestamps, reduces replay protection to 1-second granularity

**C `shield_fingerprint.c`:**
- Lines 40-56: `strcat()` into 512-byte buffer with 256-byte inputs — technically safe (256+1+256 < 512) but no bounds checking. If `get_motherboard_serial()` or `get_cpu_id()` ever returned > 255 chars, buffer overflow.
- Lines 76, 107: `_popen("wmic ...")` — hardcoded commands, no injection risk from user input
- Line 65: `md5_hash()` for combined fingerprint — MD5 is cryptographically broken, but here only used as a hash-to-string formatter

**WASM `wasm.rs`:**
- Lines 67, 104, 115: `.unwrap()` after length check + `try_into()` — safe but should use `.map_err()` for defensive coding in WASM boundary

**Rust `exchange.rs`:**
- Line 26: `NonZeroU32::new(iters).unwrap()` — would panic if `iterations = Some(0)` passed
- Line 44-57: `PAKEExchange::combine()` sorts contributions then hashes — deterministic regardless of order, good
- Line 98: `serde_json::to_string(&data).unwrap()` — safe since data is simple struct, but unwrap in public API

**Key Separation Concern (ALL implementations):**
The SAME 32-byte key is used for both XOR encryption (keystream generation) AND HMAC authentication. Best practice is to derive separate encryption and MAC keys from the master key. The PROTOCOL.md (line 39) actually specifies `mac_key = SHA256(master_key || "mac")` but NO implementation follows this — they all use the raw PBKDF2 output directly for both operations.

### Architecture Observations

| Observation | Detail |
|------------|--------|
| No version field in wire format | V1/V2 auto-detected by timestamp heuristic (2020-2100 range). False positive probability: ~0.0000024% |
| Password strength advisory only | `check_password()` warns but doesn't prevent weak passwords |
| Service as salt | Predictable salt from service name (by design for cross-platform determinism) |
| MAC truncation | 128-bit truncated HMAC-SHA256 (adequate but reduced from 256-bit) |
| CLI password in args | `shield check <password>` exposes password in shell history / process listing |
| In-memory session state | BrowserBridge, RateLimiter, IdentityProvider store state in memory only (no persistence) |

---

## 8. EXTERNAL INTEGRATIONS

### Cloud Services (Confidential Computing, optional features)

| Provider | Integration | Authentication | Data Flow |
|----------|------------|----------------|-----------|
| AWS Nitro Enclaves | NitroAttestationProvider | COSE signatures, PCR validation | Attestation evidence → verify → key release |
| AWS KMS | TEEKeyManager | IAM roles | Encrypted key material |
| AWS CloudHSM | Example: PyKCS11 | HSM PIN (env var) | PKCS#11 key operations |
| GCP Confidential VMs | SEVAttestationProvider | vTPM attestation | SEV-SNP evidence → verify |
| GCP Secret Manager | ConfidentialSpaceProvider | Service account | Secret retrieval |
| Azure MAA | MAAAttestationProvider | JWT validation | Attestation token → verify |
| Azure Key Vault | Secure Key Release | Managed identity | Key release policy |
| Intel SGX | SGXAttestationProvider | DCAP quotes | MRENCLAVE/MRSIGNER |
| HashiCorp Vault | Example: hvac client | Token/role | Transit encrypt/decrypt |

### Package Registries (Publishing)

| Registry | Package | Auth Secret |
|----------|---------|-------------|
| crates.io | shield-core | `CARGO_REGISTRY_TOKEN` |
| PyPI | shield-crypto | `PYPI_API_TOKEN` |
| npm | @guard8/shield | `NPM_TOKEN` |
| npm | @guard8/shield-browser | `NPM_TOKEN` |
| GitHub Releases | CLI binaries | `GITHUB_TOKEN` (auto) |
| Codecov | Coverage reports | `CODECOV_TOKEN` |

### Third-Party Actions (CI/CD)

| Action | Version | Purpose |
|--------|---------|---------|
| actions/checkout | v4 | Repository checkout |
| dtolnay/rust-toolchain | stable | Rust installation |
| actions/setup-python | v5 | Python matrix |
| actions/setup-node | v4 | Node.js matrix |
| actions/setup-go | v5 | Go matrix |
| actions/setup-java | v4 | Java/Android |
| actions/cache | v4 | Build caching |
| gradle/actions/setup-gradle | v3 | Gradle wrapper |
| android-actions/setup-android | v3 | Android SDK |
| swift-actions/setup-swift | v2 | Swift toolchain |
| actions/setup-dotnet | v4 | .NET SDK |
| trufflesecurity/trufflehog | @main | Secret scanning |
| codecov/codecov-action | v4 | Coverage upload |
| softprops/action-gh-release | v1 | GitHub Release creation |

---

## 9. UNKNOWNS & GAPS

### Cannot Determine from Static Analysis

| Unknown | Why | Impact |
|---------|-----|--------|
| Actual deployment environment | Library is consumed by downstream apps; no Shield-specific servers | Cannot assess runtime configuration |
| Key storage in production | Depends on integrator implementation | Critical - weak storage defeats crypto |
| TLS enforcement | Application-level responsibility | Ciphertext visible but secure; keys in transit may not be |
| Password strength in practice | Advisory only, no enforcement | Weak passwords directly reduce security |
| Clock synchronization | Replay protection depends on synchronized clocks | Affects v2 replay window |
| Ring crate internal safety | `ring` uses `unsafe` internally | Audited by Mozilla/Google but not verified here |
| C constant-time correctness | Custom loop-based comparison | Not formally verified |
| WASM memory isolation | Browser sandbox model | WASM linear memory may be inspectable by JS |
| Side-channel resistance (hardware) | Cannot test timing/power/EM from code | Depends on deployment hardware |
| Thread safety of in-memory state | BrowserBridge sessions, RateLimiter counters | Race conditions possible under load |

### Not Tested / Not Verified

| Gap | Detail |
|-----|--------|
| No external security audit | Budget allocated ($33-52k), auditor candidates listed, not executed |
| No fuzzing suite | Mentioned in audit doc, not implemented |
| No formal verification | Listed as "Planned" in SECURITY.md |
| No SAST tooling beyond Clippy | No Semgrep, CodeQL, or Bandit in CI |
| No DAST testing | No runtime security testing |
| No dependency pinning verification | Go sum verified, others use lockfiles but no integrity checks in CI |
| No supply chain verification | No SLSA, SBOM, or Sigstore integration |
| WASM binary integrity | No checksum verification of WASM module before loading |
| Browser SDK CSP compatibility | No Content-Security-Policy testing documented |
| Mobile SDK obfuscation | No ProGuard/R8 config for Android, no code stripping for iOS release |

### Documentation vs Implementation Discrepancies

| Claim | Reality |
|-------|---------|
| "Uses `ring` crate (same as Firefox, 1Password)" | True for Rust core; other languages use platform primitives |
| "Zero dependencies" | True for most languages; Rust has ring+subtle+zeroize+serde+base64+hex+md5 |
| "10 language implementations" | Actually 12 (Rust, Python, JS, Go, C, Java, C#, Swift, Kotlin, Android, iOS, WASM) |
| "95 tests (Rust)" | Actual count appears to be 234 across the Rust codebase |
| "Constant-time code (we do)" | True for Rust (subtle crate), Python (hmac.compare_digest), JS (timingSafeEqual). C/Java/C#/Swift use custom implementations |
| "Keys are wiped after use" | True for Rust (Zeroize). Not implemented in Python, JS, Go, Java, C# |
| SECURITY.md: "Formal verification: Planned" | Not started |
| SECURITY.md: "External audit: Planned" | Not started |

---

*This document captures the state of the Shield codebase as of 2026-02-28. All findings are based on static analysis of source code. No runtime testing, penetration testing, or dynamic analysis was performed. This is a fact-finding document; no remediation recommendations are included.*
