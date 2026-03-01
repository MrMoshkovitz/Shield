---
name: skill-shield-file-navigator
description: Navigate Shield's 12-language codebase to quickly locate encryption components, security primitives, and platform-specific implementations. Use at start of any audit task.
---

# Shield File Navigator

Structured map for locating any component across Shield's 12-language codebase.

## When to Use
- At the start of any audit task to locate relevant files
- When tracing a feature across multiple language implementations
- When finding platform-specific security code

## Inputs
- Component name (e.g., "PBKDF2", "HMAC", "encrypt", "nonce")
- Target language(s) or "all"

## Procedure
1. Use this codebase map to locate files:

### Core Encryption (encrypt/decrypt/key derivation)
| Language | Primary File | Key Class/Module |
|----------|-------------|-----------------|
| Rust | `shield-core/src/lib.rs` | `Shield` |
| Python | `python/shield/core.py` | `Shield` |
| JavaScript | `javascript/src/shield.js` | `Shield` |
| Go | `go/shield.go` | `Shield` |
| C | `c/shield.c` | `shield_*` functions |
| Java | `java/src/main/java/ai/guard8/shield/Shield.java` | `Shield` |
| C# | `csharp/Shield.cs` | `Shield` |
| Swift | `swift/Sources/Shield/Shield.swift` | `Shield` |
| Kotlin | `kotlin/src/main/kotlin/ai/guard8/shield/Shield.kt` | `Shield` |
| WASM | `wasm/` (re-exports shield-core) | via Rust |
| Android | `android/` | `Shield` + `SecureKeyStore` |
| iOS | `ios/` | `Shield` + `SecureKeychain` |

### Advanced Features
| Feature | Rust | Python | JS |
|---------|------|--------|----|
| StreamCipher | `shield-core/src/stream.rs` | `python/shield/stream.py` | `javascript/src/stream.js` |
| RatchetSession | `shield-core/src/ratchet.rs` | `python/shield/ratchet.py` | `javascript/src/ratchet.js` |
| TOTP | `shield-core/src/totp.rs` | `python/shield/totp.py` | `javascript/src/totp.js` |
| GroupEncryption | `shield-core/src/group.rs` | `python/shield/group.py` | `javascript/src/group.js` |
| Lamport Sigs | `shield-core/src/lamport.rs` | `python/shield/lamport.py` | `javascript/src/lamport.js` |
| KeyRotation | `shield-core/src/rotation.rs` | `python/shield/rotation.py` | `javascript/src/rotation.js` |
| Identity | `shield-core/src/identity.rs` | `python/shield/identity.py` | `javascript/src/identity.js` |

### Web Integration (Python only)
| Component | File |
|-----------|------|
| FastAPI Middleware | `python/shield/integrations/middleware.py` |
| Flask Extension | `python/shield/integrations/flask_shield.py` |
| Cookie Security | `python/shield/integrations/cookies.py` |
| Rate Limiting | `python/shield/integrations/rate_limiter.py` |
| CORS | `python/shield/integrations/cors.py` |
| Browser Bridge | `python/shield/integrations/browser_bridge.py` |
| API Protection | `python/shield/integrations/api_protector.py` |
| Token Auth | `python/shield/integrations/token_auth.py` |

### Confidential Computing
| Provider | Rust File | Python File |
|----------|-----------|-------------|
| AWS Nitro | `shield-core/src/confidential/nitro.rs` | `python/shield/integrations/confidential/nitro.py` |
| GCP SEV | `shield-core/src/confidential/sev.rs` | `python/shield/integrations/confidential/sev.py` |
| Azure MAA | `shield-core/src/confidential/maa.rs` | `python/shield/integrations/confidential/maa.py` |
| Intel SGX | `shield-core/src/confidential/sgx.rs` | `python/shield/integrations/confidential/sgx.py` |

### Infrastructure
| Component | File |
|-----------|------|
| Dockerfile | `Dockerfile` |
| Docker Compose | `docker-compose.yml` |
| Browser SDK | `browser/shield-browser.js` |
| Fingerprinting | `javascript/src/fingerprint.js`, `go/fingerprint.go`, `java/.../Fingerprint.java`, `c/fingerprint.c` |

### Tests
| Language | Test Location |
|----------|--------------|
| Rust | `shield-core/tests/` |
| Python | `python/tests/` |
| JavaScript | `javascript/test/` |
| Go | `go/*_test.go` |
| C | `c/test_shield.c` |
| Cross-language | `tests/` |

2. For a specific component, grep across implementations:
   - Use `grep -r "PATTERN" --include="*.{rs,py,js,go,c,java,cs,swift,kt}"`
3. Verify file exists before referencing in findings

## Output Format
Return a table of relevant files for the requested component:
```
| Language | File | Symbol |
|----------|------|--------|
| Rust | shield-core/src/lib.rs:42 | Shield::encrypt() |
| Python | python/shield/core.py:87 | Shield.encrypt() |
...
```

## Used By
- All 16 agents (A1-A16)
- All 7 teams (T6-T12)
