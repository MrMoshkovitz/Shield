# Agent 11: Error Disclosure — Security Findings

**Agent**: A11 — Error Disclosure
**Phase**: 2
**Priority**: HIGH
**Auditor**: Ralph Loop (Iteration 35)
**Date**: 2026-03-03
**Files Audited**: error.rs, shield.rs, core.py, shield.js, shield.go, Shield.java, Shield.cs, shield.c (+ include/shield.h), Shield.swift, Shield.kt, fastapi.py, flask.py, express.js, browser.py, cli.py, confidential/middleware.py, confidential/base.py, fido2_api.py, pgvector_api.py, protection.py, channel.py, channel.js, identity.rs, identity.py, identity.js, identityProvider.kt/java/cs
**Total Findings**: 25

---

## Error Message Catalog Summary

### Core Library Error Messages by Implementation

| Error | Rust | Python | JS | Go | Java | C# | C | Swift | Kotlin | Disclosure |
|-------|------|--------|----|----|------|----|---|-------|--------|------------|
| Ciphertext too short | `expected {expected}, got {actual}` | returns `None` | N/A | `shield: ciphertext too short` | `"Ciphertext too short"` | `"Ciphertext too short"` | `SHIELD_ERR_CIPHERTEXT_TOO_SHORT` (-2) | `.ciphertextTooShort` | `.CiphertextTooShort` | **Rust leaks byte counts** |
| Auth failed (MAC) | `"authentication failed: MAC verification failed"` | returns `None` | N/A | `"shield: authentication failed"` | `"Authentication failed"` | `"Authentication failed"` | `SHIELD_ERR_AUTHENTICATION_FAILED` (-3) | `.authenticationFailed` | `.AuthenticationFailed` | Rust reveals MAC mechanism |
| Invalid key length | `expected {expected}, got {actual}` | `f"Key must be 32 bytes, got {len(key)}"` | `f"Key must be 32 bytes, got ${key.length}"` | `"shield: invalid key size"` | `"Invalid key size"` | `"Invalid key size"` | `SHIELD_ERR_INVALID_KEY_SIZE` (-1) | `.invalidKeySize` | `"Invalid key size"` | **Rust/Python/JS leak actual key size** |
| Key derivation failed | `"key derivation failed: {0}"` | N/A | N/A | N/A | `"PBKDF2 not available"` | N/A | N/A | N/A | N/A | **Rust/Java leak algorithm names** |
| User exists | `"user {0} already exists"` | `f"User {user_id} already exists"` | `f"User ${userId} already exists"` | N/A | `f"User " + userId + " already exists"` | `f"User {userId} already exists"` | N/A | N/A | `f"User $userId already exists"` | **All leak user IDs → enumeration** |
| Unknown version | `"unknown key version: {0}"` | `f"Unknown key version: {version}"` | `f"Unknown key version: ${version}"` | N/A | `f"Unknown key version: " + version` | `f"Unknown key version: {version}"` | N/A | N/A | N/A | Leaks internal versioning scheme |
| Protocol version | N/A | `f"Unsupported protocol version: {version}"` | `f"Unsupported protocol version: ${header[0]}"` | `"shield: unsupported protocol version"` | N/A | N/A | N/A | N/A | N/A | **Python/JS leak raw protocol byte** |
| Message too large | N/A | `f"Message too large: {len(data)} > {MAX_MESSAGE_SIZE}"` | `f"Message too large: ${data.length} > ${MAX_MESSAGE_SIZE}"` | `"shield: message too large"` | N/A | N/A | N/A | N/A | N/A | **Python/JS leak actual+max size** |
| Unexpected msg type | N/A | `f"Unexpected message type: expected {expected_type}, got {msg_type}"` | `f"Unexpected message type: expected ${expectedType}, got ${header[1]}"` | N/A | N/A | N/A | N/A | N/A | N/A | **Leaks protocol state machine** |
| Frame too large | N/A | `f"Frame too large: {length} > {MAX_MESSAGE_SIZE}"` | `f"Frame too large: ${length} > ${MAX_MESSAGE_SIZE}"` | N/A | N/A | N/A | N/A | N/A | N/A | **Leaks frame size limits** |
| Chunk auth failed | N/A | `f"Chunk {chunk_num} authentication failed"` | `f"Chunk ${chunkNum} authentication failed"` | N/A | `f"Chunk " + chunkNum + " authentication failed"` | `f"Chunk {chunkNum} authentication failed"` | N/A | N/A | `f"Chunk $chunkNum authentication failed"` | **Leaks which chunk failed** |

---

## Findings

### SHIELD-A11-001: Rust CiphertextTooShort Leaks Exact Byte Counts
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-209 (Generation of Error Message Containing Sensitive Information)
- **Location**: `shield-core/src/error.rs:12-13`
- **Evidence**:
```rust
#[error("ciphertext too short: expected at least {expected} bytes, got {actual}")]
CiphertextTooShort { expected: usize, actual: usize },
```
- **Impact**: Attacker learns exact minimum ciphertext size expected (reveals wire format structure: NONCE_SIZE + MAC_SIZE = 32 bytes) and the actual size of their malformed input. Useful for chosen-ciphertext oracle refinement. Combined with distinguishable errors from MAC failure vs size failure, attacker can probe the cipher's internal structure.
- **Reproduction**: Send ciphertext < 32 bytes to decrypt(). Error string reveals expected vs actual byte counts.
- **Fix Complexity**: LOW
- **Remediation**: Change to generic: `#[error("decryption failed")]` — do not expose expected/actual sizes.
- **Verification Notes**: Read error.rs directly. This is the only implementation that exposes byte counts in errors. Python returns None, Go returns generic error string.

### SHIELD-A11-002: Rust InvalidKeyLength Reveals Expected and Actual Key Size
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-209
- **Location**: `shield-core/src/error.rs:24-25`
- **Evidence**:
```rust
#[error("invalid key length: expected {expected} bytes, got {actual}")]
InvalidKeyLength { expected: usize, actual: usize },
```
- **Impact**: Reveals the expected key size (32 bytes = 256-bit) and the caller's actual key size. In a library-as-dependency scenario, this leaks to calling application logs.
- **Reproduction**: Pass a key of incorrect length to `Shield::with_key()`.
- **Fix Complexity**: LOW
- **Remediation**: Change to: `#[error("invalid key length")]` — omit sizes.

### SHIELD-A11-003: Python/JS/Rust Key Validation Errors Leak Key Length
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-209
- **Location**: `python/shield/core.py:103`, `javascript/src/shield.js:83`, `shield-core/src/error.rs:24-25`
- **Evidence**:
```python
raise ValueError(f"Key must be 32 bytes, got {len(key)}")
```
```javascript
throw new Error(`Key must be 32 bytes, got ${key.length}`);
```
- **Impact**: Reveals the expected key size (32) and the actual key size provided. In web integrations, these errors may propagate to HTTP responses. Confirms algorithm uses 256-bit keys.
- **Reproduction**: Call `Shield(key=b'\x00'*16)` in Python or `new Shield({key: Buffer.alloc(16)})` in JS.
- **Fix Complexity**: LOW
- **Remediation**: Change to `"Invalid key size"` without revealing expected or actual values.

### SHIELD-A11-004: Rust AuthenticationFailed Reveals MAC Mechanism
- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-209
- **Location**: `shield-core/src/error.rs:16`
- **Evidence**:
```rust
#[error("authentication failed: MAC verification failed")]
AuthenticationFailed,
```
- **Impact**: Reveals that the library uses MAC-based authentication (as opposed to AEAD or other approaches). Confirms Encrypt-then-MAC construction to an attacker probing the cipher.
- **Reproduction**: Send tampered ciphertext to `shield.decrypt()`.
- **Fix Complexity**: LOW
- **Remediation**: Change to: `#[error("decryption failed")]` — generic, no construction details.
- **Verification Notes**: Other implementations use just "Authentication failed" (Java, C#, Kotlin) or return None/error code (Python, C). Only Rust explicitly mentions "MAC".

### SHIELD-A11-005: FastAPI shield_protected Leaks Raw Decrypt Exception to HTTP Response
- **Tag**: VERIFIED
- **Severity**: HIGH
- **CWE**: CWE-209
- **Location**: `python/shield/integrations/fastapi.py:174`
- **Evidence**:
```python
except (json.JSONDecodeError, KeyError, ValueError) as e:
    raise HTTPException(status_code=400, detail=f"Decryption failed: {e}")
```
- **Impact**: Forwards raw Python exception message (including tracebacks for JSONDecodeError, key material size info from ValueError) directly to HTTP client. Attacker probing encrypted endpoints gets detailed error messages about WHY decryption failed — enabling adaptive chosen-ciphertext attacks. The ValueError from Shield decrypt could contain key size info, and JSONDecodeError reveals that decrypted content is expected to be JSON.
- **Reproduction**: Send malformed base64 or incorrect encrypted body to a FastAPI endpoint decorated with `@shield_protected`. Observe the `detail` field in the 400 response.
- **Fix Complexity**: LOW
- **Remediation**: Change to: `raise HTTPException(status_code=400, detail="Invalid request body")` — no exception detail.
- **Verification Notes**: Cross-references SHIELD-A04-020 (Express similar pattern). Both web frameworks expose decrypt errors.

### SHIELD-A11-006: Express shieldRequired Leaks err.message in HTTP Response
- **Tag**: VERIFIED
- **Severity**: HIGH
- **CWE**: CWE-209
- **Location**: `javascript/integrations/express.js:142-144`
- **Evidence**:
```javascript
} catch (err) {
    return res.status(400).json({
        error: `Decryption failed: ${err.message}`
    });
}
```
- **Impact**: Forwards raw JavaScript Error.message to HTTP response body. Depending on the error, this may include "authentication failed", "ciphertext too short", or internal state. Enables crypto oracle attacks — attacker can distinguish MAC failures from format errors.
- **Reproduction**: Send malformed `req.body.data` to an Express endpoint using `shieldRequired`. Observe error message in JSON response.
- **Fix Complexity**: LOW
- **Remediation**: Change to: `return res.status(400).json({ error: 'Invalid request body' });`
- **Verification Notes**: Additionally, `shieldErrorHandler` at line 163-169 also sends `err.message` to client. Cross-references SHIELD-A04-020 and SHIELD-A06-002.

### SHIELD-A11-007: Express shieldErrorHandler Exposes Crypto Error Details
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-209
- **Location**: `javascript/integrations/express.js:163-169`
- **Evidence**:
```javascript
function shieldErrorHandler(err, req, res, next) {
    if (err.name === 'ShieldError') {
        return res.status(400).json({
            error: 'Encryption/decryption error',
            message: err.message
        });
    }
    next(err);
}
```
- **Impact**: Exposes `err.message` containing Shield error details (MAC failed, ciphertext too short, etc.) to client. This is the dedicated error handler that developers are told to use, making it a systemic issue.
- **Reproduction**: Trigger any Shield error through Express middleware and catch it with this handler.
- **Fix Complexity**: LOW
- **Remediation**: Remove `message: err.message` field. Return only `{ error: 'Encryption/decryption error' }`.

### SHIELD-A11-008: Confidential Computing Middleware Leaks Exception Details
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-209
- **Location**: `python/shield/integrations/confidential/middleware.py:132-138`
- **Evidence**:
```python
except Exception as e:
    return JSONResponse(
        status_code=401,
        content={
            "error": "attestation_failed",
            "message": str(e),
        },
    )
```
- **Impact**: Any exception during attestation verification is converted to string and sent to client. This could include internal error messages from TEE providers, network errors, certificate details, or stack traces. Enables reconnaissance of the attestation infrastructure.
- **Reproduction**: Send malformed attestation token to an endpoint protected by AttestationMiddleware.
- **Fix Complexity**: LOW
- **Remediation**: Change to: `"message": "Attestation verification failed"` — no exception detail.

### SHIELD-A11-009: TEE Type Mismatch Error Reveals Expected TEE Configuration
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-209
- **Location**: `python/shield/integrations/confidential/base.py:311-312`
- **Evidence**:
```python
raise AttestationError(
    f"TEE type mismatch: expected {envelope['tee_type']}, "
```
- **Impact**: Reveals what TEE type the server expects (e.g., "nitro", "sev-snp", "sgx"), allowing attacker to craft targeted attestation forgeries.
- **Reproduction**: Submit a valid attestation from wrong TEE type. Error reveals what type was expected.
- **Fix Complexity**: LOW
- **Remediation**: Change to: `"Invalid attestation"` — no TEE type details.

### SHIELD-A11-010: User Enumeration via User Exists Error Across 7 Implementations
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-204 (Observable Response Discrepancy)
- **Location**: `shield-core/src/error.rs:64`, `python/shield/identity.py:121`, `javascript/src/identity.js:96`, `java/**/IdentityProvider.java:105`, `csharp/Shield/IdentityProvider.cs:95`, `kotlin/**/IdentityProvider.kt:83`, `swift/**/IdentityProvider.swift:81`
- **Evidence**:
```rust
#[error("user {0} already exists")]
UserExists(String),
```
```python
raise ValueError(f"User {user_id} already exists")
```
```javascript
throw new Error(`User ${userId} already exists`);
```
- **Impact**: Returns the actual user_id in the error message, confirming user existence. Enables user enumeration attack against IdentityProvider.register(). Present in ALL 7 implementations that have IdentityProvider.
- **Reproduction**: Call `register(user_id="admin", ...)` when "admin" already exists. Error confirms existence.
- **Fix Complexity**: LOW
- **Remediation**: Change to: `"Registration failed"` — do not reveal whether user exists. Cross-references SHIELD-A07-001.

### SHIELD-A11-011: Python/JS Channel Errors Leak Protocol Internals
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-209
- **Location**: `python/shield/channel.py:268,271,326`, `javascript/src/channel.js:270,274,336`
- **Evidence**:
```python
raise ValueError(f"Unsupported protocol version: {version}")
raise ValueError(f"Unexpected message type: expected {expected_type}, got {msg_type}")
raise ValueError(f"Frame too large: {length} > {MAX_MESSAGE_SIZE}")
```
```javascript
throw new Error(`Unsupported protocol version: ${header[0]}`);
throw new Error(`Unexpected message type: expected ${expectedType}, got ${header[1]}`);
throw new Error(`Frame too large: ${length} > ${MAX_MESSAGE_SIZE}`);
```
- **Impact**: Reveals protocol version numbers, message type state machine, and maximum frame sizes (16MB). Attacker probing the channel protocol learns exact structure and limits, aiding protocol fuzzing. Go uses generic `"shield: unsupported protocol version"` without values — the correct pattern.
- **Reproduction**: Connect to ShieldChannel and send a message with wrong version byte. Error reveals expected version.
- **Fix Complexity**: LOW
- **Remediation**: Use generic errors: "Protocol error", "Invalid message", "Message too large" — omit actual values and limits.

### SHIELD-A11-012: Stream Cipher Chunk Authentication Errors Leak Chunk Numbers
- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-209
- **Location**: `python/shield/stream.py:189`, `javascript/src/stream.js:195`, `java/**/StreamCipher.java:164,259`, `csharp/Shield/StreamCipher.cs:135,211`, `kotlin/**/StreamCipher.kt:219,294`
- **Evidence**:
```python
raise ValueError(f"Chunk {chunk_num} authentication failed")
```
```java
throw new SecurityException("Chunk " + chunkNum + " authentication failed");
```
- **Impact**: Reveals which specific chunk failed authentication in a stream. An attacker intercepting and modifying encrypted streams can determine exactly which chunk was modified based on the chunk number in the error, enabling targeted chunk manipulation attacks.
- **Reproduction**: Modify a specific chunk in a stream-encrypted file, observe error identifies the tampered chunk.
- **Fix Complexity**: LOW
- **Remediation**: Change to: `"Stream authentication failed"` — omit chunk numbers.

### SHIELD-A11-013: Java/Kotlin Expose Algorithm Names in RuntimeExceptions
- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-209
- **Location**: `java/**/Shield.java:333,343,353`, `java/**/StreamCipher.java:276,359,369`, `java/**/Exchange.java:49,81`, `java/**/RatchetSession.java:142`, `java/**/GroupEncryption.java:204,214`, `java/**/IdentityProvider.java:333,353`
- **Evidence**:
```java
throw new RuntimeException("SHA-256 not available", e);
throw new RuntimeException("HMAC-SHA256 not available", e);
throw new RuntimeException("PBKDF2 not available", e);
throw new RuntimeException("Failed to derive key", e);
throw new RuntimeException("HMAC-SHA1 not available", e);
```
- **Impact**: Reveals specific algorithm names used (SHA-256, HMAC-SHA256, PBKDF2, HMAC-SHA1 for TOTP). While these are standard algorithms, confirming them to an attacker narrows the attack surface. The `RuntimeException` chain also includes the original JCE `NoSuchAlgorithmException` which may contain JVM version info.
- **Reproduction**: These fire only if JCE providers are misconfigured, which is rare but possible in custom JRE deployments.
- **Fix Complexity**: LOW
- **Remediation**: Wrap in a generic `ShieldException("Crypto operation failed")` without algorithm details.

### SHIELD-A11-014: Python CLI Version String Exposes Library Identity
- **Tag**: VERIFIED
- **Severity**: INFO
- **CWE**: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
- **Location**: `python/shield/cli.py:157`
- **Evidence**:
```python
parser.add_argument(
    "--version", action="version", version="shield-crypto 0.1.0"
)
```
- **Impact**: `shield --version` outputs `shield-crypto 0.1.0`, confirming library name and exact version. Combined with Go's `"shield: "` error prefix and all error messages mentioning "Shield", library identity is easily fingerprinted.
- **Reproduction**: Run `python -m shield --version`.
- **Fix Complexity**: LOW
- **Remediation**: Standard practice to expose version; this is INFO only. If versioning matters for security, consider not including patch version in pre-1.0 releases.

### SHIELD-A11-015: Distinguishable Error Paths Enable Crypto Oracle (Systemic)
- **Tag**: VERIFIED
- **Severity**: HIGH
- **CWE**: CWE-208 (Observable Timing Discrepancy) + CWE-209
- **Location**: All implementations — decrypt path
- **Evidence**: Rust has 3 distinct error variants for decrypt failures: `CiphertextTooShort`, `AuthenticationFailed`, `InvalidFormat`. Python returns `None` for all (SAFE). Go returns 2 distinct errors. JS throws different Error messages. Java uses `IllegalArgumentException` vs `SecurityException`. C uses distinct error codes (-2, -3).

  **Rust path analysis (shield.rs)**:
  1. Size check → `CiphertextTooShort` (line 261)
  2. MAC check → `AuthenticationFailed` (line 281)
  3. Padding validation → `InvalidFormat` (line 304)
  4. Size re-check → `InvalidFormat` (line 318)
  5. Replay (expired) → `InvalidFormat` (line 323)

  **Java path analysis (Shield.java)**:
  1. Size check → `IllegalArgumentException("Ciphertext too short")` (line 212)
  2. MAC check → `SecurityException("Authentication failed")` (line 227)

  **C path analysis (shield.c)**:
  1. Size → `SHIELD_ERR_CIPHERTEXT_TOO_SHORT` (-2)
  2. MAC → `SHIELD_ERR_AUTHENTICATION_FAILED` (-3)
  3. Alloc → `SHIELD_ERR_ALLOC_FAILED` (-4)

- **Impact**: Attacker can distinguish between "too short", "MAC failed", and "format invalid" errors. This enables a classic **padding/format oracle attack**: by modifying ciphertext and observing which error is returned, attacker can determine which processing stage was reached. Combined with web middleware that forwards these errors (A11-005, A11-006), this becomes exploitable over HTTP.
- **Reproduction**: Send progressively modified ciphertexts via web middleware and observe different error messages in response. Compare behavior across implementations to find the weakest link.
- **Fix Complexity**: MEDIUM
- **Remediation**: All decrypt operations should return a SINGLE, INDISTINGUISHABLE error for any failure: `"Decryption failed"`. No size info, no MAC status, no format details. Python's `return None` pattern is the CORRECT approach — all other implementations should follow it for their error returns.
- **Verification Notes**: This is the SYSTEMIC finding that combines individual error disclosure patterns into a crypto oracle risk. Cross-references T06 (Crypto Oracle & Error Leakage team). Python is the ONLY implementation that does this correctly (returns None for all failures).

---

## TASK-2-024: Middleware Error Propagation & Crypto Leakage (Iteration 36)

> **Audit Focus**: Trace error propagation from Shield decrypt failures through middleware to HTTP responses. Assess crypto oracle feasibility via error path differences.
> **Files Audited**: fastapi.py, flask.py, express.js, django/__init__.py, confidential/middleware.py, browser.py, protection.py, fido2_api.py, core.py, shield.js, error.rs

### SHIELD-A11-016: FastAPI shield_protected Unhandled TypeError Creates 500/400 Oracle
- **Tag**: VERIFIED
- **Severity**: HIGH
- **CWE**: CWE-209 (Generation of Error Message Containing Sensitive Information) + CWE-755 (Improper Handling of Exceptional Conditions)
- **Location**: `python/shield/integrations/fastapi.py:171-174`
- **Evidence**:
```python
try:
    payload = json.loads(body)
    if payload.get("encrypted"):
        encrypted = base64.b64decode(payload["data"])
        decrypted = shield.decrypt(encrypted)           # Returns None on MAC/auth failure
        kwargs["body"] = json.loads(decrypted)           # TypeError: can't parse None!
except (json.JSONDecodeError, KeyError, ValueError) as e:
    raise HTTPException(status_code=400, detail=f"Decryption failed: {e}")
```
Error propagation chain:
1. Malformed body (not JSON) → `json.JSONDecodeError` → caught → **400** `"Decryption failed: ..."` with JSON error detail
2. Missing "data" key → `KeyError` → caught → **400** `"Decryption failed: 'data'"` leaks expected key name
3. Invalid base64 → `binascii.Error` (subclass of `ValueError`) → caught → **400** `"Decryption failed: Invalid base64-encoded string"`
4. **Valid base64 but wrong key/tampered** → `shield.decrypt()` returns `None` → `json.loads(None)` → **`TypeError: the JSON object must be str, bytes or bytearray, not NoneType`** → **NOT CAUGHT** → propagates as **500 Internal Server Error**

- **Impact**: Attacker can distinguish 4 distinct error stages: bad JSON (400), missing key (400), bad base64 (400), vs decryption/MAC failure (500). The 500 vs 400 status code difference is a **binary crypto oracle**: attacker probes whether ciphertext passed base64 decode but failed MAC/decrypt, vs structural format errors. This is exploitable for adaptive chosen-ciphertext attacks when combined with the response timing and status code oracle. In FastAPI debug mode (`--reload`), the 500 response includes the full Python traceback with function names and file paths.
- **Reproduction**: 1. Send `{"encrypted": true, "data": "<valid-base64-of-random-bytes>"}` to a `shield_protected` endpoint. 2. Observe 500 response (not 400). 3. Compare with `{"encrypted": true, "data": "!!!not-base64!!!"}` → 400 response. 4. The status code difference confirms whether Shield.decrypt() was reached.
- **Fix Complexity**: LOW
- **Remediation**: Add `TypeError` to the except clause, OR better: check `if decrypted is None: raise HTTPException(status_code=400, detail="Invalid request body")` before attempting `json.loads(decrypted)`.
- **Verification Notes**: Traced the full error propagation chain. Python `Shield.decrypt()` confirmed to return `None` for all failures (core.py:214, 227, 244, 249). The TypeError from `json.loads(None)` is reproducible and NOT caught by the exception handler.

### SHIELD-A11-017: Express shieldRequired Leaks Decrypt-vs-Parse Error via err.message
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-209
- **Location**: `javascript/integrations/express.js:136-145`
- **Evidence**:
```javascript
try {
    const encrypted = Buffer.from(req.body.data, 'base64');
    const decrypted = shield.decrypt(encrypted);            // Returns null on failure
    req.shieldData = JSON.parse(decrypted.toString());       // null.toString() → TypeError
    next();
} catch (err) {
    return res.status(400).json({
        error: `Decryption failed: ${err.message}`
    });
}
```
Error propagation chain:
1. Bad base64 in `req.body.data` → `Buffer.from()` silently returns buffer of decoded bytes (JS doesn't throw on bad base64)
2. Shield.decrypt() returns null for MAC/auth failure
3. `null.toString()` → `TypeError: Cannot read properties of null (reading 'toString')`
4. `err.message` = `"Cannot read properties of null (reading 'toString')"` — **reveals decrypt returned null**
5. If decrypt succeeded but content isn't JSON → `SyntaxError: Unexpected token X in JSON at position 0`

- **Impact**: Attacker sees two DISTINCT error messages: "Cannot read properties of null" (decrypt failed = MAC/auth failure) vs "Unexpected token..." (decrypt succeeded but content isn't valid JSON). This is a **crypto oracle**: the error message reveals whether decryption passed the MAC check. Cross-references SHIELD-A11-006.
- **Reproduction**: 1. Send `{"encrypted": true, "data": "<base64-of-random-32-bytes>"}` to an Express `shieldRequired` endpoint. 2. Response: `{"error": "Decryption failed: Cannot read properties of null (reading 'toString')"}`. 3. Compare with a valid encrypted but non-JSON payload (if you have the key): `{"error": "Decryption failed: Unexpected token ..."}`.
- **Fix Complexity**: LOW
- **Remediation**: Check `if (decrypted === null) return res.status(400).json({ error: 'Invalid request body' });` before `JSON.parse`. Then also wrap JSON.parse in separate try/catch with same generic error.
- **Verification Notes**: JS Shield.decrypt() returns null on MAC failure (shield.js:188 `return null`). The null propagation to toString() is the specific vector.

### SHIELD-A11-018: Flask _before_request Silently Swallows ALL Decrypt Errors (Fail-Open)
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-636 (Not Failing Securely / Fail-Open)
- **Location**: `python/shield/integrations/flask.py:121-134`
- **Evidence**:
```python
def _before_request(self) -> None:
    if not self.shield or not self._should_process(request.path):
        return

    if request.is_json and request.content_length:
        try:
            data = request.get_json(force=True)
            if isinstance(data, dict) and data.get("encrypted"):
                encrypted = base64.b64decode(data["data"])
                decrypted = self.shield.decrypt(encrypted)
                g.shield_decrypted_body = json.loads(decrypted)
        except Exception:
            pass  # Let the route handle invalid data
```
- **Impact**: When decrypt fails (returns None), `json.loads(None)` raises TypeError, which is caught by the bare `except Exception: pass`. The request continues to the route handler WITHOUT `g.shield_decrypted_body` being set, and WITHOUT any error indication. The route handler receives the raw encrypted payload as if nothing happened. This is a **fail-open pattern**: tampered ciphertext or wrong-key decrypt silently fails, and the request proceeds. There is NO information leakage to the attacker from this path (no distinct error), BUT the security model is violated — the route thinks it has decrypted data when it doesn't. Cross-references SHIELD-A06-001 and SHIELD-A04-024.
- **Reproduction**: 1. Configure Flask with ShieldFlask middleware. 2. Send `{"encrypted": true, "data": "<base64-random-bytes>"}`. 3. Request proceeds to route handler. 4. `g.shield_decrypted_body` is not set — route may crash with AttributeError or proceed with raw data.
- **Fix Complexity**: LOW
- **Remediation**: Return `abort(400)` on decrypt failure instead of `pass`. At minimum: set `g.shield_decrypted_body = None` explicitly and document that routes MUST check for None.
- **Verification Notes**: This was already partially reported in SHIELD-A06-001 from the error propagation angle. This finding documents the full error chain and the TypeError → bare except → silent pass sequence.

### SHIELD-A11-019: Flask _after_request Silently Swallows Encrypt Errors (Plaintext Leakage)
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-636 (Fail-Open) + CWE-311 (Missing Encryption of Sensitive Data)
- **Location**: `python/shield/integrations/flask.py:136-158`
- **Evidence**:
```python
def _after_request(self, response: Response) -> Response:
    if not self.shield or not self._should_process(request.path):
        return response
    if response.content_type and "application/json" in response.content_type:
        try:
            body = response.get_data()
            encrypted = self.shield.encrypt(body)
            # ... set encrypted response
        except Exception:
            pass  # Return original response on error
    return response
```
- **Impact**: If encryption fails for ANY reason (e.g., memory error, RNG failure), the middleware silently returns the **plaintext response**. The client receives unencrypted sensitive data without any indication that encryption was attempted but failed. In a system designed for mandatory encryption, this fail-open destroys the security guarantee. Cross-references SHIELD-A06-002.
- **Reproduction**: 1. Trigger an encryption failure (e.g., mock Shield.encrypt() to raise). 2. The plaintext JSON response is returned to the client. 3. No error, no warning, no header indicating encryption was skipped.
- **Fix Complexity**: LOW
- **Remediation**: On encrypt failure: return `abort(500)` or return a generic error response. NEVER return plaintext when encryption was expected.

### SHIELD-A11-020: Express shieldMiddleware Encrypts Error but Sends Plaintext on Failure
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-636 (Fail-Open) + CWE-311 (Missing Encryption)
- **Location**: `javascript/integrations/express.js:58-73`
- **Evidence**:
```javascript
res.json = (data) => {
    try {
        const plaintext = Buffer.from(JSON.stringify(data));
        const encrypted = shield.encrypt(plaintext);
        const encryptedB64 = encrypted.toString('base64');
        return originalJson({ encrypted: true, data: encryptedB64 });
    } catch (err) {
        console.error('Shield encryption error:', err);
        return originalJson(data);   // <-- SENDS PLAINTEXT!
    }
};
```
- **Impact**: If Shield.encrypt() throws for any reason, the middleware falls back to sending the plaintext response. The `console.error` logs the error server-side, but the client receives unencrypted data. Additionally, `console.error('Shield encryption error:', err)` logs the full error object which may contain key material context in server logs.
- **Reproduction**: Mock Shield.encrypt() to throw, observe plaintext JSON in response.
- **Fix Complexity**: LOW
- **Remediation**: Return `res.status(500).json({ error: 'Internal server error' })` instead of sending plaintext.
- **Verification Notes**: Same pattern as Flask _after_request (A11-019). Both frameworks fail-open on encryption errors.

### SHIELD-A11-021: Django Middleware Encrypt Fails Open to Plaintext
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-636 (Fail-Open) + CWE-311 (Missing Encryption)
- **Location**: `python/shield/integrations/django/__init__.py:79-89`
- **Evidence**:
```python
try:
    encrypted = self.shield.encrypt(response.content)
    encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
    return JsonResponse({'encrypted': True, 'data': encrypted_b64})
except Exception:
    # On encryption failure, return original response
    return response
```
- **Impact**: Same fail-open pattern as Flask and Express. Encrypt failure → plaintext response. Systemic across all 3 Python frameworks + Express.
- **Reproduction**: Same as A11-019/A11-020.
- **Fix Complexity**: LOW
- **Remediation**: Return `HttpResponse(status=500)` on encrypt failure.
- **Verification Notes**: Django `shield_required` (line 169) correctly returns generic `"Decryption failed"` without exception detail — SAFE. But `ShieldMiddleware` and `shield_protected` decorator have the fail-open problem on the encrypt side.

### SHIELD-A11-022: Confidential Middleware `requires_attestation` Leaks AttestationError.message
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-209
- **Location**: `python/shield/integrations/confidential/middleware.py:237-241`
- **Evidence**:
```python
except AttestationError as e:
    raise HTTPException(
        status_code=401,
        detail=f"Attestation error: {e.message}",
    )
```
Additional leak at `requires_attestation` decorator line 249-253:
```python
if required_tee_types and result.tee_type not in required_tee_types:
    raise HTTPException(
        status_code=403,
        detail=f"TEE type {result.tee_type.value} not allowed",
    )
```
And at line 259-262:
```python
raise HTTPException(
    status_code=403,
    detail=f"Measurement {name} mismatch",
)
```
- **Impact**: Three distinct information leaks: (1) AttestationError message may contain TEE provider internals, certificate errors, network errors; (2) TEE type reveal tells attacker what TEE is expected AND what their submission was classified as; (3) Measurement name reveals which PCR/measurement registers are being checked. Cross-references SHIELD-A11-008 and SHIELD-A11-009.
- **Reproduction**: 1. Submit attestation with wrong TEE type → `"TEE type sev-snp not allowed"` reveals the submitted type. 2. Submit attestation with correct TEE type but wrong measurement → `"Measurement pcr0 mismatch"` reveals which register is checked. 3. Submit malformed attestation → `"Attestation error: ..."` reveals internal error message.
- **Fix Complexity**: LOW
- **Remediation**: Return `detail="Attestation verification failed"` for all three cases. Log the specific error server-side.

### SHIELD-A11-023: AttestationRouter verify Endpoint Returns Full Verification Details
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-200 (Exposure of Sensitive Information)
- **Location**: `python/shield/integrations/confidential/middleware.py:399-407`
- **Evidence**:
```python
result = await self.provider.verify(evidence)
return {
    "verified": result.verified,
    "tee_type": result.tee_type.value,
    "measurements": result.measurements,    # <-- ALL measurement values!
    "claims": result.claims,                # <-- ALL claims!
    "error": result.error,                  # <-- Error detail!
}
```
- **Impact**: The `/attestation/verify` endpoint returns ALL measurement values (PCR registers, MRENCLAVE, etc.), ALL claims from the attestation token, and any error detail. An attacker can: (1) discover exact PCR values needed to forge attestation; (2) learn the expected measurement format; (3) use error messages for oracle attacks. This endpoint should ONLY return `verified: true/false`.
- **Reproduction**: POST to `/attestation/verify` with any base64-encoded attestation evidence. Response includes full measurements and claims.
- **Fix Complexity**: MEDIUM
- **Remediation**: Return only `{"verified": bool}` to external callers. Move full details to a separate admin/internal endpoint with authentication.

### SHIELD-A11-024: AttestationRouter health Endpoint Exposes TEE Measurements
- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-200
- **Location**: `python/shield/integrations/confidential/middleware.py:417-422`
- **Evidence**:
```python
return {
    "status": "healthy",
    "tee_type": self.provider.tee_type.value,
    "in_tee": result.verified,
    "measurements": result.measurements,    # <-- PCR/measurement values
}
```
- **Impact**: The health endpoint (typically unauthenticated) exposes the server's TEE type and all measurement values. An attacker probing the health endpoint learns: (1) whether the server is in a TEE, (2) what TEE type is used, (3) the exact measurement values for the running enclave. The degraded response also confirms "Not running in TEE" which is useful for targeting.
- **Reproduction**: GET `/attestation/health` — no authentication required by default.
- **Fix Complexity**: LOW
- **Remediation**: Return only `{"status": "healthy"}` or `{"status": "degraded"}`. Move TEE details to authenticated endpoint.

### SHIELD-A11-025: Systemic Fail-Open on Encryption Across All Web Frameworks
- **Tag**: VERIFIED
- **Severity**: HIGH
- **CWE**: CWE-636 (Not Failing Securely) + CWE-311 (Missing Encryption)
- **Location**: `python/shield/integrations/fastapi.py:119-134` (ShieldMiddleware.dispatch), `python/shield/integrations/flask.py:136-158` (_after_request), `javascript/integrations/express.js:58-73` (shieldMiddleware), `python/shield/integrations/django/__init__.py:79-89` (ShieldMiddleware.__call__)
- **Evidence**: All 4 web framework integrations follow the SAME pattern:
```
try:
    encrypted = shield.encrypt(response_body)
    return encrypted_response
except Exception:
    return original_plaintext_response   # <-- FAIL-OPEN
```
FastAPI ShieldMiddleware (line 119): No try/except — encrypt failure would crash (slightly better than fail-open). But all 3 explicit frameworks (Flask, Express, Django) catch exceptions and return plaintext.
- **Impact**: Any encrypt failure (memory pressure, RNG failure, library bug) results in sensitive plaintext being sent to the client with NO indication that encryption was skipped. In enterprise deployments where Shield middleware provides the confidentiality guarantee, this is a fundamental security model violation. An attacker who can trigger encrypt failures (e.g., via memory pressure DoS) can force plaintext disclosure.
- **Reproduction**: 1. Deploy Flask/Express/Django with Shield middleware. 2. Trigger encrypt failure (mock, RNG exhaustion, extreme payload size). 3. Observe plaintext JSON in response. 4. No error, no header, no status code change.
- **Fix Complexity**: LOW
- **Remediation**: ALL frameworks must fail-CLOSED: on encrypt failure, return HTTP 500 with a generic error body. NEVER return plaintext when encryption was mandated. Add an `X-Shield-Encrypted: true` response header so clients can verify encryption was applied.
- **Verification Notes**: Consolidates A11-019 (Flask), A11-020 (Express), A11-021 (Django) into one systemic finding. FastAPI ShieldMiddleware does NOT have this specific problem because it doesn't wrap encrypt in try/except — but it also doesn't handle encrypt errors gracefully (crash).

---

## Summary

| Severity | Count | IDs |
|----------|-------|-----|
| HIGH | 5 | A11-005, A11-006, A11-015, A11-016, A11-025 |
| MEDIUM | 14 | A11-001, A11-002, A11-003, A11-007, A11-008, A11-009, A11-010, A11-011, A11-017, A11-018, A11-019, A11-020, A11-021, A11-022, A11-023 |
| LOW | 4 | A11-004, A11-012, A11-013, A11-024 |
| INFO | 1 | A11-014 |
| **Total** | **25** | |

## Cross-References

| Finding | Cross-refs |
|---------|-----------|
| A11-005 | SHIELD-A04-020 (Express decrypt error leak) |
| A11-006 | SHIELD-A04-020, SHIELD-A06-002 (Express plaintext fallback) |
| A11-010 | SHIELD-A07-001 (user enumeration via auth timing) |
| A11-015 | T06 team will assess full crypto oracle feasibility |
| A11-003 | SHIELD-A01-002 (key size as security parameter) |
| A11-016 | SHIELD-A11-005 (FastAPI leak), SHIELD-A04-020 |
| A11-017 | SHIELD-A11-006 (Express leak) |
| A11-018 | SHIELD-A06-001 (Flask fail-open), SHIELD-A04-024 |
| A11-019 | SHIELD-A06-002 (Flask plaintext on error) |
| A11-020 | SHIELD-A06-002 (Express plaintext fallback) |
| A11-021 | SHIELD-A11-019, SHIELD-A11-020 (same pattern across frameworks) |
| A11-022 | SHIELD-A11-008, SHIELD-A11-009 |
| A11-025 | SHIELD-A11-019, A11-020, A11-021, SHIELD-A06-002 |

## Positive Findings

- **Python decrypt()** returns `None` for ALL failures — no error distinction. This is the CORRECT pattern.
- **Go** uses generic error constants without interpolated values for most errors.
- **Swift** uses enum cases without associated values for crypto errors — no data leakage.
- **C** uses integer error codes — minimal info leakage (codes are public in header, but no strings).
- **HMAC comparisons** are constant-time in all 12 implementations (verified in Phase 1, SHIELD-A01-019).
- **Django `shield_required`** returns generic `"Decryption failed"` without exception detail — the SAFEST middleware decrypt error handler.

## Error Propagation Matrix

| Scenario | FastAPI shield_protected | Flask _before_request | Express shieldRequired | Django shield_required |
|----------|------------------------|---------------------|----------------------|---------------------|
| Bad JSON body | 400 + JSONDecodeError detail | Silent pass (fail-open) | 400 "Encrypted request body required" | 400 "Decryption failed" |
| Missing "data" key | 400 + KeyError `'data'` | Silent pass | 400 "Encrypted request body required" | 400 "Encrypted request required" |
| Invalid base64 | 400 + binascii error detail | Silent pass | 400 + null.toString TypeError msg | 400 "Decryption failed" |
| Valid base64, bad decrypt (MAC fail) | **500 TypeError (UNHANDLED!)** | Silent pass | 400 + "Cannot read properties of null" | 400 "Decryption failed" |
| Valid base64, valid decrypt, bad JSON | 400 + JSONDecodeError detail | Silent pass | 400 + SyntaxError detail | 400 "Decryption failed" |
| **Oracle potential** | **500 vs 400 = binary oracle** | **No oracle (all silent)** | **Error msg distinguishes 3 stages** | **No oracle (all generic)** |

**Crypto Oracle Assessment**: FastAPI and Express middlewares are EXPLOITABLE as crypto oracles. Django is SAFE. Flask is fail-open (no oracle but worse: no security).
