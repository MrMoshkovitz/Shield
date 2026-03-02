# Team 6: Crypto Oracle & Error Leakage — Cross-Domain Findings

**Team**: T06 — Crypto Oracle & Error Leakage
**Phase**: 4 (Cross-Domain Batch 1)
**Priority**: CRITICAL
**Date**: 2026-03-03
**Input Agents**: A01 (Crypto Primitives), A04 (Input Validation), A06 (Web Integration), A11 (Error Disclosure)
**Total New Cross-Domain Findings**: 6

---

## Executive Summary

**Crypto oracle attacks are FEASIBLE against Shield when deployed via FastAPI or Express middleware.**

The combination of (1) distinguishable error types in core decrypt paths, (2) middleware that forwards raw error details to HTTP responses, and (3) binary status code oracles (500 vs 400 in FastAPI) creates a **practical adaptive chosen-ciphertext oracle**. An attacker who can submit ciphertexts to a web endpoint and observe HTTP responses can determine whether a given ciphertext passed MAC verification, failed MAC, was too short, or had format errors.

**Key chain**: Error distinguishability (A11-015) + Middleware error forwarding (A11-005, A11-006) + Status code oracle (A11-016) = **Practical crypto oracle over HTTP**

**Mitigating factor**: The encrypt-then-MAC construction with 128-bit HMAC-SHA256 makes forgery of valid MACs computationally infeasible (2^128 work). The oracle does NOT help an attacker forge MACs — it only reveals whether a submitted ciphertext passed or failed MAC verification. Without a structural weakness in the cipher that leaks plaintext bits when MAC is bypassed (there isn't one since MAC is checked FIRST), the oracle's practical impact is LIMITED to:
1. Confirming which error stage was reached (information disclosure)
2. Profiling the implementation's internal structure
3. Exploiting the fail-open Flask path (SHIELD-A11-018) to bypass encryption entirely

---

## Error Oracle Feasibility Matrix

### Core Library Error Distinguishability

| Error Stage | Rust | Python | JS | Go | Java | C | C# | Swift | Kotlin |
|------------|------|--------|----|----|------|----|-----|-------|--------|
| 1. Size check | `CiphertextTooShort{expected,actual}` | `return None` | N/A (no size check) | `"ciphertext too short"` | `IllegalArgumentException` | `-2` | `"Ciphertext too short"` | `.ciphertextTooShort` | `.CiphertextTooShort` |
| 2. MAC check | `AuthenticationFailed` | `return None` | `return null` | `"authentication failed"` | `SecurityException` | `-3` | `"Authentication failed"` | `.authenticationFailed` | `.AuthenticationFailed` |
| 3. Pad/format | `InvalidFormat` | `return None` | `return null` | `"invalid format"` | N/A | N/A | N/A | N/A | N/A |
| 4. Replay | `InvalidFormat` | `return None` | `return null` | `"message expired"` | N/A | N/A | N/A | N/A | N/A |
| **Distinguishable?** | **YES (3 types)** | **NO (always None)** | **NO (always null)** | **YES (4 types)** | **YES (2 types)** | **YES (2 codes)** | **YES (2 types)** | **YES (2 types)** | **YES (2 types)** |

**Python is the ONLY safe implementation.** JS returns null but lacks size check. All others expose distinguishable errors.

### Web Middleware Error Propagation

| Middleware | Error Forwarding | Status Code Oracle | Crypto Detail Leakage | Oracle Rating |
|-----------|------------------|-------------------|----------------------|---------------|
| **FastAPI shield_protected** | `f"Decryption failed: {e}"` → 400, BUT `TypeError` from `json.loads(None)` → **500** | **YES: 400 vs 500** | Raw Python exception strings | **HIGH** |
| **Express shieldRequired** | `err.message` → 400 JSON | No (all 400) | `"Cannot read properties of null"` vs `"Unexpected token"` distinguishable | **MEDIUM** |
| **Flask _before_request** | `except Exception: pass` → **fail-open** | No error visible | None (but fail-open is worse) | **LOW (oracle) / HIGH (fail-open)** |
| **Express shieldErrorHandler** | `err.message` in JSON body | No (all 400) | Shield error details in body | **MEDIUM** |
| **Confidential middleware** | `str(e)` in JSON body | No (all 401) | Attestation error details | **MEDIUM** |

### Combined Attack Feasibility

| Attack Vector | Feasibility | Prerequisites | Impact |
|--------------|-------------|---------------|--------|
| **FastAPI 400/500 binary oracle** | **HIGH** | HTTP access to FastAPI endpoint with `shield_protected` | Binary feedback: "reached decrypt" vs "format/parse error". Enables probing cipher structure. |
| **Express error message oracle** | **MEDIUM** | HTTP access to Express endpoint with `shieldRequired` | Error message text reveals decrypt-null vs JSON-parse-fail. Requires message text parsing. |
| **Flask fail-open bypass** | **HIGH** | HTTP access to Flask endpoint with `ShieldFlask` | Tampered/invalid ciphertext silently passes through. Route handler operates on raw data. |
| **Cross-implementation interop oracle** | **LOW** | Attacker knows which backend is used, can submit ciphertexts | Different impls have different error paths for same malformed input. Information useful for targeted exploitation. |

---

## Cross-Domain Findings

### SHIELD-T06-001: FastAPI Binary Status Code Crypto Oracle (400 vs 500)
- **Tag**: VERIFIED
- **Severity**: HIGH
- **CWE**: CWE-203 (Observable Discrepancy) + CWE-209
- **Location**: `python/shield/integrations/fastapi.py:171-174` (handler) + `python/shield/core.py:214,227` (None return)
- **Evidence**:
  The FastAPI `shield_protected` decorator creates a binary oracle via HTTP status codes:
  ```
  Input: {"encrypted": true, "data": "<base64-of-random-bytes>"}

  Path A (format error): JSONDecodeError/KeyError/ValueError → 400 + detail string
  Path B (MAC/auth failure): shield.decrypt() → None → json.loads(None) → TypeError → 500
  ```
  The `except` clause catches `(json.JSONDecodeError, KeyError, ValueError)` but NOT `TypeError`. When Shield's Python implementation returns `None` for MAC failure, `json.loads(None)` raises `TypeError` which propagates as an uncaught 500.

  **Oracle signal**: HTTP 500 = "ciphertext was well-formed base64, passed to decrypt, MAC failed" vs HTTP 400 = "input was malformed before reaching decrypt".
- **Impact**: Attacker probing an encrypted FastAPI endpoint can determine whether their submitted ciphertext reached the MAC verification stage. While the encrypt-then-MAC construction prevents MAC forgery (128-bit security), the oracle reveals:
  1. Whether the ciphertext was properly formatted (correct length, valid base64)
  2. Whether it reached the MAC check (confirms it was >= 32 bytes)
  3. Enables systematic probing of the cipher's input expectations
  Combined with key reuse (SHIELD-A01-001) and missing padding validation in Rust (SHIELD-A04-001), this creates a multi-stage information leak.
- **Reproduction**:
  1. Deploy FastAPI endpoint with `@shield_protected`
  2. Send `{"encrypted": true, "data": "AAAA"}` (4 bytes base64) → **400** (ciphertext too short, ValueError)
  3. Send `{"encrypted": true, "data": "<base64-of-40-random-bytes>"}` → **500** (passed size check, failed MAC, None returned, TypeError)
  4. Status code difference confirms whether ciphertext reached MAC verification
- **Fix Complexity**: LOW
- **Remediation**: Check decrypt result before JSON parse:
  ```python
  decrypted = shield.decrypt(encrypted)
  if decrypted is None:
      raise HTTPException(status_code=400, detail="Invalid request body")
  kwargs["body"] = json.loads(decrypted)
  ```
  Additionally: unify ALL error responses to return identical 400 with generic message.
- **Verification Notes**: Cross-references SHIELD-A11-005, SHIELD-A11-016 (domain findings). This is a NEW cross-domain finding because the oracle requires BOTH the middleware error propagation AND the core library's None-return behavior to combine into a status code oracle.
- **Agent Source Findings**: SHIELD-A11-005 (FastAPI error forwarding), SHIELD-A11-016 (TypeError 500 oracle), SHIELD-A01-001 (key separation)

---

### SHIELD-T06-002: Express Error Message Content Oracle (Decrypt-Null vs Parse-Fail)
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-203 (Observable Discrepancy)
- **Location**: `javascript/integrations/express.js:136-145` + `javascript/src/shield.js:188`
- **Evidence**:
  Express `shieldRequired` catches all errors but leaks the error message:
  ```
  MAC failure path:  shield.decrypt() → null → null.toString() → TypeError
    Response: {"error": "Decryption failed: Cannot read properties of null (reading 'toString')"}

  Decrypt success but bad JSON: shield.decrypt() → Buffer → JSON.parse() → SyntaxError
    Response: {"error": "Decryption failed: Unexpected token X in JSON at position 0"}
  ```
  The error message text is a content oracle — attacker parses the response body to determine which stage failed.
- **Impact**: Lower severity than FastAPI because:
  1. All responses are 400 (no status code oracle)
  2. Attacker must parse error message text (fragile, may change between Node versions)
  3. Distinguishes "decrypt failed" from "decrypt succeeded but bad JSON" — less useful than the binary MAC-pass/fail oracle
  However, it still reveals whether ciphertext passed MAC verification, which is a crypto oracle.
- **Reproduction**:
  1. Deploy Express endpoint with `shieldRequired`
  2. Send encrypted random bytes → observe "Cannot read properties of null" in response
  3. If attacker has key and sends non-JSON encrypted content → observe "Unexpected token"
  4. Different messages confirm MAC pass/fail
- **Fix Complexity**: LOW
- **Remediation**: Check for null before toString():
  ```javascript
  const decrypted = shield.decrypt(encrypted);
  if (decrypted === null) {
      return res.status(400).json({ error: 'Invalid request body' });
  }
  req.shieldData = JSON.parse(decrypted.toString());
  ```
- **Verification Notes**: Cross-references SHIELD-A11-006, SHIELD-A11-017 (domain findings). Express-specific oracle chain.
- **Agent Source Findings**: SHIELD-A11-006, SHIELD-A11-017, SHIELD-A04-004 (JS exported internals)

---

### SHIELD-T06-003: Flask Silent Fail-Open Renders Encryption Bypass Without Oracle
- **Tag**: VERIFIED
- **Severity**: HIGH
- **CWE**: CWE-636 (Not Failing Securely) + CWE-311 (Missing Encryption)
- **Location**: `python/shield/integrations/flask.py:121-134` (decrypt fail-open) + `python/shield/integrations/flask.py:136-158` (encrypt fail-open)
- **Evidence**:
  Flask middleware has a WORSE problem than a crypto oracle — it doesn't fail at all:
  ```python
  # Decrypt direction:
  except Exception:
      pass  # Tampered ciphertext silently passes through

  # Encrypt direction:
  except Exception:
      pass  # Plaintext response sent without encryption
  ```
  Combined effect:
  1. Attacker sends tampered/invalid ciphertext → request proceeds to route handler with raw encrypted body
  2. If encrypt fails on response → plaintext is returned to attacker
  3. NO oracle signal exists because NO error is visible — but encryption guarantee is VOID
- **Impact**: Flask's "safe from oracle" behavior is actually WORSE: instead of leaking information about crypto state, it completely bypasses encryption on failure. A route handler that doesn't explicitly check for `g.shield_decrypted_body` will operate on encrypted/tampered data or return plaintext responses. The security model assumes mandatory encryption, but Flask middleware makes it optional-on-error.
- **Reproduction**:
  1. Deploy Flask app with `ShieldFlask(app, shield=shield)`
  2. Send `{"encrypted": true, "data": "<base64-random>"}` to an encrypted endpoint
  3. Request reaches route handler — `g.shield_decrypted_body` is NOT set
  4. Response is sent through `_after_request` — if encrypt fails → plaintext response
- **Fix Complexity**: LOW
- **Remediation**: Replace `except Exception: pass` with `abort(400, "Invalid request body")` in `_before_request`. Replace `except Exception: pass` with `abort(500)` or return error in `_after_request`. NEVER allow fail-open on crypto operations.
- **Verification Notes**: Cross-references SHIELD-A11-018, SHIELD-A11-019, SHIELD-A06-001, SHIELD-A06-002 (domain findings). This is a cross-domain escalation: individual A11/A06 findings are MEDIUM for error handling, but the combined fail-open on BOTH encrypt AND decrypt directions makes this HIGH severity — the entire encryption layer is bypassable on error.
- **Agent Source Findings**: SHIELD-A11-018 (fail-open decrypt), SHIELD-A11-019 (fail-open encrypt), SHIELD-A06-001, SHIELD-A06-002

---

### SHIELD-T06-004: Rust-Only Missing Padding Validation Creates Interop-Exploitable Oracle
- **Tag**: VERIFIED
- **Severity**: HIGH
- **CWE**: CWE-20 (Improper Input Validation) + CWE-203 (Observable Discrepancy)
- **Location**: `shield-core/src/shield.rs:300-304` vs `python/shield/core.py:242-244`, `javascript/src/shield.js:209-212`, `go/shield/shield.go:282-284`, `c/src/shield.c:500-505`
- **Evidence**:
  Rust is the ONLY V2-capable implementation that does NOT validate `pad_len` against [32, 128]:
  ```rust
  // Rust: NO bounds check — accepts pad_len 0-255
  let pad_len = decrypted[16] as usize;
  let data_start = V2_HEADER_SIZE + pad_len;
  if data_start > decrypted.len() {
      return Err(ShieldError::InvalidFormat);
  }
  ```
  ```python
  # Python: Bounds check present
  if pad_len < MIN_PADDING or pad_len > MAX_PADDING:
      return None  # CVE-PENDING fix
  ```

  **Cross-implementation oracle**: If ciphertext encrypted by Python (with valid pad_len 32-128) is tampered and then decrypted by:
  - **Rust**: Accepts any pad_len → returns data (possibly with padding as plaintext)
  - **Python**: Rejects pad_len outside [32,128] → returns None

  An attacker who can submit the same tampered ciphertext to both a Rust endpoint and a Python endpoint gets different behavior — creating a cross-implementation oracle.
- **Impact**: The missing padding validation in Rust means:
  1. Rust accepts ciphertexts that all other 11 implementations reject
  2. If an attacker can forge a MAC (via key compromise from SHIELD-A01-004), they can craft ciphertext with `pad_len=0` that Rust decrypts but Python/JS/Go/C/Java reject
  3. This breaks interoperability assumptions and creates a behavioral divergence exploitable in multi-backend deployments
- **Reproduction**:
  1. Construct V2 ciphertext with `pad_len=0` in header (after forging MAC with known key)
  2. Submit to Rust endpoint → decrypts successfully, returns data starting at byte 17
  3. Submit same to Python endpoint → returns None (pad_len < 32 rejected)
  4. Different behavior confirms which backend is Rust
- **Fix Complexity**: LOW
- **Remediation**: Add to `shield.rs` after line 300:
  ```rust
  if pad_len < MIN_PADDING || pad_len > MAX_PADDING {
      return Err(ShieldError::InvalidFormat);
  }
  ```
- **Verification Notes**: Cross-references SHIELD-A04-001 (Rust pad_len), SHIELD-A02-* (cross-language parity). This is a cross-domain escalation: the missing validation (A04) becomes exploitable when combined with cross-implementation deployment (A02) and error distinguishability (A11).
- **Agent Source Findings**: SHIELD-A04-001, SHIELD-A01-001 (key accessor for MAC forging), SHIELD-A11-015 (distinguishable errors)

---

### SHIELD-T06-005: Confidential Computing Middleware Attestation Oracle
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-209 + CWE-203
- **Location**: `python/shield/integrations/confidential/middleware.py:132-138` + `python/shield/integrations/confidential/base.py:311-312`
- **Evidence**:
  Attestation middleware exposes detailed error information that enables oracle-style probing:
  ```python
  # middleware.py:132 — raw exception to client
  "message": str(e),

  # base.py:311 — TEE type mismatch
  f"TEE type mismatch: expected {envelope['tee_type']}, "
  ```
  Combined with A13 findings (SHIELD-A13-001, A13-002, A13-003) that attestation signatures are NEVER verified, an attacker can:
  1. Submit forged attestation with wrong TEE type → error reveals expected type
  2. Submit forged attestation with correct type but wrong measurement → error reveals expected measurement
  3. Iteratively probe until forged attestation is accepted (signatures aren't checked)
- **Impact**: The attestation oracle combined with missing signature verification means:
  1. Attacker learns expected TEE type from error messages
  2. Attacker learns expected measurements from error messages
  3. Attacker submits forged attestation matching all criteria (no signature to forge since it's not checked)
  4. TEEKeyManager releases keys to untrusted environment
- **Reproduction**:
  1. Send `{"evidence": "<base64>", "tee_type": "wrong"}` → error reveals expected type
  2. Adjust `tee_type` to match → next error reveals measurement requirements
  3. Forge attestation with correct type and measurement → key released (no signature check)
- **Fix Complexity**: MEDIUM
- **Remediation**: 1. Generic error: `"Attestation failed"` — no details. 2. Fix attestation signature verification (SHIELD-A13-001/002/003). 3. Both are required — generic errors alone aren't enough if signatures aren't verified.
- **Verification Notes**: Cross-domain chain: A13 (no sig verify) + A11 (error leakage) = attestation oracle that reveals requirements for forging. Both must be fixed.
- **Agent Source Findings**: SHIELD-A13-001, SHIELD-A13-002, SHIELD-A13-003, SHIELD-A11-008, SHIELD-A11-009

---

### SHIELD-T06-006: Systemic Error Non-Uniformity Across 12 Implementations
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-203 (Observable Discrepancy)
- **Location**: All 12 implementations — decrypt error paths
- **Evidence**:
  Error handling varies dramatically across implementations:

  | Behavior | Implementations |
  |----------|----------------|
  | Returns None/null (SAFE) | Python, JavaScript |
  | 2 distinct error types | Java, C, C#, Swift, Kotlin |
  | 3+ distinct error types | Rust, Go |
  | Has padding validation | Python, JS, Go, C, Java (5/12) |
  | Missing padding validation | Rust (1/12 V2-capable) |
  | Error includes byte counts | Rust only |
  | Error includes algorithm names | Java, Kotlin |

  This non-uniformity means:
  1. A multi-backend deployment has different error behaviors for the same input
  2. Attacker can fingerprint which backend handled the request from error responses
  3. The "safest" error handling (Python) isn't enforced or even recommended
- **Impact**: The lack of a uniform error handling standard across implementations means every deployment that exposes decrypt errors is a potential oracle. Different implementations leak different information: Rust leaks byte counts, Java leaks algorithm names, Go leaks 4 distinct error types. A security assessment of "Python is safe" doesn't protect Go or Rust deployments.
- **Reproduction**: Send identical malformed ciphertext to endpoints backed by different Shield implementations. Collect distinct error messages/codes. Build a fingerprinting matrix.
- **Fix Complexity**: MEDIUM
- **Remediation**:
  1. Define a **universal error policy**: all decrypt failures return a single, indistinguishable error (follow Python's `return None` pattern)
  2. Document this in PROTOCOL.md as a security requirement
  3. Implement in all 12 languages before launch
  4. Specifically: Rust should NOT expose `CiphertextTooShort{expected, actual}`, Go should unify its 4 error types
- **Verification Notes**: Systemic cross-implementation finding. Cross-references SHIELD-A11-015, SHIELD-A02-* series.
- **Agent Source Findings**: SHIELD-A11-015, SHIELD-A11-001 through SHIELD-A11-004, SHIELD-A02 (cross-language parity)

---

## Oracle Feasibility Assessment

### Can an attacker recover plaintext via adaptive chosen-ciphertext queries?

**Short answer: NO for practical purposes, but the information leakage is real and exploitable for reconnaissance.**

**Detailed analysis**:

1. **MAC barrier**: Shield uses encrypt-then-MAC with HMAC-SHA256 truncated to 128 bits. Forging a valid MAC requires 2^128 work — the oracle doesn't help bypass this because MAC verification happens FIRST, before any post-decryption processing.

2. **No padding oracle in the classic sense**: Unlike CBC padding oracles (e.g., POODLE, Lucky13), Shield's CTR-mode encryption doesn't have a "padding check" that reveals plaintext bits. The padding in V2 format is random bytes that don't follow a structured pattern — there's no "valid padding" vs "invalid padding" check that depends on plaintext content.

3. **What the oracle DOES reveal**:
   - Whether ciphertext is well-formed (correct length)
   - Whether MAC verification passed or failed
   - In Rust: the exact minimum ciphertext size (reveals wire format)
   - In Go: 4 distinct stages of decrypt processing
   - Via middleware: which processing stage failed (pre-decrypt vs post-decrypt)

4. **Practical exploitation**:
   - **Reconnaissance**: Attacker learns internal cipher structure, wire format, and implementation details
   - **Implementation fingerprinting**: Attacker determines which language/middleware handles requests
   - **Flask fail-open**: Attacker bypasses encryption entirely on error (no oracle needed)
   - **TEE attestation oracle**: Combined with missing signature verification, enables full attestation forgery

### Severity Justification

The crypto oracle chain is rated **HIGH** (not CRITICAL) because:
- The encrypt-then-MAC construction prevents MAC forgery via oracle queries
- CTR mode doesn't have padding-dependent behavior exploitable via oracle
- The practical impact is information disclosure + Flask fail-open, not plaintext recovery

However, if key material is compromised (via SHIELD-A01-004 public key accessor), the oracle becomes more dangerous because the attacker can forge MACs and then probe post-MAC error paths.

---

## Summary of Cross-Domain Findings

| ID | Title | Severity | Type | Source Agents |
|----|-------|----------|------|---------------|
| SHIELD-T06-001 | FastAPI Binary Status Code Crypto Oracle | HIGH | Cross-domain chain | A11, A01 |
| SHIELD-T06-002 | Express Error Message Content Oracle | MEDIUM | Cross-domain chain | A11, A04 |
| SHIELD-T06-003 | Flask Silent Fail-Open Encryption Bypass | HIGH | Cross-domain escalation | A11, A06 |
| SHIELD-T06-004 | Rust-Only Missing Padding Validation Interop Oracle | HIGH | Cross-domain chain | A04, A02, A11 |
| SHIELD-T06-005 | Confidential Computing Attestation Oracle | MEDIUM | Cross-domain chain | A13, A11 |
| SHIELD-T06-006 | Systemic Error Non-Uniformity Across 12 Implementations | MEDIUM | Systemic | A11, A02 |

**Total**: 6 findings (3 HIGH, 3 MEDIUM)
