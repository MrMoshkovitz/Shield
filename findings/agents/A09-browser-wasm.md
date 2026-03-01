# Agent 09: Browser & WASM Security Assessment

**Agent**: A09 — Browser & WASM
**Phase**: 2
**Priority**: HIGH
**Started**: 2026-03-02T10:00:00+03:00
**Completed**: 2026-03-02T11:00:00+03:00

## Files Audited

| File | Lines | Status |
|------|-------|--------|
| `shield-core/src/wasm.rs` | 362 | COMPLETE |
| `browser/src/lib.rs` | 227 | COMPLETE |
| `browser/js/index.ts` | 250 | COMPLETE |
| `browser/js/fetch-hook.ts` | 131 | COMPLETE |
| `browser/js/types.ts` | 75 | COMPLETE |
| `browser/package.json` | 57 | COMPLETE |
| `browser/Cargo.toml` | 65 | COMPLETE |
| `browser/rollup.config.js` | 65 | COMPLETE |
| `python/shield/integrations/browser.py` | 418 | COMPLETE |

## Cross-References to Prior Findings

The following findings were already reported by A03 (Memory Safety) and are NOT re-reported here:
- **SHIELD-A03-019**: WASM key() exports raw key to JS heap (MEDIUM)
- **SHIELD-A03-020**: WASM linear memory exposes key material (MEDIUM)
- **SHIELD-A03-021**: 4x .unwrap() in WASM bindings (LOW)
- **SHIELD-A03-022**: WasmClient exported directly bypasses SDK safety (LOW)
- **SHIELD-A03-023**: Decrypted plaintext unzeroed in JS GC heap (INFO)
- **SHIELD-A03-024**: forbid(unsafe_code) confirmed (INFO)
- **SHIELD-A03-025**: No key storage in persistent browser storage (INFO)

---

## New Findings

### SHIELD-A09-001: Key Transported in Plaintext JSON Over Fetch — No End-to-End Encryption

- **Tag**: VERIFIED
- **Severity**: HIGH
- **CWE**: CWE-319 (Cleartext Transmission of Sensitive Information)
- **Location**: `browser/js/index.ts:120-131`, `browser/src/lib.rs:63-88`
- **Evidence**:
```typescript
// index.ts:120-131 — Key fetched as plaintext JSON
async refreshKey(): Promise<SessionInfo> {
    const response = await fetch(this.config.keyEndpoint, {
      headers: this.config.keyEndpointHeaders,
      credentials: 'same-origin',
    });
    const keyData: KeyResponse = await response.json();
    this.client.setKey(
      keyData.key,        // Raw key in base64
      keyData.session_id,
      BigInt(keyData.expires_at),
      keyData.service
    );
```
```python
# python/shield/integrations/browser.py:90-101 — Server sends raw key
key_b64 = base64.b64encode(session_key).decode("ascii")
return {
    "key": key_b64,  # Raw key material in JSON response
    "session_id": session_id,
    "expires_at": int(expires_at),
    "algorithm": "shield-v1",
    "service": self.service,
}
```
- **Impact**: The 32-byte session decryption key is sent as base64 in a plain JSON response. Any MITM (if TLS is misconfigured), browser extension, or XSS on the page can intercept the key during fetch. No challenge-response, no ephemeral key exchange. Combined with SHIELD-A03-020 (WASM memory exposure), once stolen all session data is decryptable.
- **Reproduction**: 1) Open DevTools → Network tab. 2) Observe `/api/shield-key` request. 3) Read `key` field from JSON response. 4) Use key with `quick_decrypt` to decrypt all session data.
- **Fix Complexity**: MEDIUM
- **Remediation**: Wrap key response in a Shield-encrypted envelope using a bootstrap key, or use DH key exchange. Document TLS as mandatory.

---

### SHIELD-A09-002: Fetch Hook Returns Original Encrypted Response on Decrypt Error — Fail-Open

- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-636 (Not Failing Securely)
- **Location**: `browser/js/fetch-hook.ts:85-93`
- **Evidence**:
```typescript
// fetch-hook.ts:85-93
    } catch (error) {
      if (onError) {
        onError(error as Error, response);
      } else {
        console.error('Shield decryption error:', error);
      }
      // Return original response on error ← FAIL-OPEN
      return response;
    }
```
- **Impact**: When decryption fails, the encrypted envelope `{"encrypted": true, "data": "base64..."}` is returned to the application as-is. Application code expecting plaintext JSON receives ciphertext structure — causing data leaks if rendered, logic errors, or silent data corruption.
- **Reproduction**: 1) Initialize ShieldBrowser. 2) Wait for key to expire. 3) Make fetch() call to encrypted endpoint. 4) Observe encrypted envelope returned as application data.
- **Fix Complexity**: LOW
- **Remediation**: Return error response (e.g., `new Response(null, { status: 502 })`) instead of encrypted payload. Add `failBehavior` config option.

---

### SHIELD-A09-003: Fetch Hook Returns Encrypted Response When Key Is Expired — Silent Downgrade

- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-636 (Not Failing Securely)
- **Location**: `browser/js/fetch-hook.ts:70-74`
- **Evidence**:
```typescript
// fetch-hook.ts:70-74
      if (!client.isValid()) {
        console.warn('Shield: Key expired or not set, returning encrypted response');
        return response;  // ← Returns encrypted data as-is to application
      }
```
- **Impact**: When key is expired or unset, encrypted envelope passes through silently to the application. Distinct from A09-002 (decrypt errors); this covers the "no valid key" path.
- **Reproduction**: 1) Init with short TTL, disable autoRefresh. 2) Wait past expiry. 3) Fetch encrypted endpoint — encrypted envelope returned.
- **Fix Complexity**: LOW
- **Remediation**: Same as A09-002 — return error response or throw.

---

### SHIELD-A09-004: No WASM Binary Integrity Verification — No SRI Hash

- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-494 (Download of Code Without Integrity Check)
- **Location**: `browser/js/index.ts:19-20`, `browser/package.json:17-19`
- **Evidence**:
```typescript
// index.ts:19-20 — WASM module imported without integrity check
// @ts-ignore - WASM module will be available after build
import init, { ShieldClient as WasmClient } from '../pkg/shield_browser.js';
```
- **Impact**: WASM binary loaded without SRI verification. Compromised CDN or DNS hijack could serve modified WASM that exfiltrates keys. No mechanism to verify WASM binary hash at load time.
- **Reproduction**: 1) Replace `shield_browser_bg.wasm` with modified version. 2) SDK loads tampered WASM without error.
- **Fix Complexity**: MEDIUM
- **Remediation**: Generate SHA-384 hash at build time. Modify init() wrapper to verify hash. Publish expected hashes in npm package.

---

### SHIELD-A09-005: ShieldClient.clear() Does Not Zeroize Key — Relies on GC

- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-226 (Sensitive Information in Resource Not Removed Before Reuse)
- **Location**: `browser/src/lib.rs:196-201`
- **Evidence**:
```rust
// lib.rs:196-201 — clear() sets key to None but doesn't zeroize
pub fn clear(&mut self) {
    self.key = None;       // ← Drops Vec<u8>, bytes remain in WASM linear memory
    self.session_id = None;
    self.expires_at = None;
    self.service = None;
}
```
- **Impact**: Key bytes remain in WASM `ArrayBuffer` after `clear()`. `ShieldClient` in `browser/src/lib.rs` does NOT derive `Zeroize` or `ZeroizeOnDrop`. Key field is bare `Option<Vec<u8>>`. Cross-refs A03-020.
- **Reproduction**: 1) Create ShieldBrowser, fetch key. 2) Call destroy(). 3) Scan WASM memory — key bytes still present.
- **Fix Complexity**: LOW
- **Remediation**: Import `zeroize::Zeroize`, use `Zeroizing<Vec<u8>>` for key field, or manually `key.zeroize()` before setting to None.

---

### SHIELD-A09-006: Fetch Hook Clones Every JSON Response — Memory and Performance DoS

- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-400 (Uncontrolled Resource Consumption)
- **Location**: `browser/js/fetch-hook.ts:44-63`
- **Evidence**:
```typescript
// fetch-hook.ts:44-63 — Every JSON response cloned and parsed
    const contentType = response.headers.get('content-type');
    if (!contentType?.includes('application/json')) {
      return response;
    }
    const clonedResponse = response.clone();  // ← CLONES every JSON response
    try {
      const text = await clonedResponse.text();  // ← READS entire body
      let data: unknown;
      try {
        data = JSON.parse(text);  // ← PARSES entire body
      }
```
- **Impact**: EVERY `application/json` response is cloned (2x memory), read to text, and parsed as JSON — even non-encrypted responses. For large API responses or API-heavy SPAs, significant latency and memory pressure. ~3x memory overhead per JSON response.
- **Reproduction**: 1) Install fetch hook. 2) Fetch 50MB JSON endpoint. 3) Observe ~150MB memory spike.
- **Fix Complexity**: LOW
- **Remediation**: Check for custom header (e.g., `X-Shield-Encrypted: true`) before cloning, or skip responses larger than configurable max size.

---

### SHIELD-A09-007: Fetch Hook Monkey-Patches window.fetch — Incompatible With Other Interceptors

- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-1021 (Improper Restriction of Rendered UI Layers or Frames)
- **Location**: `browser/js/fetch-hook.ts:35-37`
- **Evidence**:
```typescript
// fetch-hook.ts:35-37
  originalFetch = window.fetch;
  window.fetch = async function shieldFetch(
```
- **Impact**: Global monkey-patch conflicts with other fetch interceptors (Sentry, DataDog, auth middleware). Installation order creates unpredictable behavior. uninstallFetchHook() may not correctly restore the original chain.
- **Reproduction**: 1) Install Sentry (patches fetch). 2) Install Shield hook. 3) Uninstall Shield. 4) Sentry's wrapper state is inconsistent.
- **Fix Complexity**: MEDIUM
- **Remediation**: Offer Service Worker alternative or explicit `shieldFetch()` function. Detect pre-existing patches and warn.

---

### SHIELD-A09-008: Key Endpoint URL User-Controlled — No URL Validation

- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-918 (Server-Side Request Forgery)
- **Location**: `browser/js/index.ts:66-72`, `browser/js/index.ts:120-124`
- **Evidence**:
```typescript
// index.ts:66-72 — Arbitrary URL, no validation
static async init(
    keyEndpoint: string,   // ← No validation
    config?: Partial<Omit<ShieldClientConfig, 'keyEndpoint'>>
): Promise<ShieldBrowser> {
// ...
// index.ts:120-124
const response = await fetch(this.config.keyEndpoint, {  // ← Arbitrary URL
    credentials: 'same-origin',
});
```
- **Impact**: Attacker controlling `keyEndpoint` (via config injection, stored XSS) can redirect key fetch to attacker server. SDK accepts any valid key JSON response, enabling decryption with attacker-known key. `credentials: 'same-origin'` mitigates cross-origin cookie theft but same-origin path injection still sends cookies.
- **Reproduction**: 1) `ShieldBrowser.init('https://evil.com/key')`. 2) Attacker returns valid key JSON. 3) SDK accepts and uses attacker's key.
- **Fix Complexity**: LOW
- **Remediation**: Validate keyEndpoint is relative path or same-origin URL. Reject `http://`. Reject URLs with `@`.

---

### SHIELD-A09-009: Singleton Pattern Prevents Multi-Service Use — Stale Key on Re-init

- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-664 (Improper Control of a Resource Through its Lifetime)
- **Location**: `browser/js/index.ts:77-80`
- **Evidence**:
```typescript
// index.ts:77-80
if (ShieldBrowser.instance) {
    console.warn('ShieldBrowser already initialized, returning existing instance');
    return ShieldBrowser.instance;  // ← Ignores new config/endpoint
}
```
- **Impact**: Re-initialization silently returns first instance with original key/config. New keyEndpoint and config are ignored.
- **Fix Complexity**: LOW
- **Remediation**: Auto-destroy old instance on re-init with different config, or throw explicit error.

---

### SHIELD-A09-010: Auto-Refresh Failure Silently Expires Session — No Retry Logic

- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-754 (Improper Check for Unusual or Exceptional Conditions)
- **Location**: `browser/js/index.ts:170-176`
- **Evidence**:
```typescript
// index.ts:170-176
this.refreshTimer = setTimeout(async () => {
    try {
        await this.refreshKey();
    } catch (error) {
        console.error('Shield auto-refresh failed:', error);
        // ← No retry, no re-schedule, no notification
    }
}, delayMs);
```
- **Impact**: Single refresh failure silently disables decryption. No retry, no callback, no recovery.
- **Fix Complexity**: LOW
- **Remediation**: Add retry with exponential backoff. Add `onKeyRefreshError` callback.

---

### SHIELD-A09-011: Decryption Errors Leak Crypto Internals via JsError Messages

- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-209 (Generation of Error Message Containing Sensitive Information)
- **Location**: `browser/src/lib.rs:73`, `browser/src/lib.rs:76-79`, `browser/src/lib.rs:133`, `browser/src/lib.rs:141`
- **Evidence**:
```rust
// lib.rs:73
.map_err(|e| JsError::new(&format!("Invalid base64 key: {}", e)))?;
// lib.rs:76-79
return Err(JsError::new(&format!("Key must be 32 bytes, got {}", key.len())));
// lib.rs:133
.map_err(|e| JsError::new(&format!("Invalid base64 ciphertext: {}", e)))?;
// lib.rs:141
shield_core::quick_decrypt(&key_array, &encrypted)
    .map_err(|e| JsError::new(&format!("Decryption failed: {}", e)))
```
- **Impact**: Errors reveal key size, base64 format, and specific decrypt failure modes. Distinguishable errors may enable oracle attacks. Cross-refs A06, T06.
- **Fix Complexity**: LOW
- **Remediation**: Replace with generic `"Decryption failed"` for all errors in production.

---

### SHIELD-A09-012: No CSP Documentation or Compatibility Testing

- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-1021 (Improper Restriction of Rendered UI Layers or Frames)
- **Location**: `browser/README.md`, `browser/package.json`
- **Evidence**: Zero mentions of "CSP", "Content-Security-Policy", "unsafe-eval", "wasm-unsafe-eval" in browser SDK documentation. WASM requires `'wasm-unsafe-eval'` in CSP `script-src`.
- **Impact**: Enterprise apps with strict CSP will fail to load WASM. Integrators may use overly permissive `'unsafe-eval'`.
- **Fix Complexity**: LOW
- **Remediation**: Document minimum CSP: `script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'`. Add CSP compatibility test.

---

### SHIELD-A09-013: WASM Exports Crypto Primitives to JavaScript

- **Tag**: VERIFIED
- **Severity**: INFO
- **CWE**: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
- **Location**: `shield-core/src/wasm.rs:327-362`
- **Evidence**:
```rust
#[wasm_bindgen(js_name = sha256)]
pub fn wasm_sha256(data: &[u8]) -> Vec<u8> { ... }
#[wasm_bindgen(js_name = hmacSha256)]
pub fn wasm_hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> { ... }
#[wasm_bindgen(js_name = constantTimeEquals)]
pub fn wasm_constant_time_eq(a: &[u8], b: &[u8]) -> bool { ... }
#[wasm_bindgen(js_name = randomBytes)]
pub fn wasm_random_bytes(size: usize) -> Result<Vec<u8>, JsError> { ... }
```
- **Impact**: Expands WASM attack surface. `hmacSha256` with stolen key enables MAC computation.
- **Fix Complexity**: LOW
- **Remediation**: Remove if unused by Browser SDK. Gate behind feature flag.

---

### SHIELD-A09-014: XSS via Decrypted Content — No Output Encoding

- **Tag**: UN-VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-79 (Improper Neutralization of Input During Web Page Generation)
- **Location**: `browser/js/fetch-hook.ts:79-84`, `browser/src/lib.rs:152-179`
- **Evidence**:
```typescript
// fetch-hook.ts:79-84
const decryptedText = client.decryptEnvelope(text);
return new Response(decryptedText, {     // ← Raw decrypted content, no sanitization
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,            // ← Original Content-Type preserved
});
```
- **Impact**: Decrypted content returned as-is with original Content-Type. If app renders decrypted data in DOM without escaping, XSS possible. Requires compromised server or server-side injection. Marked UN-VERIFIED because exploitation requires server compromise + client rendering weakness.
- **Fix Complexity**: LOW
- **Remediation**: Document that decrypted content must still be sanitized. Add `X-Shield-Decrypted: true` header.

---

## Audit Checklist Completion

| # | Check | Status | Finding |
|---|-------|--------|---------|
| 1 | WASM memory accessible to JS | Cross-ref A03-020 | Prior |
| 2 | Fetch hook error paths | FAIL | A09-002, A09-003 |
| 3 | Non-encrypted responses unbroken | PASS | — |
| 4 | SRI for WASM binary | FAIL | A09-004 |
| 5 | CSP documented | FAIL | A09-012 |
| 6 | Key not in global/window scope | PASS | Cross-ref A03-025 |
| 7 | No type confusion TS↔WASM | PASS | — |
| 8 | XSS on decrypted content | UN-VERIFIED | A09-014 |
| 9 | CORS respected by fetch hook | PASS | — |
| 10 | Secure key transport | FAIL | A09-001 |
| 11 | Key zeroization on clear | FAIL | A09-005 |
| 12 | Resource consumption | FAIL | A09-006 |

---

---

## TASK-2-018: Fetch Hook & Auto-Decrypt Security Deep Audit

**Started**: 2026-03-02T12:00:00+03:00
**Completed**: 2026-03-02T13:00:00+03:00

### SHIELD-A09-015: Attacker-Controlled Response Triggers Decrypt Attempt — Error Catch Returns Original Malicious Payload

- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-345 (Insufficient Verification of Data Authenticity)
- **Location**: `browser/js/fetch-hook.ts:53-93`, `browser/src/lib.rs:152-180`
- **Evidence**:
```typescript
// fetch-hook.ts:53-93 — Full intercept flow
try {
    const text = await clonedResponse.text();
    let data: unknown;
    try {
        data = JSON.parse(text);
    } catch {
        return response; // Not JSON
    }
    // Check if it's an encrypted envelope
    if (!isEncryptedEnvelope(data, encryptedIndicator)) {
        return response; // Not encrypted
    }
    // Check if client has valid key
    if (!client.isValid()) {
        return response; // ← Returns attacker payload as-is (A09-003)
    }
    // Decrypt the envelope
    const decryptedText = client.decryptEnvelope(text);
    // ← If MAC fails, falls to catch
    return new Response(decryptedText, { ... });
} catch (error) {
    // ...
    return response; // ← Returns ORIGINAL attacker response to application
}
```
- **Impact**: An attacker (via MITM, DNS hijack, or compromised CDN) who injects `{"encrypted": true, "data": "<base64-junk>"}` into any JSON API response causes the following chain: (1) hook detects `encrypted: true`, (2) attempts WASM decryption which fails MAC verification, (3) catch block returns the ORIGINAL response to the application, (4) application receives `{"encrypted": true, "data": "..."}` as valid data. The application has no way to distinguish "never was encrypted" from "decryption failed silently". This enables response injection attacks where the attacker's payload is accepted as legitimate API data. Cross-refs A09-002 (fail-open pattern).
- **Reproduction**: 1) MITM an API response. 2) Replace body with `{"encrypted": true, "data": "AAAA"}`. 3) Observe: hook tries decrypt → MAC fails → catch returns attacker response → app receives malicious JSON as valid data.
- **Fix Complexity**: LOW
- **Remediation**: On decrypt failure, return an error Response (e.g., 502) instead of the original. Add `X-Shield-Error: decrypt-failed` header. Never pass through a response that claimed to be encrypted but couldn't be decrypted.
- **Verification Notes**: Verified by tracing all code paths through fetch-hook.ts. The catch block at line 85 unconditionally returns `response` (the original) regardless of whether the response claimed to be encrypted. Confirmed in `isEncryptedEnvelope` at line 122-131 that any JSON with `{<indicator>: true, data: <string>}` triggers the decrypt path.

---

### SHIELD-A09-016: decryptEnvelope Passes Non-Encrypted JSON Through Without Validation

- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-345 (Insufficient Verification of Data Authenticity)
- **Location**: `browser/src/lib.rs:152-166`
- **Evidence**:
```rust
// lib.rs:152-166
pub fn decrypt_envelope(&self, envelope_json: &str) -> Result<String, JsError> {
    let envelope: serde_json::Value = serde_json::from_str(envelope_json)
        .map_err(|e| JsError::new(&format!("Invalid JSON: {}", e)))?;

    let is_encrypted = envelope
        .get("encrypted")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !is_encrypted {
        // Not encrypted, return as-is ← BYPASS: returns raw JSON unmodified
        return Ok(envelope_json.to_string());
    }
    // ...
}
```
- **Impact**: If an attacker serves a response with `{"encrypted": false, "data": "malicious"}` or any JSON without the `encrypted` field, `decryptEnvelope()` returns the raw input as-is. However, this path is actually NOT reachable from the fetch hook because `isEncryptedEnvelope` in `fetch-hook.ts:122-131` checks for `encrypted === true` BEFORE calling `decryptEnvelope`. The bypass exists only in the WASM API when `decryptEnvelope` is called directly (via `ShieldBrowser.decryptEnvelope()` at `index.ts:195-197` or via exported `WasmClient`). A malicious proxy returning `{"encrypted": false, ...}` bypasses the WASM `decryptEnvelope` completely, returning unverified attacker JSON.
- **Reproduction**: 1) Call `ShieldBrowser.getInstance().decryptEnvelope('{"encrypted": false, "data": "xss-payload"}')`. 2) Returns `{"encrypted": false, "data": "xss-payload"}` — unverified, no MAC check. 3) App processes attacker data as legitimate.
- **Fix Complexity**: LOW
- **Remediation**: `decryptEnvelope` should return an error when `encrypted` is not `true`, not pass-through. If the caller wants unencrypted data, they should not call `decryptEnvelope`.
- **Verification Notes**: Confirmed in lib.rs lines 163-165. The fetch hook at fetch-hook.ts:66 already pre-filters, but the direct API doesn't. The `ShieldBrowser.decryptEnvelope()` method at index.ts:195 passes through to WASM without the pre-filter.

---

### SHIELD-A09-017: refreshKey() Uses Intercepted fetch() — Potential Self-Decrypt Loop or Key Leak

- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-696 (Incorrect Behavior Order)
- **Location**: `browser/js/index.ts:84-93`, `browser/js/index.ts:120-131`
- **Evidence**:
```typescript
// index.ts:84-93 — Key fetch happens BEFORE hook install on init
static async init(...): Promise<ShieldBrowser> {
    // ...
    await instance.refreshKey();   // ← Uses window.fetch (original at this point)
    if (instance.config.interceptFetch) {
        installFetchHook(          // ← Hook installed AFTER first key fetch
            instance.client,
            // ...
        );
    }
    // ...
}

// index.ts:120-131 — Auto-refresh uses window.fetch (NOW INTERCEPTED)
async refreshKey(): Promise<SessionInfo> {
    const response = await fetch(this.config.keyEndpoint, {  // ← This IS the hooked fetch
        headers: this.config.keyEndpointHeaders,
        credentials: 'same-origin',
    });
    // ...
    const keyData: KeyResponse = await response.json();
    // ...
}
```
- **Impact**: After initial init, `refreshKey()` is called by auto-refresh timer at `index.ts:170`. At this point, `window.fetch` is the hooked version. If the key endpoint response happens to match the encrypted envelope pattern (e.g., key endpoint returns `{"encrypted": true, "data": "..."}` for some reason), the hook will attempt to decrypt the key response using the current (possibly expired) key. Three outcomes: (1) Key is expired → hook passes through encrypted response → `refreshKey` parses it as `KeyResponse` — key field contains ciphertext, not a valid key → silent corruption. (2) Key is valid → hook decrypts the key response → `refreshKey` gets decrypted plaintext instead of the envelope → parsing fails. (3) Infinite recursion if the key endpoint is protected by Shield encryption. Additionally, if an attacker injects `{"encrypted": true, "data": "base64..."}` at the key endpoint, the hook tries to decrypt it and fails, then returns the attacker payload as the key response (per A09-015).
- **Reproduction**: 1) Configure key endpoint to return Shield-encrypted responses. 2) Wait for auto-refresh. 3) Observe: hooked fetch intercepts key response → tries decrypt → fails or succeeds incorrectly → key corruption.
- **Fix Complexity**: LOW
- **Remediation**: Use `originalFetch` for key refresh calls. Store reference to original fetch in ShieldBrowser and bypass hook for internal key management requests.
- **Verification Notes**: Confirmed that `installFetchHook` stores `originalFetch` at fetch-hook.ts:35 but does NOT expose it. `refreshKey()` at index.ts:121 calls bare `fetch()` which is the hooked version after init. The initial init call at line 85 is safe (hook not yet installed), but all subsequent refreshes use the hooked fetch.

---

### SHIELD-A09-018: Decrypted Plaintext Exposed to All Same-Origin Scripts as JS String

- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-316 (Cleartext Storage of Sensitive Information in Memory)
- **Location**: `browser/js/fetch-hook.ts:77-84`, `browser/src/lib.rs:177-179`
- **Evidence**:
```typescript
// fetch-hook.ts:77-84
const decryptedText = client.decryptEnvelope(text);  // ← JS string on heap
return new Response(decryptedText, {                   // ← Creates new Response with plaintext
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,                         // ← Original headers (may include caching)
});
```
```rust
// lib.rs:177-179 — Decrypted bytes converted to UTF-8 string
String::from_utf8(decrypted)
    .map_err(|e| JsError::new(&format!("Decrypted data is not valid UTF-8: {}", e)))
// Returns String → wasm_bindgen converts to JS string on JS heap
```
- **Impact**: Decrypted plaintext crosses the WASM boundary as a JavaScript string. Once on the JS heap: (1) Any same-origin script can access via `Response.text()` or `.json()`. (2) Browser extensions with page access can read it. (3) The JS string is GC-managed — no zeroization possible. (4) Original response headers are preserved including `Cache-Control` — if the server sets caching headers, the *decrypted* response could be stored in the browser's HTTP cache or service worker cache, persisting plaintext on disk. (5) DevTools Network tab shows decrypted body. Cross-refs A03-023 (unzeroed plaintext in JS GC heap).
- **Reproduction**: 1) Init ShieldBrowser. 2) Fetch encrypted endpoint. 3) In DevTools console: `const r = await fetch('/api/secret'); const text = await r.text();` — `text` contains decrypted plaintext. 4) Any injected script can do the same.
- **Fix Complexity**: MEDIUM
- **Remediation**: (1) Strip or override `Cache-Control` header on decrypted responses: `headers.set('Cache-Control', 'no-store')`. (2) Add `X-Shield-Decrypted: true` header so application can differentiate. (3) Document that decrypted data on JS heap is inherent to the architecture and not isolatable without service worker approach.
- **Verification Notes**: Confirmed by tracing data flow: WASM `decryptEnvelope` returns `String` → `wasm_bindgen` converts to JS string → `new Response(decryptedText)` creates response with plaintext body → any consumer of the fetch call gets plaintext. The original response headers at line 83 are passed through unmodified, including any `Cache-Control` headers from the server.

---

### SHIELD-A09-019: encryptedIndicator Is Configurable — Envelope Detection Bypass via Attacker Knowledge

- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-330 (Use of Insufficiently Random Values)
- **Location**: `browser/js/fetch-hook.ts:17-18`, `browser/js/fetch-hook.ts:122-131`, `browser/js/index.ts:47`
- **Evidence**:
```typescript
// fetch-hook.ts:17-18
export function installFetchHook(
    client: WasmClient,
    encryptedIndicator: string = 'encrypted',  // ← Default 'encrypted'
// ...

// types.ts:48-51 — Standard envelope always uses 'encrypted'
export interface EncryptedEnvelope {
    encrypted: true;     // ← Hardcoded field name
    data: string;
}

// fetch-hook.ts:122-131
function isEncryptedEnvelope(data: unknown, indicator: string): data is EncryptedEnvelope {
    // ...
    return obj[indicator] === true && typeof obj['data'] === 'string';
    // ← 'data' field is ALWAYS hardcoded, only the boolean indicator is configurable
}
```
- **Impact**: The `encryptedIndicator` can be changed to a custom field name, but the `data` field is always hardcoded to `"data"`. An attacker who discovers the custom indicator (via source inspection or response observation) can craft targeted payloads. Conversely, if indicator is changed from default `"encrypted"`, the TypeScript `EncryptedEnvelope` type definition becomes inaccurate. The mismatch between configurable indicator and hardcoded `data` field creates inconsistency.
- **Reproduction**: 1) Configure `encryptedIndicator: 'shield_enc'`. 2) Attacker crafts `{"shield_enc": true, "data": "base64..."}`. 3) Hook processes it identically.
- **Fix Complexity**: LOW
- **Remediation**: Document that `encryptedIndicator` is not a security feature. If security-through-obscurity is desired, also make the `data` field name configurable. Better: use a custom response header for detection instead of body inspection.
- **Verification Notes**: Confirmed in `isEncryptedEnvelope` function at fetch-hook.ts:130 — `obj['data']` is hardcoded string literal.

---

### SHIELD-A09-020: No Scheme Validation on keyEndpoint — HTTP Downgrade Leaks Cookies and Key

- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-319 (Cleartext Transmission of Sensitive Information)
- **Location**: `browser/js/index.ts:66-72`, `browser/js/index.ts:120-124`
- **Evidence**:
```typescript
// index.ts:66-72 — keyEndpoint accepted without scheme validation
static async init(
    keyEndpoint: string,  // ← No check for https:// or relative path
    // ...
): Promise<ShieldBrowser> {

// index.ts:120-124
const response = await fetch(this.config.keyEndpoint, {
    headers: this.config.keyEndpointHeaders,
    credentials: 'same-origin',  // ← Sends cookies, but 'same-origin' works for http:// too
});
```
- **Impact**: `credentials: 'same-origin'` sends cookies to the same origin regardless of scheme. If the application is on HTTP (e.g., development, intranet, misconfigured reverse proxy), the session key AND cookies are transmitted in cleartext. This extends A09-001 (plaintext key transport): even with `same-origin`, there's no protection against HTTP downgrade. An attacker on the same network can passively capture the key. Additionally, the `keyEndpointHeaders` are also sent over HTTP, potentially leaking auth tokens.
- **Reproduction**: 1) `ShieldBrowser.init('http://api.local/key')` on HTTP page. 2) Wireshark captures plaintext JSON with `key`, `session_id`, cookies.
- **Fix Complexity**: LOW
- **Remediation**: Check `keyEndpoint` starts with `https://` or is a relative path (inherits page scheme). Reject `http://` explicitly. Log warning if page is on `http://`.
- **Verification Notes**: Confirmed no URL validation exists in `init()` or `refreshKey()`. `credentials: 'same-origin'` per MDN: "Only send credentials if the request URL is on the same origin as the calling script" — but "same origin" includes same-scheme, which for HTTP means HTTP.

---

### SHIELD-A09-021: Fetch Hook Does Not Validate Response Status Before Decrypt — Processes Error Responses

- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-754 (Improper Check for Unusual or Exceptional Conditions)
- **Location**: `browser/js/fetch-hook.ts:42-67`
- **Evidence**:
```typescript
// fetch-hook.ts:42-67
const response = await originalFetch!.call(window, input, init);

// Only process JSON responses
const contentType = response.headers.get('content-type');
if (!contentType?.includes('application/json')) {
    return response;
}
// ← No check for response.ok or response.status
// A 500 error with Content-Type: application/json and encrypted envelope body would be decrypted
const clonedResponse = response.clone();
```
- **Impact**: The hook processes ANY JSON response regardless of HTTP status code. A 4xx/5xx error response that happens to contain `{"encrypted": true, "data": "..."}` in the body (e.g., error pages, debug output) will be processed through the decrypt path. This could lead to: (1) Decryption of error payloads that should remain opaque. (2) Status code mismatch — original 500 status preserved but body changed to decrypted content. (3) Unnecessary WASM computation on error responses.
- **Reproduction**: 1) Server returns HTTP 500 with `Content-Type: application/json` and body `{"encrypted": true, "data": "..."}`. 2) Hook attempts decryption.
- **Fix Complexity**: LOW
- **Remediation**: Add `if (!response.ok) return response;` before cloning. Only process 2xx responses.
- **Verification Notes**: Confirmed by reading fetch-hook.ts lines 42-67 — no status check exists between fetch call and envelope detection.

---

## Summary

| Severity | Count | Finding IDs |
|----------|-------|-------------|
| HIGH | 1 | A09-001 |
| MEDIUM | 12 | A09-002, A09-003, A09-004, A09-005, A09-006, A09-008, A09-014, A09-015, A09-016, A09-017, A09-018, A09-020 |
| LOW | 7 | A09-007, A09-009, A09-010, A09-011, A09-012, A09-019, A09-021 |
| INFO | 1 | A09-013 |
| **Total** | **21** | |

**Prior cross-referenced findings**: 7 (A03-019 through A03-025)
**TASK-2-017 findings**: 14 (SHIELD-A09-001 through SHIELD-A09-014)
**TASK-2-018 findings**: 7 (SHIELD-A09-015 through SHIELD-A09-021)

---

## TASK-2-019: Browser SDK Key Exchange & CSP Deep Audit

**Started**: 2026-03-02T14:00:00+03:00
**Completed**: 2026-03-02T15:00:00+03:00

### SHIELD-A09-022: Key Response Has No Server Signature — Client Cannot Verify Key Authenticity

- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-345 (Insufficient Verification of Data Authenticity)
- **Location**: `python/shield/integrations/browser.py:90-101`, `browser/js/index.ts:130-138`, `browser/src/lib.rs:63-88`
- **Evidence**:
```python
# browser.py:90-101 — Server sends key response with NO signature
key_b64 = base64.b64encode(session_key).decode("ascii")
return {
    "key": key_b64,             # Raw key, no MAC
    "session_id": session_id,
    "expires_at": int(expires_at),
    "algorithm": "shield-v1",
    "service": self.service,
    # ← No HMAC, no signature, no challenge-response token
}
```
```typescript
// index.ts:130-138 — Client accepts key response without verification
const keyData: KeyResponse = await response.json();
this.client.setKey(
    keyData.key,         // ← Accepted as-is, no integrity check
    keyData.session_id,
    BigInt(keyData.expires_at),
    keyData.service
);
```
```rust
// lib.rs:64-88 — set_key validates format but NOT authenticity
pub fn set_key(&mut self, key_b64: &str, ...) -> Result<(), JsError> {
    let key = BASE64.decode(key_b64)...;  // ← Only checks base64 + 32-byte length
    if key.len() != 32 { ... }
    self.key = Some(key);  // ← Accepted without server proof
}
```
- **Impact**: The `KeyResponse` JSON contains no HMAC, digital signature, or challenge-response nonce to prove it came from the legitimate server. Any entity able to inject or modify the HTTP response (MITM, compromised CDN, DNS hijack, or same-origin XSS) can supply a known key. Since `credentials: 'same-origin'` only protects cookies from cross-origin leakage but not response authenticity, the SDK will accept any valid 32-byte key from any source. Combined with A09-001 (plaintext transport) and A09-008 (no URL validation), an attacker can completely control decryption by substituting their own key. The SDK has ZERO cryptographic authentication of the key exchange.
- **Reproduction**: 1) MITM the `/api/shield-key` response. 2) Return `{"key":"AAAA...AA==","session_id":"attacker","expires_at":9999999999,"algorithm":"shield-v1","service":"test"}` with a known 32-byte key. 3) SDK accepts and uses attacker's key. 4) Attacker can now decrypt all responses using their known key.
- **Fix Complexity**: MEDIUM
- **Remediation**: Sign the key response with an HMAC using a bootstrap secret (e.g., from a secure cookie), or implement a DH key exchange where the client contributes a nonce. Minimum: include a server-signed token that the client can verify against a pre-shared public key or bootstrap secret.
- **Verification Notes**: Confirmed by reading all three files in the key exchange chain. `set_key()` in lib.rs only validates base64 decoding and length (32 bytes). No MAC, no signature field in `KeyResponse` type (types.ts:60-75). No verification step in `refreshKey()` (index.ts:120-155).

---

### SHIELD-A09-023: BrowserBridge Session Key Derivation Uses Predictable Input — No Server Nonce

- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-330 (Use of Insufficiently Random Values)
- **Location**: `python/shield/integrations/browser.py:103-111`
- **Evidence**:
```python
# browser.py:103-111
def _derive_session_key(self, session_id: str) -> bytes:
    """Derive a session-specific key."""
    master = self.shield.key      # ← Master key (static per BrowserBridge instance)
    return hmac.new(
        master,
        session_id.encode("utf-8"),  # ← ONLY input: session_id string
        hashlib.sha256,
    ).digest()
```
- **Impact**: Session key = HMAC-SHA256(master_key, session_id). The derivation is entirely deterministic based on `session_id`. If an attacker learns or predicts a `session_id` (they're often UUIDs or session cookies visible in HTTP headers) AND obtains the master key through any other vulnerability (A03-026: key accessor exposure, A06-002: password persistence), they can derive any session's decryption key offline. There is NO server-side random nonce mixed into the derivation — calling `generate_client_key("session123")` twice returns the SAME key. This means: (1) Session key replay is possible if session_id is reused. (2) No forward secrecy — compromising master key compromises ALL past and future session keys. (3) The `expires_at` TTL only limits the client-side validity window; the derived key is valid forever server-side since `encrypt_for_client` and `decrypt_from_client` re-derive fresh each call without checking TTL.
- **Reproduction**: 1) `bridge = BrowserBridge("secret", "api.example.com")`. 2) `k1 = bridge.generate_client_key("session123")`. 3) `k2 = bridge.generate_client_key("session123")`. 4) `k1["key"] == k2["key"]` → True. Same key, no nonce.
- **Fix Complexity**: MEDIUM
- **Remediation**: Mix a random nonce into the key derivation: `HMAC(master, session_id || random_nonce)`. Store and transmit the nonce alongside the key. This ensures each key generation produces a unique key even for the same session_id.
- **Verification Notes**: Confirmed deterministic by reading `_derive_session_key`. The only inputs are the static `self.shield.key` and the caller-provided `session_id`. No random element. `generate_client_key` at line 71-101 doesn't add any randomness.

---

### SHIELD-A09-024: BrowserBridge Session Keys Accumulate Without Auto-Cleanup — Memory Growth DoS

- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-401 (Missing Release of Memory after Effective Lifetime)
- **Location**: `python/shield/integrations/browser.py:69,88,135-144`
- **Evidence**:
```python
# browser.py:69 — Session keys stored in unbounded dict
self._session_keys: Dict[str, tuple[bytes, float]] = {}

# browser.py:88 — Every generate_client_key adds to dict, never auto-removes
self._session_keys[session_id] = (session_key, expires_at)

# browser.py:135-144 — cleanup_expired() exists but is NEVER auto-called
def cleanup_expired(self) -> int:
    """Remove expired session keys. Returns count of removed."""
    now = time.time()
    expired = [
        sid for sid, (_, exp) in self._session_keys.items()
        if now >= exp
    ]
    for sid in expired:
        del self._session_keys[sid]
    return len(expired)
```
- **Impact**: `_session_keys` grows unboundedly. `cleanup_expired()` is a public method but is never called automatically — not from `generate_client_key()`, not from `is_session_valid()`, not from a timer. In a long-running server process handling many browser sessions, this dict grows indefinitely. Each entry is ~40 bytes (32-byte key + float timestamp) plus Python dict overhead (~100 bytes per entry). At 10,000 sessions/hour with 1-hour TTL, after 24 hours: ~240,000 expired entries consuming ~33MB. Not critical alone but contributes to server memory pressure.
- **Reproduction**: 1) Create BrowserBridge. 2) Generate 100,000 client keys with unique session_ids. 3) Observe `len(bridge._session_keys) == 100000` even after TTL expires. 4) Memory not reclaimed until explicit `cleanup_expired()` call.
- **Fix Complexity**: LOW
- **Remediation**: Call `cleanup_expired()` automatically inside `generate_client_key()` or `is_session_valid()` (e.g., probabilistically: `if random() < 0.01: self.cleanup_expired()`). Or use a max-size LRU dict.
- **Verification Notes**: Confirmed by reading all methods. No method in BrowserBridge calls `cleanup_expired()` internally. The method is only available for external callers.

---

### SHIELD-A09-025: BrowserBridge revoke_session Does Not Zeroize Key Bytes — GC-Dependent Cleanup

- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-226 (Sensitive Information in Resource Not Removed Before Reuse)
- **Location**: `python/shield/integrations/browser.py:130-133`
- **Evidence**:
```python
# browser.py:130-133
def revoke_session(self, session_id: str) -> None:
    """Revoke a session key."""
    if session_id in self._session_keys:
        del self._session_keys[session_id]  # ← dict.__delitem__ drops reference
        # ← 32-byte key remains in Python heap until GC collects
        # ← No explicit zeroization of the bytes object
```
- **Impact**: When a session is revoked, `del` removes the dict entry but the `bytes` object containing the 32-byte session key remains in Python's heap memory until garbage collected. Python's `bytes` is immutable — cannot be overwritten in-place. In CPython with reference counting, the object is freed quickly (refcount → 0), but the memory page is NOT zeroed and the bytes persist in the process address space. Heap scanning (e.g., via `/proc/PID/mem`, core dump, or memory forensics) can recover revoked session keys. Cross-refs A03-003 (Python no zeroization).
- **Reproduction**: 1) Generate a client key. 2) Revoke the session. 3) Dump process memory. 4) Search for the 32-byte key pattern — still present.
- **Fix Complexity**: MEDIUM
- **Remediation**: Use `bytearray` instead of `bytes` for session keys (mutable). Before deletion: `key_bytes[:] = b'\x00' * len(key_bytes)`. However, this requires changing `_derive_session_key` to return `bytearray`. Alternative: use `ctypes.memset` on the bytes buffer address.
- **Verification Notes**: Confirmed: `_derive_session_key` returns `hmac.new(...).digest()` which is immutable `bytes`. Dict stores `(bytes, float)` tuple. `del` only removes dict reference, no memory wipe.

---

### SHIELD-A09-026: BrowserBridge TTL Not Enforced on encrypt_for_client/decrypt_from_client

- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-613 (Insufficient Session Expiration)
- **Location**: `python/shield/integrations/browser.py:113-121`
- **Evidence**:
```python
# browser.py:113-121
def encrypt_for_client(self, session_id: str, data: bytes) -> bytes:
    """Encrypt data for a specific client session."""
    session_key = self._derive_session_key(session_id)  # ← Re-derives, no TTL check
    return quick_encrypt(session_key, data)

def decrypt_from_client(self, session_id: str, encrypted: bytes) -> bytes:
    """Decrypt data from a client session."""
    session_key = self._derive_session_key(session_id)  # ← Re-derives, no TTL check
    return quick_decrypt(session_key, encrypted)
```
```python
# browser.py:123-128 — TTL check exists but is separate, never called internally
def is_session_valid(self, session_id: str) -> bool:
    if session_id not in self._session_keys:
        return False
    _, expires_at = self._session_keys[session_id]
    return time.time() < expires_at
```
- **Impact**: `encrypt_for_client()` and `decrypt_from_client()` re-derive the session key from scratch using `_derive_session_key(session_id)`. They do NOT check `is_session_valid()` or the `_session_keys` TTL. This means: (1) Server continues to encrypt/decrypt for a session even after its TTL has expired. (2) Server encrypts/decrypts for sessions that were explicitly revoked via `revoke_session()`. (3) The TTL is purely a client-side enforcement via the browser's `is_valid()` check. Server-side, the key derivation is stateless and eternal. An attacker who obtains a valid session_id can use it indefinitely for server-side decryption — the revocation and TTL mechanisms are client-side only.
- **Reproduction**: 1) Generate key with TTL=60. 2) Wait 120 seconds. 3) Call `bridge.encrypt_for_client("session123", b"data")` — succeeds. 4) Call `bridge.revoke_session("session123")`. 5) Call `bridge.encrypt_for_client("session123", b"data")` — STILL succeeds.
- **Fix Complexity**: LOW
- **Remediation**: Add `if not self.is_session_valid(session_id): raise ValueError("Session expired or revoked")` at the start of `encrypt_for_client()` and `decrypt_from_client()`. This enforces TTL server-side.
- **Verification Notes**: Confirmed by reading both methods — they call `_derive_session_key` directly, which is a pure HMAC computation with no state lookup. The `_session_keys` dict and `is_session_valid()` are never consulted.

---

### SHIELD-A09-027: WASM init() Failure Not Handled — SDK in Broken State Without Error

- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-754 (Improper Check for Unusual or Exceptional Conditions)
- **Location**: `browser/js/index.ts:70-74`
- **Evidence**:
```typescript
// index.ts:70-74
if (!wasmInitialized) {
    await init();          // ← If WASM fails to load (CSP block, network error, corrupt binary)
    wasmInitialized = true;  // ← This line only runs if init() succeeds
}
// BUT: if init() throws, wasmInitialized stays false, AND the error propagates up
// The constructor at line 41: this.client = new WasmClient(); would have already been called...
```
```typescript
// Wait — actually the flow is:
// Line 82: const instance = new ShieldBrowser({ keyEndpoint, ...config }); ← calls constructor
// Constructor line 41: this.client = new WasmClient(); ← This REQUIRES WASM init
// So if WASM init fails, WasmClient constructor also fails
```
- **Impact**: If WASM fails to load (due to CSP `script-src` blocking `wasm-unsafe-eval`, network error, or corrupt binary), `init()` throws and the error propagates to the caller of `ShieldBrowser.init()`. However, the error message is generic (WASM load error) and doesn't guide the developer on CSP requirements. More importantly, after a WASM init failure, `wasmInitialized` stays `false` and subsequent calls to `ShieldBrowser.init()` will retry WASM init — but if the cause is CSP, it will fail every time with no helpful error. There's no fallback mode and no specific CSP detection.
- **Reproduction**: 1) Set CSP: `script-src 'self'` (no `wasm-unsafe-eval`). 2) Call `ShieldBrowser.init('/api/key')`. 3) Get unhelpful WASM error. 4) Retry — same error, no guidance.
- **Fix Complexity**: LOW
- **Remediation**: Wrap `init()` with specific error detection: check for `CompileError` (CSP/invalid WASM) vs `TypeError` (network) and provide actionable error messages: "Add 'wasm-unsafe-eval' to CSP script-src".
- **Verification Notes**: Confirmed `init()` at line 72 is a bare `await` with no try/catch within ShieldBrowser.init(). Error propagates to caller. No CSP-specific error handling.

---

### SHIELD-A09-028: Build Pipeline Generates No WASM Integrity Hashes — No Verifiable Build Artifacts

- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-353 (Missing Support for Integrity Check)
- **Location**: `browser/package.json:22-26`, `browser/rollup.config.js`
- **Evidence**:
```json
// package.json:22-26 — Build scripts, no hash generation
"scripts": {
    "build:wasm": "cd .. && wasm-pack build browser --target web --out-dir browser/pkg",
    "build:js": "rollup -c",
    "build:types": "tsc --emitDeclarationOnly --outDir dist",
    "build": "npm run build:wasm && npm run build:js && npm run build:types",
    // ← No hash generation step
    // ← No "build:integrity" or "postbuild" to generate SRI hashes
    "prepublishOnly": "npm run build"
    // ← prepublishOnly doesn't generate checksums
}
```
```json
// package.json:16-20 — Published files include WASM without hashes
"files": [
    "dist/",   // ← JS bundles, no .integrity file
    "pkg/",    // ← WASM module, no .sha384 file
    "README.md"
]
```
- **Impact**: The npm package ships `pkg/shield_browser_bg.wasm` without any accompanying integrity hash file. Consumers cannot verify the WASM binary matches what was built from the source. Combined with A09-004 (no SRI at load time), there is no integrity verification at any stage: (1) Build time: no hash generated. (2) Publish time: no hash included in package. (3) Install time: npm `integrity` field in `package-lock.json` covers the tarball but not individual WASM files. (4) Load time: no SRI check. A supply chain attacker who modifies `shield_browser_bg.wasm` in the npm registry would go undetected.
- **Reproduction**: 1) `npm pack @guard8/shield-browser`. 2) Extract tarball. 3) No `.sha384`, `.integrity`, or hash manifest file present. 4) Modify `shield_browser_bg.wasm` — no verification fails.
- **Fix Complexity**: LOW
- **Remediation**: Add `"postbuild": "shasum -a 384 pkg/shield_browser_bg.wasm | base64 > pkg/shield_browser_bg.wasm.sha384"` to build scripts. Ship the hash file. Document how consumers can verify. Better: generate an `integrity.json` manifest with SRI hashes for all artifacts.
- **Verification Notes**: Confirmed by reading package.json scripts and rollup.config.js — no integrity-related steps. The `files` array includes raw `pkg/` directory.

---

### SHIELD-A09-029: ShieldBrowser Exports WasmClient and Fetch Hook Utilities — Expanded Attack Surface

- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
- **Location**: `browser/js/index.ts:243-247`
- **Evidence**:
```typescript
// index.ts:243-247 — Exports bypass the SDK's safety layer
export { WasmClient as ShieldClient };
export { installFetchHook, uninstallFetchHook, isFetchHookInstalled };
```
- **Impact**: The npm package exports `WasmClient` (renamed `ShieldClient`) and all fetch hook functions. This allows consumers (or attackers with same-origin JS execution) to: (1) Create standalone `WasmClient` instances that bypass `ShieldBrowser` singleton pattern. (2) Install additional fetch hooks with different configs. (3) Uninstall the legitimate fetch hook via `uninstallFetchHook()`. (4) Call `WasmClient.setKey()` with an attacker-controlled key. Cross-refs A03-022 (WasmClient exported), A09-013 (WASM exports crypto primitives).
- **Reproduction**: 1) `import { ShieldClient, uninstallFetchHook } from '@guard8/shield-browser'`. 2) `uninstallFetchHook()` — disables auto-decrypt. 3) `const c = new ShieldClient(); c.setKey(attackerKey, ...)` — installs attacker key.
- **Fix Complexity**: LOW
- **Remediation**: Don't re-export `WasmClient` and fetch hook utilities from the main entry point. Expose only `ShieldBrowser` class. If advanced usage is needed, export from a separate `@guard8/shield-browser/advanced` entry point.
- **Verification Notes**: Confirmed at index.ts lines 243-247. These are direct module exports, fully accessible to any code importing the package.

---

## Updated Summary

| Severity | Count | Finding IDs |
|----------|-------|-------------|
| HIGH | 1 | A09-001 |
| MEDIUM | 16 | A09-002, A09-003, A09-004, A09-005, A09-006, A09-008, A09-014, A09-015, A09-016, A09-017, A09-018, A09-020, A09-022, A09-023, A09-026 |
| LOW | 11 | A09-007, A09-009, A09-010, A09-011, A09-012, A09-019, A09-021, A09-024, A09-025, A09-027, A09-028, A09-029 |
| INFO | 1 | A09-013 |
| **Total** | **29** | |

**Prior cross-referenced findings**: 7 (A03-019 through A03-025)
**TASK-2-017 findings**: 14 (SHIELD-A09-001 through SHIELD-A09-014)
**TASK-2-018 findings**: 7 (SHIELD-A09-015 through SHIELD-A09-021)
**TASK-2-019 findings**: 8 (SHIELD-A09-022 through SHIELD-A09-029)

**A09 COMPLETE** — 29 total findings across 3 tasks.
