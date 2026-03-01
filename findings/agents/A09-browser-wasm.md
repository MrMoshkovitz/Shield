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

## Summary

| Severity | Count | Finding IDs |
|----------|-------|-------------|
| HIGH | 1 | A09-001 |
| MEDIUM | 7 | A09-002, A09-003, A09-004, A09-005, A09-006, A09-008, A09-014 |
| LOW | 5 | A09-007, A09-009, A09-010, A09-011, A09-012 |
| INFO | 1 | A09-013 |
| **Total** | **14** | |

**Prior cross-referenced findings**: 7 (A03-019 through A03-025)
**New findings this agent**: 14 (SHIELD-A09-001 through SHIELD-A09-014)
