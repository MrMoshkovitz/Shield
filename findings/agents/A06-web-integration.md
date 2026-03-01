# A06 — Web Integration Security Findings

**Agent**: A06 (Web Integration)
**Phase**: 2 (Protocol & App & Infra)
**Priority**: HIGH
**Date**: 2026-03-02
**Tasks**: TASK-2-007 (12 findings), TASK-2-008 (6 findings), TASK-2-009 (8 findings)
**Total**: 26 findings (1 HIGH, 14 MEDIUM, 9 LOW, 2 INFO)

---

## TASK-2-007 Findings (A06-001 through A06-012) — see SECURITY_REPORT.md

> Written directly to SECURITY_REPORT.md during iteration 21.
> Cross-reference: SHIELD-A06-001 through SHIELD-A06-012.

---

## TASK-2-008 Findings — Flask Decorators, FlaskAPIKeyAuth, Route Exclusion Bypass

### SHIELD-A06-013: Flask `_should_process` Route Exclusion Bypass via Path Encoding/Traversal
- **Severity**: MEDIUM
- **CWE**: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- **Location**: `python/shield/integrations/flask.py:112`
- **Evidence**:
```python
def _should_process(self, path: str) -> bool:
    # Skip excluded routes
    if any(path.startswith(prefix) for prefix in self.exclude_routes):
        return False
```
- **Impact**: Route exclusion uses raw `request.path` with `startswith()`. Depending on WSGI server normalization behavior:
  - URL-encoded paths (`/%73tatic/foo` for `/static/foo`) may bypass exclusion but resolve to excluded route
  - Case mismatch (`/Static/` vs `/static`) — `startswith` is case-sensitive, some proxies/servers normalize case
  - Prefix over-match: `/staticx` is excluded when only `/static` was intended (no trailing slash enforcement)
  - An attacker could craft a request path that bypasses exclusion but gets routed to an excluded endpoint, causing encryption to be applied where it shouldn't be (or vice versa)
- **Reproduction**:
  1. Configure `exclude_routes=["/health"]`
  2. Send request to `/%68ealth` (URL-encoded `/health`)
  3. If WSGI server passes encoded path to Flask, `_should_process` returns `True` (encryption applied to health endpoint)
- **Fix Complexity**: LOW
- **Remediation**: Normalize `request.path` before comparison — URL-decode, lowercase, strip trailing slashes. Use `request.url_rule` or pattern matching instead of prefix strings.

### SHIELD-A06-014: Express Path Matching Bypass via Encoding/Traversal
- **Severity**: MEDIUM
- **CWE**: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- **Location**: `javascript/integrations/express.js:46-50`
- **Evidence**:
```javascript
if (paths && !paths.some(p => req.path.startsWith(p))) {
    return next();
}
if (excludePaths && excludePaths.some(p => req.path.startsWith(p))) {
    return next();
}
```
- **Impact**: Same as SHIELD-A06-013. Express `req.path` is URL-decoded by Express but:
  - Double-encoding (`%252F`) can bypass normalization
  - Case sensitivity issues persist (`/Api` vs `/api`)
  - Prefix over-match: `excludePaths=["/api"]` also excludes `/api-docs`, `/api-internal`, etc.
  - No path normalization removes `/../` sequences before comparison
- **Reproduction**:
  1. Configure `excludePaths: ["/health"]`
  2. Send request to `/api/../health`
  3. Express normalizes for routing but `req.path` may retain the traversal, causing `startsWith` to miss
- **Fix Complexity**: LOW
- **Remediation**: Use `path.normalize()` or Express route matching patterns instead of string prefix comparison. Compare against `req.route.path` after routing resolution.

### SHIELD-A06-015: FlaskAPIKeyAuth No Rate Limiting or Brute-Force Detection
- **Severity**: MEDIUM
- **CWE**: CWE-307 (Improper Restriction of Excessive Authentication Attempts)
- **Location**: `python/shield/integrations/flask.py:393-408`
- **Evidence**:
```python
def required(self, func: Callable) -> Callable:
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        api_key = request.headers.get(self.header_name)
        if not api_key:
            abort(401, description=f"Missing {self.header_name} header")
        payload = self.validate_key(api_key)
        if not payload:
            abort(401, description="Invalid or expired API key")
        g.api_user = payload
        return func(*args, **kwargs)
    return wrapper
```
- **Impact**: `FlaskAPIKeyAuth.required` performs unlimited validation attempts with no rate limiting, lockout, or logging. An attacker can brute-force API keys at network speed. The `validate_key` method (line 378) catches all exceptions silently — failed attempts are invisible to monitoring. Combined with no key complexity requirements, API key space may be feasibly brute-forced.
- **Reproduction**:
  1. Deploy Flask app with `FlaskAPIKeyAuth`
  2. Send 10,000 requests/second with random API keys
  3. No 429 responses, no logging, no detection
- **Fix Complexity**: MEDIUM
- **Remediation**: Add rate limiting per IP/header. Log failed authentication attempts. Consider exponential backoff or account lockout after N failures. Integrate with Flask-Limiter or similar.

### SHIELD-A06-016: Flask Token and API Key Have No Revocation Mechanism
- **Severity**: LOW
- **CWE**: CWE-613 (Insufficient Session Expiration)
- **Location**: `python/shield/integrations/flask.py:172-210`
- **Evidence**:
```python
def generate_token(self, user_id, roles=None, claims=None, ttl=3600):
    payload = {
        "sub": user_id,
        "roles": roles or [],
        "claims": claims or {},
        "iat": int(time.time()),
        "exp": int(time.time()) + ttl,
    }
```
- **Impact**: Tokens contain no `jti` (unique token ID) claim. There is no revocation list, no token blacklist, and no way to invalidate a token before expiration. If a token is compromised, it remains valid for up to `ttl` seconds (default 3600 = 1 hour). Same applies to `FlaskAPIKeyAuth.generate_key()` — API keys with TTL cannot be revoked early. API keys without TTL (`ttl=None`) are valid forever.
- **Reproduction**:
  1. Generate token via `generate_token("user1", ttl=3600)`
  2. Token is compromised (leaked in logs, stolen)
  3. No mechanism exists to revoke the token — it remains valid for 1 hour
- **Fix Complexity**: MEDIUM
- **Remediation**: Add `jti` claim to tokens. Implement server-side revocation list (Redis/in-memory set). Check `jti` against revocation list in `validate_token()`.

### SHIELD-A06-017: Flask `validate_token` Timing Oracle — Expired vs Invalid Distinguishable
- **Severity**: LOW
- **CWE**: CWE-208 (Observable Timing Discrepancy)
- **Location**: `python/shield/integrations/flask.py:195-210`
- **Evidence**:
```python
def validate_token(self, token: str) -> Optional[dict]:
    try:
        encrypted = base64.urlsafe_b64decode(token)
        decrypted = self.shield.decrypt(encrypted)
        payload = json.loads(decrypted)
        if time.time() > payload.get("exp", 0):
            return None
        return payload
    except Exception:
        return None
```
- **Impact**: Two distinct code paths return `None`: (1) decrypt succeeds but token is expired (fast path — no exception), (2) decrypt fails (slow path — exception thrown). An attacker can distinguish "once-valid but expired" tokens from "never-valid" tokens by measuring response time. This confirms the token's password/key is correct even though the token is expired, which assists in credential validation attacks. Cross-ref: A01-020 (TOTP timing leak pattern).
- **Reproduction**:
  1. Send valid-but-expired token — measure response time T1
  2. Send random garbage token — measure response time T2
  3. T1 < T2 consistently (no exception overhead) → confirms token was valid
- **Fix Complexity**: LOW
- **Remediation**: Add constant-time processing or artificial delay to make both paths indistinguishable. Alternatively, always perform decrypt + JSON parse before returning, regardless of validity.

### SHIELD-A06-018: Flask Decorators Encourage Hardcoded Credentials in Source Code
- **Severity**: MEDIUM
- **CWE**: CWE-798 (Use of Hard-coded Credentials)
- **Location**: `python/shield/integrations/flask.py:213-269`, `python/shield/integrations/flask.py:272-325`
- **Evidence**:
```python
# Module docstring and usage examples show:
@shield_required(password="secret", service="api.example.com")
def protected():
    return {"user_id": g.shield_user["sub"]}

@shield_encrypt_response(password="secret", service="api.example.com")
def data_endpoint():
    return {"sensitive": "data"}
```
- **Impact**: The decorator API design (`shield_required(password=..., service=...)`) encourages developers to hardcode passwords directly in source code. Unlike `ShieldFlask` extension which reads from `app.config`, decorators have no config integration — the only way to pass credentials is as literal arguments or variables. In practice, developers copy usage examples and ship hardcoded `password="secret"` to production. The password is then visible in version control, code reviews, and any source code leak. Cross-ref: A06-009 (Flask config password persistence).
- **Reproduction**:
  1. Follow documentation example: `@shield_required(password="secret", service="api.example.com")`
  2. Password appears in git history, IDE search, and code review
  3. Password cannot be rotated without code deployment
- **Fix Complexity**: LOW
- **Remediation**: Add config-aware decorator variants that read from `app.config` or environment variables. Update documentation examples to show environment variable usage: `@shield_required(password=os.environ["SHIELD_PASSWORD"], ...)`.

---

## TASK-2-009 Findings — SecureCORS, BrowserBridge Session Keys, EncryptedCookie, Route Exclusion

### SHIELD-A06-019: SecureCORS `allow_all` + `allow_credentials` Reflects Arbitrary Origin with Credentials
- **Severity**: MEDIUM
- **CWE**: CWE-346 (Origin Validation Error)
- **Location**: `python/shield/integrations/browser.py:310,339-341`
- **Evidence**:
```python
self.allow_all = "*" in allowed_origins
# ...
if self.allow_credentials:
    headers["Access-Control-Allow-Origin"] = origin  # reflects ANY origin
    headers["Access-Control-Allow-Credentials"] = "true"
```
- **Impact**: When `"*"` is in `allowed_origins`, `allow_all=True` and `allow_credentials=True` (default). The `get_headers()` method reflects the requesting origin back verbatim with `Access-Control-Allow-Credentials: true`. This is equivalent to a universal CORS bypass — any origin (including attacker-controlled sites) can make credentialed cross-origin requests. Browsers block `Access-Control-Allow-Origin: *` with credentials, but reflecting the specific origin back circumvents this protection. An attacker's site `https://evil.com` gets `Access-Control-Allow-Origin: https://evil.com` + credentials, enabling full cross-origin data theft. Cross-ref: A06-012 (SecureCORS key reuse).
- **Reproduction**:
  1. Create `SecureCORS(allowed_origins=["*"], password="secret", service="api.example.com")`
  2. Send request with `Origin: https://evil.com`
  3. Response: `Access-Control-Allow-Origin: https://evil.com` + `Access-Control-Allow-Credentials: true`
  4. Attacker site can now read authenticated API responses via `fetch(url, {credentials: 'include'})`
- **Fix Complexity**: LOW
- **Remediation**: When `allow_all=True`, set `allow_credentials=False` and use `Access-Control-Allow-Origin: *`. Never reflect arbitrary origins with credentials. Add explicit warning if user tries to set both.

### SHIELD-A06-020: SecureCORS Origin Comparison is Case-Sensitive — No Normalization
- **Severity**: LOW
- **CWE**: CWE-178 (Improper Handling of Case Sensitivity)
- **Location**: `python/shield/integrations/browser.py:321-325`
- **Evidence**:
```python
def is_origin_allowed(self, origin: str) -> bool:
    if self.allow_all:
        return True
    return origin in self.allowed_origins  # case-sensitive set lookup
```
- **Impact**: Origin comparison uses case-sensitive set membership. `https://App.Example.Com` would NOT match `https://app.example.com` in the allowed set. Per RFC 6454, the scheme and host in an origin are case-insensitive, but browsers typically lowercase them. The risk is low because browsers normalize origins, but proxies or non-browser clients may send non-normalized origins. More critically, `add_origin()` at line 413 also performs no normalization, so developers adding origins in mixed case create silent mismatches.
- **Reproduction**:
  1. `cors = SecureCORS(allowed_origins=["https://app.example.com"], ...)`
  2. `cors.is_origin_allowed("https://APP.EXAMPLE.COM")` → `False` (unexpected)
- **Fix Complexity**: LOW
- **Remediation**: Normalize origins to lowercase before storing and comparing. Apply `origin.lower()` in `is_origin_allowed()`, `add_origin()`, and constructor.

### SHIELD-A06-021: SecureCORS `add_origin` Accepts Arbitrary Strings Including `null`
- **Severity**: LOW
- **CWE**: CWE-20 (Improper Input Validation)
- **Location**: `python/shield/integrations/browser.py:411-413`
- **Evidence**:
```python
def add_origin(self, origin: str) -> None:
    """Add an origin to the allowed list."""
    self.allowed_origins.add(origin)  # no validation
```
- **Impact**: No validation on the `origin` parameter. An attacker or misconfigured code can add:
  - `"null"` — the string "null" is sent by browsers for sandboxed iframes, data: URIs, and redirects. Allowing it enables attacks from these contexts.
  - Empty string `""` — any request without an Origin header would match
  - Malformed URLs like `javascript:`, `data:`, or partial schemes
  - The `__init__` constructor at line 309 also performs no validation on `allowed_origins` list entries
- **Reproduction**:
  1. `cors.add_origin("null")`
  2. Attacker creates sandboxed iframe → browser sends `Origin: null`
  3. `is_origin_allowed("null")` → `True` → CORS headers returned with credentials
- **Fix Complexity**: LOW
- **Remediation**: Validate origins match `scheme://host[:port]` format. Reject `"null"`, empty strings, and non-HTTPS schemes in production. Add `validate_origin()` helper.

### SHIELD-A06-022: SecureCORS `sign_request` Signature Replay Within 5-Minute Window
- **Severity**: LOW
- **CWE**: CWE-294 (Authentication Bypass by Capture-replay)
- **Location**: `python/shield/integrations/browser.py:368-383,385-409`
- **Evidence**:
```python
def sign_request(self, origin: str, timestamp: Optional[int] = None) -> str:
    ts = timestamp or int(time.time())
    data = f"{origin}:{ts}".encode("utf-8")
    signature = hmac.new(self.shield.key, data, hashlib.sha256).digest()[:16]
    # ...

def verify_request(self, origin: str, signature: str, max_age: int = 300) -> bool:
    # Check age
    if abs(time.time() - ts) > max_age:
        return False
```
- **Impact**: `sign_request` generates HMAC signatures valid for `max_age=300` seconds (5 minutes). Within this window, signatures are replayable — the same signature can be used for multiple requests. Additionally, `timestamp` parameter allows caller-supplied timestamps, enabling pre-computed signatures for future use. The signature binds only `origin:timestamp` — no request method, path, or body binding. An attacker who captures one signed request can replay it to any endpoint for 5 minutes. No nonce or sequence number prevents replay.
- **Reproduction**:
  1. Capture a `sign_request` signature from a legitimate response
  2. Replay the signature with a different request to a different API endpoint within 5 minutes
  3. `verify_request` returns `True` — no request-specific binding
- **Fix Complexity**: MEDIUM
- **Remediation**: Bind signature to request method + path + body hash. Add nonce to prevent replay. Remove caller-supplied `timestamp` parameter.

### SHIELD-A06-023: BrowserBridge Session Key Not Zeroized on Revocation
- **Severity**: LOW
- **CWE**: CWE-226 (Sensitive Information in Resource Not Removed Before Reuse)
- **Location**: `python/shield/integrations/browser.py:130-133`
- **Evidence**:
```python
def revoke_session(self, session_id: str) -> None:
    """Revoke a session key."""
    if session_id in self._session_keys:
        del self._session_keys[session_id]
```
- **Impact**: `revoke_session` removes the entry from `_session_keys` dict, but the `bytes` object containing the 32-byte session key is not overwritten before deletion. Python's garbage collector may not immediately collect the object, and the key material remains in process memory until overwritten. Same issue in `cleanup_expired()` at line 143. Cross-ref: A03-003 (Python has zero zeroization). The session key tuple `(bytes, float)` persists in heap until GC collects and OS overwrites the page.
- **Reproduction**:
  1. Generate session key: `bridge.generate_client_key("session1")`
  2. Revoke: `bridge.revoke_session("session1")`
  3. Memory dump of Python process still contains the 32-byte session key
- **Fix Complexity**: LOW
- **Remediation**: Overwrite key bytes with zeros using `ctypes` or `mmap` before deleting the reference. Use `bytearray` instead of `bytes` (immutable) for key material.

### SHIELD-A06-024: BrowserBridge `_derive_session_key` No Domain Separation Label
- **Severity**: MEDIUM
- **CWE**: CWE-330 (Use of Insufficiently Random Values)
- **Location**: `python/shield/integrations/browser.py:103-111`
- **Evidence**:
```python
def _derive_session_key(self, session_id: str) -> bytes:
    master = self.shield.key  # raw master key access
    return hmac.new(
        master,
        session_id.encode("utf-8"),
        hashlib.sha256,
    ).digest()
```
- **Impact**: Session key derivation uses `HMAC(master_key, session_id)` with no domain separation label/context string. If the same master key is used in another HMAC context with the same input format (e.g., SecureCORS `sign_request` which uses `HMAC(master_key, f"{origin}:{ts}")`), a `session_id` crafted as `"https://example.com:1234567890"` would produce the same HMAC output as `sign_request(origin="https://example.com", timestamp=1234567890)`. This creates cross-protocol key confusion — a session key could be used to forge CORS signatures and vice versa. Cross-ref: A06-004 (raw key exposure), A03-026 (all impls expose raw key).
- **Reproduction**:
  1. `session_id = "https://evil.com:1709337600"` (origin:timestamp format)
  2. `session_key = bridge._derive_session_key(session_id)`
  3. This session_key = `HMAC(master, "https://evil.com:1709337600")` = same as `sign_request("https://evil.com", 1709337600)`
  4. Cross-protocol signature forgery possible
- **Fix Complexity**: LOW
- **Remediation**: Add domain separation label: `HMAC(master, b"shield-session-key:" + session_id.encode())`. Use distinct labels for each HMAC context (`"shield-cors-sig:"` for CORS, `"shield-session:"` for sessions).

### SHIELD-A06-025: BrowserBridge `generate_client_key` No Session ID Validation
- **Severity**: MEDIUM
- **CWE**: CWE-20 (Improper Input Validation)
- **Location**: `python/shield/integrations/browser.py:71-101`
- **Evidence**:
```python
def generate_client_key(
    self,
    session_id: str,
    ttl: int = 3600,
    include_meta: bool = True,
) -> dict:
    session_key = self._derive_session_key(session_id)  # no validation
    expires_at = time.time() + ttl
    self._session_keys[session_id] = (session_key, expires_at)
```
- **Impact**: `session_id` accepts any string with no validation:
  - Empty string `""` → valid session, shared by all callers using empty ID
  - Extremely long strings → unbounded memory in `_session_keys` dict
  - Strings containing special characters → potential injection if session_id is logged or used in other contexts
  - No uniqueness check → calling `generate_client_key("same-id")` twice overwrites the first entry silently
  - `ttl` parameter accepts negative values → `expires_at` is in the past, session immediately invalid
  - `ttl=0` → session expires at creation time
  Cross-ref: A04-021 (BrowserBridge session_id no validation).
- **Reproduction**:
  1. `bridge.generate_client_key("", ttl=-1)` → creates session with empty ID, already expired
  2. `bridge.generate_client_key("x" * 10_000_000, ttl=3600)` → 10MB string stored as dict key
  3. Multiple calls with same session_id silently overwrite previous session
- **Fix Complexity**: LOW
- **Remediation**: Validate `session_id` is non-empty, max length (e.g., 256 chars), alphanumeric+hyphen. Validate `ttl > 0`. Optionally reject duplicate session IDs or require explicit revocation first.

### SHIELD-A06-026: FastAPI Route Exclusion Uses Same `startsWith` Pattern — Cross-ref A06-013/014
- **Severity**: MEDIUM
- **CWE**: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- **Location**: `python/shield/integrations/fastapi.py:100-106`
- **Evidence**:
```python
# Skip excluded routes
if any(path.startswith(prefix) for prefix in self.exclude_routes):
    return response

# If encrypt_routes specified, only encrypt matching routes
if self.encrypt_routes:
    if not any(path.startswith(prefix) for prefix in self.encrypt_routes):
        return response
```
- **Impact**: FastAPI `ShieldMiddleware.dispatch()` uses the identical `path.startswith(prefix)` pattern as Flask (A06-013) and Express (A06-014). Default exclusions are `["/docs", "/redoc", "/openapi.json"]` (line 90). The same bypass vectors apply: URL encoding, case mismatch, prefix over-matching (`/docs-internal` excluded unintentionally), path traversal. Starlette's `request.url.path` behavior may differ from Flask's `request.path` under some ASGI servers, but the core vulnerability is the same. This establishes a **systemic pattern** — all 3 web frameworks (Flask, Express, FastAPI) use the same insecure prefix-matching approach.
- **Reproduction**:
  1. FastAPI with default `exclude_routes=["/docs", "/redoc", "/openapi.json"]`
  2. Request to `/docs-admin` → excluded (prefix match on `/docs`), bypasses encryption unintentionally
  3. Request to `/Docs` → NOT excluded (case-sensitive), encrypted when it shouldn't be
- **Fix Complexity**: LOW
- **Remediation**: Same as A06-013/014. Normalize paths before comparison. Consider exact-match or regex patterns. This is a systemic issue that should be fixed with a shared utility function used by all 3 framework integrations.
