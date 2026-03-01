# A07 — Auth & Session Security Findings

**Agent**: A07 (Auth & Session)
**Phase**: 2 (Protocol & App & Infra)
**Priority**: HIGH
**Date**: 2026-03-02
**Tasks**: TASK-2-010 (10 findings), TASK-2-011 (8 findings), TASK-2-012 (11 findings), TASK-2-013 (9 findings)
**Total**: 38 findings (1 HIGH, 21 MEDIUM, 13 LOW, 4 INFO)

---

## TASK-2-010 Findings — Token Auth & API Key Security

### SHIELD-A07-001: No Token Revocation Mechanism — Tokens Valid Until Expiry
- **Severity**: HIGH
- **CWE**: CWE-613 (Insufficient Session Expiration)
- **Location**: `python/shield/integrations/fastapi.py:334-347` (ShieldTokenAuth.validate_token), `python/shield/integrations/flask.py:195-210` (ShieldFlask.validate_token), `shield-core/src/identity.rs:249-309` (IdentityProvider.validate_token)
- **Evidence**:
```python
# fastapi.py ShieldTokenAuth.validate_token
def validate_token(self, token: str) -> Optional[dict]:
    try:
        encrypted = base64.urlsafe_b64decode(token)
        decrypted = self.shield.decrypt(encrypted)
        payload = json.loads(decrypted)
        # Check expiration
        if time.time() > payload.get("exp", 0):
            return None
        return payload
    except Exception:
        return None
```
```rust
// identity.rs — IdentityProvider has revoke_user() but NO token blacklist
pub fn revoke_user(&mut self, user_id: &str) {
    self.users.remove(user_id);  // removes user, but issued tokens remain valid
}
```
- **Impact**: Once a token is issued, it cannot be revoked before its TTL expires. If an API key or bearer token is compromised, there is no mechanism to invalidate it. The Rust `IdentityProvider.revoke_user()` removes the user from the registry but does NOT invalidate already-issued session tokens — those tokens remain valid until they naturally expire (default: 3600 seconds). An attacker with a stolen token has a guaranteed window of exploitation.
- **Reproduction**:
  1. Create a token: `auth.create_token(user_id="victim", roles=["admin"])`
  2. Revoke user (Rust) or attempt any revocation — no API exists in Python
  3. Validate the token — it still passes `validate_token()` because validation only checks TTL, not a blacklist
- **Fix Complexity**: MEDIUM
- **Remediation**: Implement a token blacklist (in-memory set or Redis-backed). On revocation, add the token's `iat` or a unique `jti` claim to the blacklist. Check blacklist during `validate_token()`. Alternatively, use short-lived tokens (< 5 min) with a refresh token pattern.

### SHIELD-A07-002: No Token ID (jti) Claim — Tokens Cannot Be Individually Tracked or Revoked
- **Severity**: MEDIUM
- **CWE**: CWE-613 (Insufficient Session Expiration)
- **Location**: `python/shield/integrations/fastapi.py:315-332` (ShieldTokenAuth.create_token), `python/shield/integrations/flask.py:172-193` (ShieldFlask.generate_token)
- **Evidence**:
```python
# fastapi.py ShieldTokenAuth.create_token
payload = {
    "sub": user_id,
    "roles": roles or [],
    "claims": claims or {},
    "iat": int(time.time()),
    "exp": int(time.time()) + self.ttl,
    # NO "jti" (JWT ID) claim
}
```
- **Impact**: Without a unique token identifier (`jti`), there is no way to track individual tokens for audit logging, selective revocation, or replay detection. All tokens for the same user created within the same second will have identical `iat` values and be indistinguishable. This makes forensic analysis after a breach extremely difficult.
- **Reproduction**: Create two tokens for the same user within the same second — their payloads will be structurally identical (only differing by encryption nonce), making them impossible to distinguish in logs.
- **Fix Complexity**: LOW
- **Remediation**: Add a `"jti": uuid4()` or `"jti": os.urandom(16).hex()` claim to all token payloads. Use jti for audit logging and as the key for any revocation blacklist.

### SHIELD-A07-003: Timing Oracle in Token Validation — Expired vs Invalid Distinguishable
- **Severity**: MEDIUM
- **CWE**: CWE-208 (Observable Timing Discrepancy)
- **Location**: `python/shield/integrations/fastapi.py:334-347` (ShieldTokenAuth.validate_token), `python/shield/integrations/flask.py:195-210` (ShieldFlask.validate_token)
- **Evidence**:
```python
# fastapi.py ShieldTokenAuth.validate_token
def validate_token(self, token: str) -> Optional[dict]:
    try:
        encrypted = base64.urlsafe_b64decode(token)
        decrypted = self.shield.decrypt(encrypted)  # Full decrypt path
        payload = json.loads(decrypted)
        if time.time() > payload.get("exp", 0):
            return None  # Expired: decrypt + JSON parse + time check
        return payload
    except Exception:
        return None  # Invalid: fails at decrypt or JSON parse (shorter path)
```
- **Impact**: An attacker can distinguish between an expired-but-valid token and a completely invalid token by measuring response time. Expired tokens traverse the full decrypt → JSON parse → time check path, while invalid tokens fail early at decrypt or base64 decode. This leaks information about whether a token was legitimately issued, aiding targeted attacks (e.g., confirming stolen tokens are genuine before the attacker modifies the TTL via other means).
- **Reproduction**:
  1. Send 1000 requests with a valid-but-expired token, measure average response time
  2. Send 1000 requests with random garbage token, measure average response time
  3. Compare distributions — expired tokens will consistently take longer due to successful decryption
- **Fix Complexity**: LOW
- **Remediation**: Add a constant-time padding delay or restructure validation to always perform the full decrypt path regardless of outcome (decrypt → parse → check → compare result). Cross-reference: SHIELD-A06-017 (`validate_token` timing oracle, same pattern).

### SHIELD-A07-004: API Keys Use Shield Encrypt — Decrypt Becomes Brute-Force Oracle
- **Severity**: MEDIUM
- **CWE**: CWE-307 (Improper Restriction of Excessive Authentication Attempts)
- **Location**: `python/shield/integrations/fastapi.py:249-263` (ShieldAPIKeyAuth.validate_key), `python/shield/integrations/flask.py:378-391` (FlaskAPIKeyAuth.validate_key)
- **Evidence**:
```python
# fastapi.py ShieldAPIKeyAuth.validate_key
def validate_key(self, api_key: str) -> Optional[dict]:
    try:
        encrypted = base64.urlsafe_b64decode(api_key)
        decrypted = self.shield.decrypt(encrypted)  # HMAC verification
        payload = json.loads(decrypted)
        if "expires_at" in payload:
            if time.time() > payload["expires_at"]:
                return None
        return payload
    except Exception:
        return None
```
- **Impact**: API key validation relies entirely on Shield's decrypt (which includes MAC verification). While MAC verification is computationally expensive (~PBKDF2 + HMAC), there is no rate limiting built into the auth classes themselves. An attacker can submit arbitrary API key values without any lockout. The `ShieldAPIKeyAuth` and `FlaskAPIKeyAuth` classes have no integration with `RateLimiter` or `APIProtector` — they are standalone. Cross-reference: SHIELD-A06-015 (FlaskAPIKeyAuth no rate limiting, already reported). This finding extends to FastAPI's `ShieldAPIKeyAuth` as well.
- **Reproduction**:
  1. Set up `ShieldAPIKeyAuth` as FastAPI dependency
  2. Send unlimited requests with random `X-API-Key` values
  3. No lockout, no rate limiting, no account lockout after N failures
- **Fix Complexity**: LOW
- **Remediation**: Integrate `RateLimiter` into `ShieldAPIKeyAuth.__call__()` and `FlaskAPIKeyAuth.required()`. Add per-IP rate limiting for failed validation attempts. Consider exponential backoff after consecutive failures.

### SHIELD-A07-005: ShieldTokenAuth and ShieldAPIKeyAuth Leak Auth State via Different HTTP Error Details
- **Severity**: MEDIUM
- **CWE**: CWE-203 (Observable Discrepancy / User Enumeration)
- **Location**: `python/shield/integrations/fastapi.py:265-282` (ShieldAPIKeyAuth.__call__), `python/shield/integrations/fastapi.py:349-367` (ShieldTokenAuth.__call__)
- **Evidence**:
```python
# ShieldAPIKeyAuth.__call__
if not api_key:
    raise HTTPException(status_code=401, detail="Missing API key",
        headers={"WWW-Authenticate": f"ApiKey realm={self.header_name}"})
payload = self.validate_key(api_key)
if not payload:
    raise HTTPException(status_code=401, detail="Invalid or expired API key")
    # ^^ Different detail: "Missing" vs "Invalid or expired"

# ShieldTokenAuth.__call__
if not auth_header.startswith("Bearer "):
    raise HTTPException(status_code=401, detail="Missing bearer token",
        headers={"WWW-Authenticate": "Bearer"})
payload = self.validate_token(token)
if not payload:
    raise HTTPException(status_code=401, detail="Invalid or expired token")
    # ^^ Different detail: "Missing" vs "Invalid or expired"
```
- **Impact**: An attacker can distinguish three states: (1) no token/key provided ("Missing"), (2) token/key provided but invalid or expired ("Invalid or expired"), (3) valid (success). While "Missing" vs "Invalid" distinction is minor, combining with SHIELD-A07-003 timing oracle, an attacker can further distinguish "invalid" from "expired" — building a complete picture of the authentication state machine. This aids in confirming whether stolen tokens are genuine and when they expire.
- **Reproduction**:
  1. Request with no `Authorization` header → "Missing bearer token"
  2. Request with `Authorization: Bearer garbage` → "Invalid or expired token"
  3. Request with expired but legitimate token → "Invalid or expired token" (but slower per A07-003)
- **Fix Complexity**: LOW
- **Remediation**: Use a single generic error message for all authentication failures: `"Authentication required"` or `"Unauthorized"`. Do not distinguish missing vs invalid vs expired in error responses.

### SHIELD-A07-006: FIDO2 Signature Verification Not Implemented — Always Accepts Non-Empty Signature
- **Severity**: MEDIUM
- **CWE**: CWE-287 (Improper Authentication)
- **Location**: `shield-core/src/fido2/manager.rs:219-223`
- **Evidence**:
```rust
// In a real implementation, verify signature with stored_cred.public_key
// For this simplified version, we just check signature is non-empty
if signature.is_empty() {
    return Err(Fido2Error::InvalidSignature);
}
```
- **Impact**: The FIDO2 authentication flow accepts ANY non-empty byte sequence as a valid signature. An attacker who knows a user's credential ID (which is often publicly transmitted in the challenge response) can authenticate as that user by providing any non-empty signature. The counter check (line 215-217) provides minimal protection — it only prevents replay of the same counter value, not fabrication of new authentications. **This is a complete authentication bypass for FIDO2.**
- **Reproduction**:
  1. Register a credential for user "alice"
  2. Call `verify_authentication` with the correct challenge, credential_id, signature `b"x"`, and counter > stored
  3. Authentication succeeds — any byte is accepted as a valid signature
- **Fix Complexity**: HIGH
- **Remediation**: Implement proper ECDSA/EdDSA signature verification using the stored public key against the authenticator data + client data hash. This is the core of WebAuthn security and cannot be shipped as a stub. Cross-reference: SHIELD-A04-028 (FIDO2 unsigned token after auth).

### SHIELD-A07-007: Rust IdentityProvider.authenticate Returns None for Both Invalid User and Wrong Password
- **Severity**: LOW
- **CWE**: CWE-203 (Observable Discrepancy)
- **Location**: `shield-core/src/identity.rs:176-199`
- **Evidence**:
```rust
pub fn authenticate(&self, user_id: &str, password: &str, ...) -> Option<String> {
    let user = self.users.get(user_id)?;  // Returns None immediately if user doesn't exist
    // ... PBKDF2 derive ...
    if password_hash.ct_eq(&user.password_hash).unwrap_u8() != 1 {
        return None;  // Returns None after PBKDF2 + constant-time compare
    }
    Some(self.create_token(...))
}
```
- **Impact**: While both cases return `None`, a timing oracle exists: invalid user_id returns immediately (HashMap lookup fails), while wrong password requires a full PBKDF2 derivation (100k iterations). An attacker can enumerate valid user IDs by measuring response time — valid users take ~100ms longer due to PBKDF2. The constant-time comparison on line 194 is correctly implemented but is preceded by a timing-distinguishable early return.
- **Reproduction**:
  1. Call `authenticate("nonexistent_user", "pass", ...)` — returns in microseconds
  2. Call `authenticate("alice", "wrong_pass", ...)` — returns in ~100ms (PBKDF2)
  3. Time difference reveals user existence
- **Fix Complexity**: LOW
- **Remediation**: Always perform PBKDF2 derivation even for non-existent users. Use a dummy salt for the non-existent case: `let salt = user.map(|u| u.salt).unwrap_or_else(|| [0u8; 16]);` and always derive the hash before checking user existence.

### SHIELD-A07-008: Recovery Codes Stored as Plaintext Strings in HashSet
- **Severity**: LOW
- **CWE**: CWE-256 (Plaintext Storage of a Password)
- **Location**: `shield-core/src/totp.rs:184-187`
- **Evidence**:
```rust
pub struct RecoveryCodes {
    codes: HashSet<String>,  // Plaintext recovery codes
    original_count: usize,
}
```
- **Impact**: Recovery codes are stored as plaintext strings in a `HashSet<String>`. If memory is dumped (via crash dump, core dump, debugging, or memory-safety exploit), all unused recovery codes are exposed. Recovery codes are single-use emergency credentials equivalent to passwords — they should be hashed. The `codes()` method (line 249) also returns all codes as a `Vec<String>`, making them trivially extractable. Cross-reference: SHIELD-A03-010 (RecoveryCodes HashSet<String>, already reported as LOW).
- **Reproduction**: Call `recovery_codes.codes()` at any time to get all remaining codes in plaintext. No authentication required for this method call.
- **Fix Complexity**: MEDIUM
- **Remediation**: Store HMAC or hash of each recovery code instead of plaintext. On verification, hash the submitted code and compare against stored hashes. The `codes()` method should only be called once at generation time for user display, then codes should be stored hashed.

### SHIELD-A07-009: TOTP Verify Does Not Prevent Replay Within Window
- **Severity**: LOW
- **CWE**: CWE-294 (Authentication Bypass by Capture-replay)
- **Location**: `shield-core/src/totp.rs:88-111`
- **Evidence**:
```rust
pub fn verify(&self, code: &str, timestamp: Option<u64>, window: u32) -> bool {
    // ... iterates through time windows ...
    for i in 0..=window {
        let t = time.saturating_sub(u64::from(i) * self.interval);
        if self.generate(Some(t)) == code {
            return true;  // No tracking of used codes
        }
        // ...
    }
    false
}
```
- **Impact**: The same TOTP code can be reused multiple times within the valid window (default: 1 window = +-30 seconds). No state is maintained to track which codes have been consumed. An attacker who intercepts or shoulder-surfs a TOTP code can reuse it within the window. With `window=1` (default), a code is valid for up to 90 seconds (current + 1 previous + 1 future interval), giving a meaningful replay window.
- **Reproduction**:
  1. Generate TOTP code at time T
  2. Call `verify(code, Some(T), 1)` → `true`
  3. Call `verify(code, Some(T), 1)` again → `true` (no replay protection)
- **Fix Complexity**: MEDIUM
- **Remediation**: Maintain a set of recently used codes (keyed by user + code + time step). After successful verification, add the (code, time_step) pair to the used set. Reject codes already in the used set. Prune entries older than the maximum window.

### SHIELD-A07-010: Python Token Auth Classes Create Shield Instance at Decorator Import Time
- **Severity**: INFO
- **CWE**: CWE-798 (Use of Hard-coded Credentials)
- **Location**: `python/shield/integrations/fastapi.py:158` (shield_protected), `python/shield/integrations/flask.py:233` (shield_required), `python/shield/integrations/flask.py:286` (shield_encrypt_response)
- **Evidence**:
```python
# fastapi.py shield_protected decorator
def shield_protected(password: str, service: str, ...):
    shield = Shield(password, service)  # Created at import/decoration time, not per-request
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Uses shield from closure — password baked into module scope
```
- **Impact**: The Shield instance (and thus the encryption password) is captured in the decorator closure at import/decoration time. This means: (1) the password is pinned for the lifetime of the process, (2) password rotation requires process restart, (3) the password string persists in memory for the entire application lifetime with no opportunity for zeroization. Cross-reference: SHIELD-A06-003 (Decorator import-time key, MEDIUM). This is informational as a token-lifecycle context note — the middleware persistence finding is already cataloged.
- **Reproduction**: Inspect `shield_protected.__closure__` or `shield_required.__closure__` — the Shield instance with the password is accessible.
- **Fix Complexity**: MEDIUM
- **Remediation**: Accept a Shield factory/callable instead of password strings. Create Shield instances per-request or use a provider pattern that supports key rotation.

---

## TASK-2-011 Findings — Rate Limiter & Brute Force Protection

### SHIELD-A07-011: Fixed Window Counter Allows 2x Burst at Window Boundary
- **Severity**: MEDIUM
- **CWE**: CWE-799 (Improper Control of Interaction Frequency)
- **Location**: `python/shield/integrations/protection.py:120-122` (RateLimiter.is_allowed)
- **Evidence**:
```python
# Reset window if expired
if now - state.window_start >= self.window:
    state = RateLimitState(count=0, window_start=now)
```
- **Impact**: The RateLimiter uses a fixed window algorithm. When the window expires, the counter resets entirely. An attacker can send `max_requests` requests at the end of window N, then immediately send `max_requests` at the start of window N+1, achieving 2x the intended rate in a short burst. With `max_requests=100, window=60`, an attacker gets 200 requests in ~2 seconds straddling the window boundary.
- **Reproduction**:
  1. Create `RateLimiter(password="x", service="s", max_requests=100, window=60)`
  2. Wait until 59.9 seconds into a window
  3. Send 100 requests (all allowed — window still active)
  4. Wait 0.2 seconds (window expires)
  5. Send 100 more requests (all allowed — new window)
  6. Result: 200 requests in ~0.3 seconds
- **Fix Complexity**: MEDIUM
- **Remediation**: Implement sliding window counter or sliding window log algorithm instead of fixed window. Alternatively, use the TokenBucket class which naturally handles bursts. If fixed window is kept, implement a "previous window weighted" approach where the count includes a proportional share of the previous window's count.

### SHIELD-A07-012: Decrypt Failure Resets Rate Limit Counter to Zero — Silent Bypass
- **Severity**: MEDIUM
- **CWE**: CWE-755 (Improper Handling of Exceptional Conditions)
- **Location**: `python/shield/integrations/protection.py:95-103` (RateLimiter._get_state), `python/shield/integrations/protection.py:228-230` (TokenBucket._get_state)
- **Evidence**:
```python
# RateLimiter._get_state
try:
    decrypted = self.shield.decrypt(encrypted)
    data = json.loads(decrypted)
    return RateLimitState(count=data.get("count", 0), window_start=data.get("window_start", 0.0))
except Exception:
    return RateLimitState()  # Counter reset to 0!

# TokenBucket._get_state
except Exception:
    return TokenBucketState(tokens=self.capacity, last_update=time.time())  # Full bucket!
```
- **Impact**: If decryption of the stored state fails for ANY reason — corruption, key rotation, process restart with different password — the rate limit counter silently resets to zero (RateLimiter) or full capacity (TokenBucket). The TokenBucket case is worse: a full bucket means the attacker gets `capacity` requests immediately. An attacker who can corrupt the in-memory storage dict (e.g., via a separate vulnerability, shared memory, or race condition on the dict itself) can bypass all rate limiting by causing decrypt failures.
- **Reproduction**:
  1. Create `RateLimiter(password="x", service="s", max_requests=5, window=3600)`
  2. Exhaust 5 requests → rate limited
  3. Corrupt `limiter.storage[key]` to any invalid bytes
  4. Call `is_allowed()` → returns True (counter reset to 0)
- **Fix Complexity**: LOW
- **Remediation**: On decrypt failure, assume the MOST restrictive state (deny the request) rather than the most permissive. Return `RateLimitState(count=self.max_requests, window_start=time.time())` for RateLimiter and `TokenBucketState(tokens=0.0, last_update=time.time())` for TokenBucket. Log the decrypt failure as a security event.

### SHIELD-A07-013: Multi-Worker Bypass — threading.Lock Does Not Protect Across Processes
- **Severity**: MEDIUM
- **CWE**: CWE-362 (Concurrent Execution Using Shared Resource with Improper Synchronization)
- **Location**: `python/shield/integrations/protection.py:87` (RateLimiter.__init__), `python/shield/integrations/protection.py:214` (TokenBucket.__init__)
- **Evidence**:
```python
self._lock = threading.Lock()  # Process-local only!
self.storage = storage if storage is not None else {}  # In-memory dict
```
- **Impact**: The `threading.Lock()` only protects within a single process. In production deployments with multiple workers (gunicorn with `--workers 4`, uvicorn with `--workers N`), each worker has its own independent RateLimiter with its own storage dict and lock. An attacker can make `max_requests × N` requests before being limited (where N = number of workers). With 4 workers and `max_requests=100`, the effective limit is 400 requests per window. The in-memory storage is not shared between workers.
- **Reproduction**:
  1. Deploy FastAPI with `uvicorn --workers 4` using `APIProtector(max_requests=100)`
  2. Send 400 requests rapidly
  3. Each worker allows 100 requests independently = 400 total before any limiting
- **Fix Complexity**: MEDIUM
- **Remediation**: Document that in-memory rate limiting only works for single-worker deployments. Provide a Redis or database-backed storage backend for multi-worker. Use `multiprocessing.Lock` or shared memory for process-level synchronization as a minimal fix.

### SHIELD-A07-014: Invalid IP Address Silently Bypasses Blacklist Check
- **Severity**: MEDIUM
- **CWE**: CWE-20 (Improper Input Validation)
- **Location**: `python/shield/integrations/protection.py:398-409` (APIProtector.check_request)
- **Evidence**:
```python
# IP blacklist check
if client_ip:
    try:
        ip = ipaddress.ip_address(client_ip)
        for network in self.ip_blacklist:
            if ip in network:
                self._log_event("blocked", client_ip, user_id, "IP blacklisted")
                return self.CheckResult(allowed=False, reason="IP address blocked")
    except ValueError:
        pass  # Invalid IP silently passes blacklist check!
```
- **Impact**: If `client_ip` is a malformed string (e.g., `"not-an-ip"`, `"127.0.0.1; DROP TABLE"`, or `"::ffff:999.999.999.999"`), the `ipaddress.ip_address()` raises `ValueError` which is caught and silently ignored. The request proceeds past the blacklist check. An attacker can bypass IP blacklisting by sending a malformed IP address in the `X-Forwarded-For` header (if the application passes that directly as `client_ip`). Note: the whitelist check (line 423) does correctly reject invalid IPs when `require_whitelist=True`, but only in whitelist mode.
- **Reproduction**:
  1. Add `"1.2.3.4"` to blacklist
  2. Call `check_request(client_ip="1.2.3.4")` → blocked (correct)
  3. Call `check_request(client_ip="not-a-valid-ip")` → allowed (incorrect — should fail closed)
- **Fix Complexity**: LOW
- **Remediation**: Reject requests with invalid IP addresses. Change the `except ValueError: pass` to return `CheckResult(allowed=False, reason="Invalid IP address")`. Alternatively, require IP validation before reaching the protector.

### SHIELD-A07-015: Anonymous Identifier Shared Across All Unauthenticated Requests
- **Severity**: MEDIUM
- **CWE**: CWE-799 (Improper Control of Interaction Frequency)
- **Location**: `python/shield/integrations/protection.py:429` (APIProtector.check_request)
- **Evidence**:
```python
identifier = user_id or client_ip or "anonymous"
```
- **Impact**: If neither `user_id` nor `client_ip` is provided, ALL requests share the single `"anonymous"` rate limit bucket. A single attacker can exhaust the rate limit for all unauthenticated users by sending `max_requests` requests, causing a denial-of-service for legitimate anonymous users. Even if `client_ip` is provided, the `user_id or client_ip` precedence means that if `user_id` is an empty string `""` (falsy), the system falls back to `client_ip`, which is correct — but `user_id=None` and no `client_ip` yields the shared anonymous bucket.
- **Reproduction**:
  1. Create `APIProtector` with `add_rate_limit(max_requests=10, window=60)`
  2. Attacker calls `check_request()` 10 times (no user_id, no client_ip)
  3. Legitimate user calls `check_request()` → denied (shared "anonymous" bucket exhausted)
- **Fix Complexity**: LOW
- **Remediation**: When both `user_id` and `client_ip` are None, reject the request outright rather than falling back to a shared identifier. Alternatively, generate a unique per-request identifier or require at least `client_ip`.

### SHIELD-A07-016: No Account Lockout After Consecutive Authentication Failures
- **Severity**: MEDIUM
- **CWE**: CWE-307 (Improper Restriction of Excessive Authentication Attempts)
- **Location**: `python/shield/integrations/protection.py` (entire module), `shield-core/src/identity.rs:176-199` (IdentityProvider.authenticate)
- **Evidence**:
```python
# RateLimiter only tracks per-window count, not consecutive failures
# No failed_attempts counter anywhere in protection.py or identity.rs

# identity.rs authenticate — no lockout
pub fn authenticate(&self, user_id: &str, password: &str, ...) -> Option<String> {
    let user = self.users.get(user_id)?;
    // ... PBKDF2 ...
    if password_hash.ct_eq(&user.password_hash).unwrap_u8() != 1 {
        return None;  // No failure tracking, no lockout
    }
    Some(self.create_token(...))
}
```
- **Impact**: Neither the Python rate limiting module nor the Rust identity provider tracks consecutive failed authentication attempts. An attacker can make unlimited password guessing attempts, limited only by per-window rate limits (if configured). Even with rate limiting, the attacker gets `max_requests` guesses per window indefinitely — there is no exponential backoff, no CAPTCHA trigger, and no account lockout after N failures. With `max_requests=100, window=60`, an attacker gets 100 password guesses per minute = 6,000/hour = 144,000/day. Combined with SHIELD-A07-013 (multi-worker bypass), this could be significantly higher.
- **Reproduction**:
  1. Call `authenticate("alice", "wrong1", ...)` → None
  2. Repeat 10,000 times with different passwords
  3. No lockout, no delay increase, no alert
- **Fix Complexity**: MEDIUM
- **Remediation**: Add a `FailedLoginTracker` that counts consecutive failures per user. After N failures (e.g., 5), either lock the account temporarily (exponential backoff: 1min, 5min, 30min) or require CAPTCHA verification. Reset the counter on successful authentication. Cross-reference: SHIELD-A07-004 (API keys no rate limiting).

### SHIELD-A07-017: APIProtector Stores Encryption Password as Plaintext Attribute
- **Severity**: LOW
- **CWE**: CWE-256 (Plaintext Storage of a Password)
- **Location**: `python/shield/integrations/protection.py:323` (APIProtector.__init__)
- **Evidence**:
```python
def __init__(self, password: str, service: str):
    self.shield = Shield(password, service)
    self.password = password  # Stored as plaintext attribute!
    self.service = service
```
- **Impact**: The encryption password is stored as a plain `self.password` attribute on the APIProtector instance, in addition to being held by the Shield instance. This password is used to create child RateLimiter/TokenBucket instances via `add_rate_limit()` and `add_token_bucket()`. The password persists as a Python string for the lifetime of the object with no zeroization. It's accessible via `protector.password` and visible in `protector.__dict__`, memory dumps, and debugging tools. Cross-reference: SHIELD-A03-026 (all impls expose raw key unconditionally), SHIELD-A06-003 (decorator import-time key).
- **Reproduction**: `print(protector.password)` → prints the encryption password.
- **Fix Complexity**: LOW
- **Remediation**: Remove `self.password` storage. Pass the `Shield` instance directly to child objects instead of re-creating them. Alternatively, accept a `shield_factory` callable.

### SHIELD-A07-018: Rate Limit Headers Expose Configuration to Attackers
- **Severity**: INFO
- **CWE**: CWE-200 (Exposure of Sensitive Information)
- **Location**: `python/shield/integrations/protection.py:439-443` (APIProtector.check_request)
- **Evidence**:
```python
return self.CheckResult(
    allowed=False,
    reason="Rate limit exceeded",
    headers={
        "X-RateLimit-Limit": str(self.rate_limiter.max_requests),
        "X-RateLimit-Remaining": str(remaining),
        "X-RateLimit-Reset": str(int(reset_time)),
    },
)
```
- **Impact**: Rate limit response headers expose the exact `max_requests` limit, remaining count, and reset time. An attacker can use this to: (1) calculate the exact window boundary for the 2x burst attack (SHIELD-A07-011), (2) know exactly when to resume after being rate limited, (3) fingerprint the protection mechanism. While these headers are common practice (RFC 6585), exposing `X-RateLimit-Limit` reveals the maximum capacity which aids in capacity-based DoS planning.
- **Reproduction**: Send requests until rate limited. The 429 response headers reveal the full rate limit configuration.
- **Fix Complexity**: LOW
- **Remediation**: Make rate limit headers configurable (opt-in rather than default). Consider omitting `X-RateLimit-Limit` in production. At minimum, do not expose the reset time with second-precision granularity — this enables perfect timing of the window boundary attack.

---

## TASK-2-012 Findings — Session & Identity Management

### SHIELD-A07-019: Python IdentityProvider Uses Deterministic Salt Derived From user_id
- **Severity**: MEDIUM
- **CWE**: CWE-760 (Use of a One-Way Hash with a Predictable Salt)
- **Location**: `python/shield/identity.py:124-125`
- **Evidence**:
```python
# register()
salt = hashlib.sha256(f"user:{user_id}".encode()).digest()
user_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

# authenticate() — same pattern
salt = hashlib.sha256(f"user:{user_id}".encode()).digest()
user_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
```
- **Impact**: The salt is deterministically derived from `user_id` via `SHA256("user:{user_id}")`. This means: (1) the salt is predictable and computable by anyone who knows the user_id, (2) two users with the same password on different instances will have the same derived key if they share a user_id, (3) an attacker can pre-compute rainbow tables for common user_ids (e.g., "admin", "root", "alice") since the salt is known in advance. The Rust implementation (`identity.rs:129`) correctly uses `crate::random::random_bytes()` for a 16-byte random salt. This is a cross-language divergence.
- **Reproduction**:
  1. Compute `hashlib.sha256(b"user:admin").hexdigest()` — always `e3b7...` (deterministic)
  2. Pre-compute PBKDF2 table for top 10,000 passwords with this salt
  3. Compare against any captured verification_key to test passwords instantly
- **Fix Complexity**: LOW
- **Remediation**: Use `secrets.token_bytes(16)` for salt and store it alongside the identity. Align with Rust implementation's random salt approach.

### SHIELD-A07-020: Python Token Payload Is Plaintext Readable — HMAC-Only, No Encryption
- **Severity**: MEDIUM
- **CWE**: CWE-312 (Cleartext Storage of Sensitive Information)
- **Location**: `python/shield/identity.py:325-329` (_sign_token), `python/shield/identity.py:331-352` (_verify_token)
- **Evidence**:
```python
def _sign_token(self, data: dict) -> str:
    """Sign token data."""
    token_bytes = json.dumps(data, separators=(',', ':')).encode()
    mac = hmac.new(self.provider_key, token_bytes, hashlib.sha256).digest()[:16]
    return base64.urlsafe_b64encode(token_bytes + mac).decode()
    # ^^ token_bytes is plaintext JSON, only MAC is appended
```
- **Impact**: Python tokens are `base64(JSON_plaintext + HMAC)`. Anyone who intercepts a token can base64-decode it and read the full payload: `user_id`, `permissions`, `created`, `expires`, `nonce`. The Rust implementation (`identity.rs:202-244`) encrypts the token data using SHA256-CTR keystream before applying HMAC — the payload is not readable without the key. This means: (1) token contents leak via logging, error messages, or network sniffing, (2) permissions and roles are visible to the client, (3) an attacker learns exact token expiration time to plan replay attacks. The token is integrity-protected (HMAC) but NOT confidentiality-protected.
- **Reproduction**:
  1. Get a token from `provider.authenticate("alice", "pass")`
  2. `base64.urlsafe_b64decode(token)[:-16]` → readable JSON with user_id, permissions, expiry
- **Fix Complexity**: MEDIUM
- **Remediation**: Encrypt the token payload before signing, matching the Rust implementation. Use Shield's encrypt function or implement CTR-mode encryption with the provider key. At minimum, document that Python tokens are not confidential and should only be transmitted over TLS.

### SHIELD-A07-021: Python IdentityProvider.authenticate() Timing Oracle — Same as Rust A07-007
- **Severity**: LOW
- **CWE**: CWE-208 (Observable Timing Discrepancy)
- **Location**: `python/shield/identity.py:157-168`
- **Evidence**:
```python
def authenticate(self, user_id, password, ...):
    if user_id not in self._identities:
        return None  # Immediate return — no PBKDF2

    identity = self._identities[user_id]
    salt = hashlib.sha256(f"user:{user_id}".encode()).digest()
    user_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    verification_key = hashlib.sha256(b'verify:' + user_key).digest()

    if not hmac.compare_digest(verification_key, identity.verification_key):
        return None  # Returns after PBKDF2 (100k iterations)
```
- **Impact**: Same pattern as SHIELD-A07-007 (Rust). Non-existent user returns immediately; wrong password takes ~100ms for PBKDF2. An attacker can enumerate valid user_ids by timing responses. Cross-reference: SHIELD-A07-007. Both implementations share this vulnerability, confirming it's a systemic design issue rather than an implementation bug.
- **Reproduction**: Time `authenticate("nonexistent", "x")` vs `authenticate("alice", "wrong")` — measurable difference.
- **Fix Complexity**: LOW
- **Remediation**: Always derive PBKDF2 even for non-existent users. Use a dummy salt derived from the user_id.

### SHIELD-A07-022: Rust validate_token Unchecked Array Indexing — Panic on Malformed Token After MAC Bypass
- **Severity**: MEDIUM
- **CWE**: CWE-125 (Out-of-bounds Read)
- **Location**: `shield-core/src/identity.rs:284-295`
- **Evidence**:
```rust
// After MAC verification passes (line 271), token_data is decrypted
// Parsing assumes minimum structure — no bounds checking:
let user_id_len = u16::from_le_bytes([token_data[0], token_data[1]]) as usize;
let user_id = String::from_utf8(token_data[2..2 + user_id_len].to_vec()).ok()?;
// ^^ If token_data.len() < 2 + user_id_len, this panics with index out of bounds

let offset = 2 + user_id_len;
let perms_len = u16::from_le_bytes([token_data[offset], token_data[offset + 1]]) as usize;
// ^^ No check that offset + 1 < token_data.len()

let exp_offset = offset + 2 + perms_len;
let expires_at = u64::from_le_bytes(token_data[exp_offset..exp_offset + 8].try_into().ok()?);
// ^^ .try_into().ok()? catches this one, but earlier slicing may panic first
```
- **Impact**: While MAC verification prevents external attackers from crafting malformed tokens (they'd need the key), this is still exploitable if: (1) a bug in the crypto layer produces corrupted but MAC-valid output (e.g., the nonce/key reuse issue in SHIELD-A01-001), (2) the master_key is compromised (attacker can forge valid MACs), (3) there's a padding oracle or truncation issue. A crafted token with `user_id_len = 65535` and a short `token_data` buffer would cause a panic (DoS) rather than returning `None`. The `validate_service_token` function (line 404-427) has the same pattern but uses `offset` tracking that's slightly more careful.
- **Reproduction**:
  1. With knowledge of `master_key`, create a token with `user_id_len = 0xFFFF` and encrypted/MAC'd correctly
  2. Call `validate_token()` → panic (index out of bounds)
- **Fix Complexity**: LOW
- **Remediation**: Add bounds checks before each array access: `if token_data.len() < 2 + user_id_len { return None; }` and similar for subsequent fields. Alternatively, wrap the entire parsing block in a helper that returns `Option` and catches panics.

### SHIELD-A07-023: Rust IdentityProvider Uses Same Derived Key for Encryption AND HMAC in Tokens
- **Severity**: MEDIUM
- **CWE**: CWE-323 (Reusing a Nonce, Key Pair in Encryption)
- **Location**: `shield-core/src/identity.rs:224-237`
- **Evidence**:
```rust
// create_token()
let key = self.derive_key("session");  // Single key for both operations
let keystream = generate_keystream(&key, &nonce, token_data.len());  // Encryption
// ...
let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &key);  // HMAC with SAME key
let tag = hmac::sign(&hmac_key, &hmac_data);

// validate_token() — same pattern
let key = self.derive_key("session");  // Same key derived for both
let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &key);  // HMAC
// ... then used for decryption keystream
```
- **Impact**: The same `derive_key("session")` output is used as both the CTR-mode encryption key and the HMAC authentication key. While this mirrors the main Shield protocol's design (which has the same issue — SHIELD-A01-001), in the identity context it's especially concerning because: (1) the keystream uses `SHA256(key || nonce || counter)` which means the HMAC key appears as a prefix in every keystream block's hash input, creating a relationship between encryption and authentication, (2) cryptographic best practice mandates separate keys for separate purposes (encrypt-then-MAC). Cross-reference: SHIELD-A01-001 (key reuse across encryption and MAC — systemic).
- **Reproduction**: Both operations can be confirmed to use the same 32-byte key by inspecting `derive_key("session")` return value.
- **Fix Complexity**: LOW
- **Remediation**: Derive separate keys: `let enc_key = self.derive_key("session:enc");` and `let mac_key = self.derive_key("session:mac");`. This is a minimal change that significantly improves the cryptographic separation.

### SHIELD-A07-024: Rust IdentityProvider HashMap Not Thread-Safe — Race Conditions Under Concurrent Access
- **Severity**: MEDIUM
- **CWE**: CWE-362 (Concurrent Execution Using Shared Resource with Improper Synchronization)
- **Location**: `shield-core/src/identity.rs:87-91`
- **Evidence**:
```rust
pub struct IdentityProvider {
    master_key: [u8; 32],
    token_ttl: u64,
    users: HashMap<String, UserData>,  // No Mutex/RwLock protection
}

// register() takes &mut self — Rust's borrow checker prevents data races at compile time
// authenticate() takes &self — read-only, safe for concurrent access
// revoke_user() takes &mut self — requires exclusive access
```
- **Impact**: While Rust's borrow checker prevents data races in single-threaded code and `&mut self` methods enforce exclusive access, in a real server scenario (e.g., wrapped in `Arc<Mutex<IdentityProvider>>`), the following TOCTOU races exist: (1) `authenticate()` reads `self.users.get(user_id)` and then performs PBKDF2 — if `revoke_user()` removes the user between the get and the PBKDF2 completion, the authentication succeeds because the `UserData` reference was already obtained, (2) `register()` checks `contains_key()` then inserts — if two concurrent registrations for the same user_id race, neither will see the other's insert. The Python implementation (`identity.py`) has the same issue: `_identities` dict has no locking, and `if user_id in self._identities` followed by assignment is a classic TOCTOU vulnerability (CWE-367).
- **Reproduction**:
  1. Wrap `IdentityProvider` in `Arc<Mutex<>>` for multi-threaded server use
  2. Race `register("alice", "pass1")` and `register("alice", "pass2")` concurrently
  3. Both may pass the `contains_key` check and insert, with last write winning
- **Fix Complexity**: LOW
- **Remediation**: Document that `IdentityProvider` must be protected by external synchronization in multi-threaded contexts, or use `HashMap` entry API for atomic check-and-insert: `match self.users.entry(user_id.to_string()) { Entry::Occupied(_) => return Err(...), Entry::Vacant(e) => e.insert(...) }`.

### SHIELD-A07-025: Rust validate_token Does Not Verify User Still Exists — Tokens Valid After Revocation
- **Severity**: MEDIUM
- **CWE**: CWE-613 (Insufficient Session Expiration)
- **Location**: `shield-core/src/identity.rs:249-309`
- **Evidence**:
```rust
pub fn validate_token(&self, token: &str) -> Option<Session> {
    // ... base64 decode, MAC verify, decrypt, parse ...
    let session = Session {
        user_id,           // Extracted from token
        permissions,
        expires_at: Some(expires_at),
        attributes: HashMap::new(),
    };
    if session.is_expired() {
        return None;
    }
    Some(session)  // Returns session WITHOUT checking self.users.contains_key(&user_id)
}
```
- **Impact**: After `revoke_user()` removes a user from the `users` HashMap, `validate_token()` still returns a valid `Session` for that user because it only checks the token's cryptographic validity and expiration — it never checks if the user still exists in the provider. This is the implementation-level detail behind SHIELD-A07-001 (no revocation mechanism). While A07-001 focused on the Python middleware layer, this finding confirms the same issue exists in the Rust core: `validate_token` is a purely cryptographic operation with no state check. The Python `identity.py` has the same behavior — `validate_token()` only calls `_verify_token()` which checks HMAC and expiry, not user existence. Cross-reference: SHIELD-A07-001.
- **Reproduction**:
  1. Register user, authenticate, get token
  2. `provider.revoke_user("alice")` — removes from HashMap
  3. `provider.validate_token(token)` → returns `Some(Session)` — user is gone but token works
- **Fix Complexity**: LOW
- **Remediation**: Add `if !self.users.contains_key(&user_id) { return None; }` after parsing user_id from token. This provides immediate revocation at the cost of requiring the provider instance to be available for validation (which is already the case since `validate_token` is a method on `IdentityProvider`).

### SHIELD-A07-026: Python SecureSession Key Rotation Uses Current Key as PRNG Seed — Predictable Key Sequence
- **Severity**: MEDIUM
- **CWE**: CWE-330 (Use of Insufficiently Random Values)
- **Location**: `python/shield/identity.py:394-396`
- **Evidence**:
```python
def _maybe_rotate(self) -> bool:
    # ...
    self._current_key = hashlib.sha256(
        self._current_key + struct.pack('<Q', now)
    ).digest()
    # ^^ New key = SHA256(old_key + timestamp)
```
- **Impact**: The key rotation in Python `SecureSession` derives each new key from the previous key concatenated with the current timestamp. If an attacker recovers any single key (e.g., via memory dump), they can compute ALL future keys since they only need the timestamp (which is predictable). The Rust implementation (`identity.rs:499-506`) uses `SHA256(master_key + "session:{version}")` — also deterministic but derived from the master_key, not chained from the previous key. The Python approach creates a forward chain: compromise of key N reveals keys N+1, N+2, etc. The Rust approach limits compromise to only the master_key.
- **Reproduction**:
  1. Recover `_current_key` at time T from memory
  2. Compute `hashlib.sha256(key + struct.pack('<Q', T+3600)).digest()` = next key
  3. Repeat for all future rotations
- **Fix Complexity**: LOW
- **Remediation**: Derive each rotated key from the master key (not the previous key): `self._current_key = hashlib.sha256(session_key + struct.pack('<I', self._key_version)).digest()`. This prevents forward key compromise. Alternatively, mix in `secrets.token_bytes(16)` for each rotation.

### SHIELD-A07-027: BrowserBridge Session Keys Dict Not Thread-Safe — Race Condition on Concurrent Access
- **Severity**: LOW
- **CWE**: CWE-362 (Concurrent Execution Using Shared Resource with Improper Synchronization)
- **Location**: `python/shield/integrations/browser.py:69-88`
- **Evidence**:
```python
class BrowserBridge:
    def __init__(self, password: str, service: str):
        self._session_keys: Dict[str, tuple[bytes, float]] = {}
        # No threading.Lock!

    def generate_client_key(self, session_id: str, ttl: int = 3600, ...):
        session_key = self._derive_session_key(session_id)
        expires_at = time.time() + ttl
        self._session_keys[session_id] = (session_key, expires_at)  # Unprotected write

    def is_session_valid(self, session_id: str) -> bool:
        if session_id not in self._session_keys:     # TOCTOU: check
            return False
        _, expires_at = self._session_keys[session_id]  # TOCTOU: use — may KeyError
        return time.time() < expires_at

    def cleanup_expired(self) -> int:
        # Iterates dict while potentially modified by concurrent generate_client_key
        expired = [sid for sid, (_, exp) in self._session_keys.items() if now >= exp]
        for sid in expired:
            del self._session_keys[sid]  # Deletion during iteration race
```
- **Impact**: `BrowserBridge` manages session keys in a plain dict with no synchronization. In ASGI/multi-threaded deployments: (1) `is_session_valid()` has a TOCTOU vulnerability — session could be deleted between the `not in` check and the dict access, (2) `cleanup_expired()` iterates and deletes from the dict — concurrent `generate_client_key()` may cause `RuntimeError: dictionary changed size during iteration`, (3) `revoke_session()` deletes without locking, potentially racing with `encrypt_for_client()` which reads from the dict. While CPython's GIL prevents data corruption, it does NOT prevent TOCTOU logic bugs or `KeyError`/`RuntimeError` exceptions. Cross-reference: SHIELD-A07-013 (threading.Lock process-local only — same class of issue).
- **Reproduction**:
  1. In a multi-threaded server, call `cleanup_expired()` and `generate_client_key()` concurrently
  2. `RuntimeError: dictionary changed size during iteration` on the cleanup thread
- **Fix Complexity**: LOW
- **Remediation**: Add `threading.Lock()` to `BrowserBridge` and protect all dict access. Or document that `BrowserBridge` is not thread-safe and must be used with external synchronization.

### SHIELD-A07-028: Rust SecureSession.decrypt MAC Verification Includes Version Bytes in Wrong Scope
- **Severity**: LOW
- **CWE**: CWE-345 (Insufficient Verification of Data Authenticity)
- **Location**: `shield-core/src/identity.rs:577-579`
- **Evidence**:
```rust
// SecureSession.decrypt()
// MAC is computed over version + nonce + ciphertext (all bytes before MAC)
let expected_tag = hmac::sign(&hmac_key, &encrypted[..encrypted.len() - 16]);
// This is correct — version is included in MAC scope

// But SecureSession.encrypt() constructs:
// version(4) + nonce(16) + ciphertext + mac(16)
// MAC computed over: version + nonce + ciphertext
hmac_data.extend_from_slice(&version_bytes);   // version
hmac_data.extend_from_slice(&nonce);           // nonce
hmac_data.extend_from_slice(&ciphertext);      // ciphertext
let tag = hmac::sign(&hmac_key, &hmac_data);
```
- **Impact**: The MAC computation in `encrypt()` and `decrypt()` is subtly different. In `encrypt()`, the MAC is computed over explicitly constructed `version + nonce + ciphertext`. In `decrypt()`, it's computed over `encrypted[..encrypted.len() - 16]` which is a slice of the full input. While these happen to produce the same result (both cover version + nonce + ciphertext), the `decrypt` approach has a defensive advantage — it MACs exactly what was received. However, the inconsistency between `encrypt` (explicit construction) and `decrypt` (slice) makes the code fragile: if the wire format ever changes (e.g., adding metadata between version and nonce), `decrypt` would silently include the new bytes in the MAC while `encrypt` would need explicit modification. This is a defense-in-depth observation rather than an exploitable vulnerability.
- **Reproduction**: N/A — currently produces identical results. Risk is future maintainability.
- **Fix Complexity**: LOW
- **Remediation**: Align both methods to use the same MAC construction pattern. Either both explicit or both slice-based.

### SHIELD-A07-029: Python IdentityProvider Does Not Store Password Hash — Only Verification Key
- **Severity**: INFO
- **CWE**: CWE-916 (Use of Password Hash With Insufficient Computational Effort)
- **Location**: `python/shield/identity.py:123-126` vs `shield-core/src/identity.rs:131-138`
- **Evidence**:
```python
# Python register() — stores verification_key, NOT password_hash
salt = hashlib.sha256(f"user:{user_id}".encode()).digest()
user_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
verification_key = hashlib.sha256(b'verify:' + user_key).digest()
# ^^ stored as identity.verification_key

# Rust register() — stores password_hash directly
ring::pbkdf2::derive(..., &salt, password.as_bytes(), &mut password_hash);
// ^^ stored as UserData.password_hash
```
- **Impact**: The Python implementation adds an extra SHA256 hash on top of the PBKDF2 output (`SHA256("verify:" + PBKDF2_output)`). This is not harmful but creates a cross-language divergence: Python and Rust store different values for the same user/password combination, making user database migration between implementations impossible without re-registration. The Rust implementation stores the raw PBKDF2 output. Both approaches are cryptographically sound individually, but the inconsistency prevents SSO federation between Python and Rust identity providers using the same master_key.
- **Reproduction**: Register "alice" with "password" in both Python and Rust — the stored verification values will differ despite same inputs.
- **Fix Complexity**: MEDIUM
- **Remediation**: Align the storage format. Either both use raw PBKDF2 output or both add the `verify:` prefix hashing step. Document the chosen format as protocol specification.

---

## TASK-2-013 Findings — Cookie Security & TOTP/Recovery Codes

### SHIELD-A07-030: EncryptedCookie Not Bound to Client — No IP/User-Agent Binding Enables Cookie Theft Replay
- **Severity**: MEDIUM
- **CWE**: CWE-384 (Session Fixation)
- **Location**: `python/shield/integrations/browser.py:192-203` (EncryptedCookie.encode)
- **Evidence**:
```python
def encode(self, data: dict) -> str:
    payload = {
        "data": data,
        "created_at": int(time.time()),
    }
    if self.options.max_age:
        payload["expires_at"] = int(time.time()) + self.options.max_age
    # ^^ No client binding: no IP, no User-Agent, no fingerprint
    serialized = json.dumps(payload).encode("utf-8")
    encrypted = self.shield.encrypt(serialized)
    return base64.urlsafe_b64encode(encrypted).decode("ascii")
```
- **Impact**: Encrypted cookies contain no binding to the originating client. If an attacker steals a cookie (via XSS in a subdomain, network sniffing before HTTPS redirect, or physical access), they can replay it from any IP address, browser, or device. The cookie payload only contains `data`, `created_at`, and `expires_at` — no client fingerprint. While Shield encryption prevents tampering, it does not prevent replay. Combined with the `max_age=3600` default (1 hour), a stolen cookie provides a 1-hour replay window. This is especially concerning because `EncryptedCookie` stores sensitive data like `{"user_id": "123", "role": "admin"}` (per the docstring example). Cross-reference: SHIELD-A06-006 (no CSRF in cookies).
- **Reproduction**:
  1. Generate cookie on Client A: `cookie.encode({"user_id": "123", "role": "admin"})`
  2. Copy the cookie value to Client B (different IP/browser)
  3. `cookie.decode(stolen_value)` → returns `{"user_id": "123", "role": "admin"}`
- **Fix Complexity**: MEDIUM
- **Remediation**: Include client binding in the cookie payload: `payload["client_ip"] = request.client.host`, `payload["user_agent_hash"] = hashlib.sha256(request.headers["user-agent"].encode()).hexdigest()[:16]`. Verify these on decode. Alternatively, add a separate anti-replay token (nonce) tracked server-side.

### SHIELD-A07-031: EncryptedCookie parse_header Naive Cookie Parsing — Mishandles URL-Encoded Values
- **Severity**: LOW
- **CWE**: CWE-20 (Improper Input Validation)
- **Location**: `python/shield/integrations/browser.py:248-259` (EncryptedCookie.parse_header)
- **Evidence**:
```python
def parse_header(self, cookie_header: str, name: str) -> Optional[dict]:
    cookies = {}
    for part in cookie_header.split(";"):
        part = part.strip()
        if "=" in part:
            key, value = part.split("=", 1)
            cookies[key.strip()] = value.strip()
    # ^^ Does not handle: quoted strings, URL encoding, multiple same-name cookies
```
- **Impact**: The cookie parser uses naive `split(";")` followed by `split("=", 1)`. This fails on: (1) cookie values containing literal semicolons in quoted strings per RFC 6265, (2) cookie values with URL-encoded characters, (3) multiple cookies with the same name (last-write-wins, no deterministic priority). While Shield's encrypted cookies are base64-encoded (avoiding special characters), a malicious cookie injected before the Shield cookie could contain a semicolon that shifts the parsing boundaries, potentially causing the wrong value to be associated with the Shield cookie name. This is a defense-in-depth issue — unlikely to be directly exploitable with base64 values but violates cookie parsing standards.
- **Reproduction**:
  1. Send header: `Cookie: fake=val;ue; session=REAL_ENCRYPTED_VALUE`
  2. Parser splits on `;` → `["fake=val", "ue", "session=REAL_ENCRYPTED_VALUE"]`
  3. `"ue"` has no `=` sign, so it's skipped. But `"fake"` gets value `"val"` instead of `"val;ue"`. Parsing is incorrect.
- **Fix Complexity**: LOW
- **Remediation**: Use Python's `http.cookies.SimpleCookie` or `email.utils` for RFC-compliant cookie parsing. Alternatively, document that the parser only handles simple key=value pairs.

### SHIELD-A07-032: Rust TOTP verify() Silently Overrides window=0 to window=1 — Cannot Disable Window
- **Severity**: LOW
- **CWE**: CWE-697 (Incorrect Comparison)
- **Location**: `shield-core/src/totp.rs:96`
- **Evidence**:
```rust
pub fn verify(&self, code: &str, timestamp: Option<u64>, window: u32) -> bool {
    // ...
    let window = if window == 0 { 1 } else { window };
    // ^^ Caller passes window=0 expecting exact-time-only verification
    // ^^ But gets window=1 (checks ±1 interval = 3 time slots)
```
- **Impact**: A caller who explicitly passes `window=0` intending to only accept the current interval's code gets `window=1` instead, accepting codes from the previous and next intervals (±30 seconds). This is a security-weakening silent default: (1) a code that expired 30 seconds ago would still be accepted, (2) a code from 30 seconds in the future would be accepted, (3) the verification window is 3x wider than requested. The Python implementation does NOT have this behavior — `window=1` is the default parameter, but `window=0` would correctly produce `range(0, 1)` = check only the current interval. This is a cross-language behavioral divergence.
- **Reproduction**:
  1. Rust: `totp.verify(code, Some(timestamp), 0)` → checks ±1 interval (90-second window)
  2. Python: `totp.verify(code, timestamp, window=0)` → checks only current interval (30-second window)
- **Fix Complexity**: LOW
- **Remediation**: Remove the `window=0` override. If the concern is zero window being unhelpful, add a `#[must_use]` doc note instead. Alternatively, make `window=0` mean "check only the current counter value" (no loop offset), which matches the Python behavior.

### SHIELD-A07-033: TOTP verify() Not Replay-Protected — Same Code Valid for Full Window Duration
- **Severity**: MEDIUM
- **CWE**: CWE-294 (Authentication Bypass by Capture-replay)
- **Location**: `shield-core/src/totp.rs:88-111` (Rust), `python/shield/totp.py:114-141` (Python)
- **Evidence**:
```rust
// Rust — verify() checks code against time window, no state tracking
pub fn verify(&self, code: &str, timestamp: Option<u64>, window: u32) -> bool {
    // ... generates codes for current ± window intervals
    // No tracking of previously-verified codes
    // Same code returns true for entire window duration
}
```
```python
# Python — same pattern, no replay tracking
def verify(self, code: str, timestamp=None, window: int = 1) -> bool:
    counter = timestamp // self.interval
    for offset in range(-window, window + 1):
        expected = self._hotp(counter + offset)
        if hmac.compare_digest(code, expected):
            return True  # No tracking that this code was already used
    return False
```
- **Impact**: Neither Rust nor Python TOTP tracks previously-verified codes. A valid code can be replayed multiple times within the acceptance window (default ±1 interval = 90 seconds in Rust, 90 seconds in Python). An attacker who intercepts a TOTP code (shoulder surfing, screen capture, MITM) has a 30-90 second window to replay it. RFC 6238 Section 5.2 RECOMMENDS that verifiers track the last used time-step to prevent replay. This was already noted at a lower granularity as SHIELD-A07-009 (TOTP replay within window, LOW). This finding confirms the systemic nature across both implementations. Cross-reference: SHIELD-A07-009.
- **Reproduction**:
  1. User enters code `123456` at time T
  2. Attacker captures code `123456`
  3. Attacker replays code within 90 seconds → accepted again
- **Fix Complexity**: MEDIUM
- **Remediation**: Track the last successfully verified counter value per user. Reject any code whose counter is ≤ the last verified counter. Add a `last_verified_counter: Option<u64>` field to the TOTP struct. RFC 6238 Section 5.2: "The verifier MUST NOT accept the same time-step window [...] more than once."

### SHIELD-A07-034: Rust TOTP generate() Panics on Pre-Epoch System Clock
- **Severity**: LOW
- **CWE**: CWE-252 (Unchecked Return Value)
- **Location**: `shield-core/src/totp.rs:55-60`
- **Evidence**:
```rust
pub fn generate(&self, timestamp: Option<u64>) -> String {
    let time = timestamp.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()  // Panics if system clock is before 1970-01-01
            .as_secs()
    });
```
- **Impact**: If the system clock is set before UNIX epoch (January 1, 1970), `duration_since(UNIX_EPOCH)` returns `Err` and `.unwrap()` panics, crashing the application. The same pattern appears in `verify()` at line 89-94. While rare on production servers, this can occur on: (1) embedded/IoT devices with no RTC or dead battery, (2) VMs/containers with unconfigured system time, (3) testing environments with mocked time. The Python implementation uses `int(time.time())` which would return a negative value (no panic) but produce incorrect TOTP codes.
- **Reproduction**: Set system clock to 1969-12-31. Call `totp.generate(None)` → panic.
- **Fix Complexity**: LOW
- **Remediation**: Replace `.unwrap()` with `.unwrap_or(0)` or return a `Result<String, ShieldError>` to handle clock errors gracefully.

### SHIELD-A07-035: Recovery Code Entropy Only 32 Bits — Brute-Forceable Without Rate Limiting
- **Severity**: MEDIUM
- **CWE**: CWE-330 (Use of Insufficiently Random Values)
- **Location**: `shield-core/src/totp.rs:204-206` (Rust), `python/shield/totp.py:226-230` (Python)
- **Evidence**:
```rust
// Rust — 4 random bytes = 32 bits per code
let bytes: [u8; 4] = crate::random::random_bytes()?;
let code = format!("{:04X}-{:04X}",
    u16::from_be_bytes([bytes[0], bytes[1]]),
    u16::from_be_bytes([bytes[2], bytes[3]])
);
```
```python
# Python — 4 random bytes = 32 bits per code
code = secrets.token_hex(length // 2).upper()  # length=8 → token_hex(4) → 4 bytes
formatted = f"{code[:4]}-{code[4:]}"
```
- **Impact**: Each recovery code has only 32 bits of entropy (4 bytes). With 10 codes active, an attacker needs on average `2^32 / 10 ≈ 429 million` guesses to find a valid code. Without rate limiting on the recovery code verification endpoint (no rate limiting exists — cross-ref SHIELD-A07-011), at 1000 guesses/second this takes ~5 days. At 10,000 guesses/second (parallel requests), ~12 hours. Google Authenticator uses 8-digit numeric codes (26.6 bits) but enforces strict rate limiting. NIST SP 800-63B recommends at minimum 20 bits of entropy with rate limiting, or 112+ bits without. Shield has neither sufficient entropy nor rate limiting for recovery codes. Cross-reference: SHIELD-A07-016 (no account lockout).
- **Reproduction**:
  1. Enumerate hex codes `0000-0000` through `FFFF-FFFF` (4.3 billion combinations)
  2. With 10 valid codes, expected success at ~429 million attempts
  3. No rate limiting prevents high-speed enumeration
- **Fix Complexity**: LOW
- **Remediation**: Increase to 8 random bytes (64 bits) or 16 bytes (128 bits) per code. Format as `XXXX-XXXX-XXXX-XXXX` for 64-bit codes. Enforce rate limiting on recovery code verification (max 5 attempts per hour). After 10 failed recovery code attempts, lock the account.

### SHIELD-A07-036: Python RecoveryCodes Does Not Remove Used Codes from _codes Set — Memory Leak and State Inconsistency
- **Severity**: LOW
- **CWE**: CWE-459 (Incomplete Cleanup)
- **Location**: `python/shield/totp.py:233-250`
- **Evidence**:
```python
class RecoveryCodes:
    def __init__(self, codes=None):
        self._codes = set(codes)  # All codes
        self._used = set()        # Separate used tracking

    def verify(self, code: str) -> bool:
        # ...
        if formatted in self._codes and formatted not in self._used:
            self._used.add(formatted)  # Adds to _used, but does NOT remove from _codes
            return True
        return False

    @property
    def remaining(self) -> int:
        return len(self._codes) - len(self._used)  # Computed from difference
```
- **Impact**: The Python implementation tracks used codes in a separate `_used` set while keeping all original codes in `_codes`. This means: (1) used recovery codes remain in memory in `_codes` indefinitely — if memory is dumped, all codes (including used ones) are visible, (2) the `codes` property returns ALL codes (including used ones) with no indication of which are consumed, (3) the Rust implementation correctly uses `HashSet::remove()` — the used code is deleted from the set entirely (line 226). This is a cross-language behavioral divergence: Rust codes disappear after use, Python codes persist. Cross-reference: SHIELD-A03-010 (RecoveryCodes HashSet<String> no zeroize — Rust side).
- **Reproduction**:
  1. `rc = RecoveryCodes()`
  2. `code = rc.codes[0]`
  3. `rc.verify(code)` → True
  4. `code in rc._codes` → True (still present!)
  5. `code in rc._used` → True (marked used)
  6. In Rust: `rc.verify(&code)` → True, then `rc.codes()` no longer contains the code
- **Fix Complexity**: LOW
- **Remediation**: Change `verify()` to `self._codes.discard(formatted)` after adding to `_used`, matching the Rust behavior. Or remove the `_used` set entirely and just use `self._codes.remove(formatted)` like Rust does.

### SHIELD-A07-037: Rust TOTP digits Parameter Not Validated — Large Values Cause Panic in 10u32.pow()
- **Severity**: LOW
- **CWE**: CWE-20 (Improper Input Validation)
- **Location**: `shield-core/src/totp.rs:82`
- **Evidence**:
```rust
fn generate_hotp(&self, counter: u64) -> String {
    // ...
    let modulo = 10u32.pow(self.digits as u32);
    //                      ^^ self.digits as u32 — if digits > 9, pow overflows u32
    //                      10^10 = 10_000_000_000 > u32::MAX (4_294_967_295)
    format!("{:0width$}", code % modulo, width = self.digits)
}
```
- **Impact**: If `digits` is set to 10 or higher, `10u32.pow(10)` = 10 billion, which overflows `u32` (max 4.29 billion) and panics in debug mode or wraps in release mode. While digits=6 or digits=8 are standard (RFC 4226 allows 6-8), the constructor accepts any `usize` value: `digits: if digits == 0 { 6 } else { digits }`. An attacker or misconfigured caller passing `digits=10` causes a panic (DoS). The Python implementation avoids this by using Python's arbitrary-precision integers: `10**self.digits` never overflows.
- **Reproduction**: `let totp = TOTP::new(secret, 10, 30); totp.generate(Some(59));` → panic (debug) or wrong code (release).
- **Fix Complexity**: LOW
- **Remediation**: Validate `digits` in the constructor: `digits: digits.clamp(6, 8)` or `assert!(digits >= 6 && digits <= 8)`. RFC 4226 specifies 6-digit minimum, 6-8 digit range for interoperability.

### SHIELD-A07-038: EncryptedCookie decode() Swallows All Exceptions — No Distinction Between Tampered, Expired, and Malformed
- **Severity**: INFO
- **CWE**: CWE-755 (Improper Handling of Exceptional Conditions)
- **Location**: `python/shield/integrations/browser.py:206-219` (EncryptedCookie.decode)
- **Evidence**:
```python
def decode(self, value: str) -> Optional[dict]:
    try:
        encrypted = base64.urlsafe_b64decode(value)
        decrypted = self.shield.decrypt(encrypted)
        payload = json.loads(decrypted)
        if "expires_at" in payload:
            if time.time() > payload["expires_at"]:
                return None  # Expired — returns same None as tampered
        return payload.get("data")
    except Exception:
        return None  # Tampered, malformed, wrong key — all return None
```
- **Impact**: All cookie failure modes return `None` — expired, tampered, malformed, wrong encryption key, base64 corruption. The calling application cannot distinguish between a legitimately expired cookie (prompt re-login) and a tampered cookie (potential attack — should log/alert). While this is a common pattern for cookie handling (fail-closed), it prevents security monitoring: an attacker repeatedly sending tampered cookies would generate no alerts. Cross-reference: SHIELD-A11 (error disclosure) — this is the opposite problem: too little information rather than too much.
- **Reproduction**: `cookie.decode("TAMPERED")` → None. `cookie.decode(expired_value)` → None. Same result for fundamentally different security conditions.
- **Fix Complexity**: LOW
- **Remediation**: Return a typed result instead of `Optional[dict]` — e.g., a `CookieResult` enum/dataclass with states: `valid(data)`, `expired`, `tampered`, `malformed`. The caller can then log tampered cookies as security events while handling expired cookies as normal flow.
