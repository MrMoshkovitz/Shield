# A04 — Input Validation Findings

**Agent**: A04 (Input Validation)
**Phase**: 2
**Priority**: CRITICAL
**Audit Scope**: Ciphertext parsing, parameter validation, type confusion, V1/V2 edge cases across all 12 implementations; CLI input security, file path validation, password exposure; API middleware input validation across FastAPI, Flask, Express.js, BrowserBridge, FIDO2, pgvector
**Date**: 2026-03-01 — 2026-03-02

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 3     |
| MEDIUM   | 16    |
| LOW      | 9     |
| INFO     | 6     |
| **Total**| **34**|

---

### SHIELD-A04-001: Rust pad_len Missing Bounds Validation (CVE-PENDING)
- **Severity**: HIGH
- **CWE**: CWE-20 (Improper Input Validation)
- **Location**: `shield-core/src/shield.rs:300-301`
- **Evidence**:
```rust
let pad_len = decrypted[16] as usize;
let data_start = V2_HEADER_SIZE + pad_len;

if data_start > decrypted.len() {
    return Err(ShieldError::InvalidFormat);
}
```
- **Impact**: Rust is the ONLY V2-capable implementation that does NOT validate `pad_len` against `MIN_PADDING` (32) and `MAX_PADDING` (128). An attacker who can construct authenticated ciphertext (e.g., via key compromise or oracle) could set `pad_len=0`, causing `data_start=17` instead of the expected minimum of 49. This leaks the padding bytes as plaintext, breaking the length obfuscation guarantee of V2 format. Compare with Python (`core.py:243`), JS (`shield.js:210`), Go (`shield.go:283`), and C (`shield.c:501`) which all validate `pad_len < MIN_PADDING || pad_len > MAX_PADDING`.
- **Reproduction**: Create V2 ciphertext with `pad_len=0` in the header. Decrypt with Rust. Observe that random padding bytes are returned as part of plaintext.
- **Fix Complexity**: LOW
- **Remediation**: Add bounds check before using pad_len:
```rust
if pad_len < MIN_PADDING || pad_len > MAX_PADDING {
    return Err(ShieldError::InvalidFormat);
}
```

---

### SHIELD-A04-002: JS `iterations || PBKDF2_ITERATIONS` Falsy Default Treats Zero as 100k
- **Severity**: MEDIUM
- **CWE**: CWE-697 (Incorrect Comparison)
- **Location**: `javascript/src/shield.js:67`
- **Evidence**:
```javascript
const iterations = options.iterations || PBKDF2_ITERATIONS;
```
- **Impact**: JavaScript's `||` operator treats `0`, `null`, `undefined`, `""`, and `false` as falsy. Passing `options.iterations = 0` silently defaults to 100,000 iterations instead of throwing an error. An attacker who can influence options could exploit this to ensure non-zero iterations are always used (which is actually safe), but the semantic confusion means `iterations = 0` appears to be accepted while being silently changed. The real risk: if the code were changed to `??` in the future, `0` would pass through and PBKDF2 with 0 iterations would produce insecure keys.
- **Reproduction**: `new Shield('pw', 'svc', { iterations: 0 })` — key derived with 100k iterations, not 0.
- **Fix Complexity**: LOW
- **Remediation**: Validate explicitly:
```javascript
if (options.iterations !== undefined && (!Number.isInteger(options.iterations) || options.iterations < 1)) {
    throw new Error('iterations must be a positive integer');
}
const iterations = options.iterations || PBKDF2_ITERATIONS;
```

---

### SHIELD-A04-003: JS `options.salt` Type Confusion — String vs Buffer
- **Severity**: MEDIUM
- **CWE**: CWE-843 (Access of Resource Using Incompatible Type)
- **Location**: `javascript/src/shield.js:65-66`
- **Evidence**:
```javascript
const salt = options.salt ||
    crypto.createHash('sha256').update(service).digest();
```
- **Impact**: `options.salt` can be a string or Buffer. `crypto.pbkdf2Sync` accepts both but interprets strings as UTF-8 encoded data, while Buffer is raw bytes. Two callers using the same salt value — one as `"salt"` (string) and one as `Buffer.from("salt")` — will derive the **same key** (since pbkdf2Sync encodes string as UTF-8). However, passing a hex string like `"deadbeef"` vs `Buffer.from("deadbeef", "hex")` will produce **different keys**. No type validation exists.
- **Reproduction**: Compare keys from `new Shield('pw', 'svc', { salt: 'ab' })` vs `new Shield('pw', 'svc', { salt: Buffer.from('ab', 'hex') })` — different keys.
- **Fix Complexity**: LOW
- **Remediation**: Validate salt is a Buffer: `if (options.salt && !Buffer.isBuffer(options.salt)) throw new TypeError('salt must be a Buffer');`

---

### SHIELD-A04-004: JS Exports Internal `generateKeystream()` Function
- **Severity**: MEDIUM
- **CWE**: CWE-749 (Exposed Dangerous Method or Function)
- **Location**: `javascript/src/shield.js:347`
- **Evidence**:
```javascript
module.exports = {
    Shield,
    quickEncrypt,
    quickDecrypt,
    generateKeystream
};
```
- **Impact**: The internal `generateKeystream()` function is exported publicly. This allows any consumer to generate arbitrary keystream blocks from key+nonce without authentication. An attacker with key access can generate keystream for known nonces and XOR with captured ciphertext to recover plaintext, bypassing the intended encrypt/decrypt API. No other implementation exports this function.
- **Cross-Reference**: SHIELD-A02-015 (already reported). This finding confirms from the A04 perspective.
- **Fix Complexity**: LOW
- **Remediation**: Remove `generateKeystream` from `module.exports`.

---

### SHIELD-A04-005: Python `iterations` Parameter Accepts Zero and Negative Values
- **Severity**: HIGH
- **CWE**: CWE-20 (Improper Input Validation)
- **Location**: `python/shield/core.py:60-66`
- **Evidence**:
```python
def __init__(
    self,
    password: str,
    service: str,
    salt: Optional[bytes] = None,
    iterations: int = PBKDF2_ITERATIONS,
    max_age_ms: Optional[int] = 60_000,
):
    ...
    self._key = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, iterations
    )
```
- **Impact**: No validation of the `iterations` parameter. `iterations=0` is accepted by `hashlib.pbkdf2_hmac` and produces a key that is NOT cryptographically derived — it's essentially a hash of the password with the salt. `iterations=1` produces extremely weak key derivation. Negative values raise a ValueError at the C level (CPython), but this is implementation-dependent and not documented. An attacker who can influence the `iterations` parameter can weaken key derivation to trivially brutable levels.
- **Reproduction**: `Shield("password", "service", iterations=1)` — key derived with 1 iteration, breakable in microseconds.
- **Fix Complexity**: LOW
- **Remediation**: Add validation: `if iterations < 10000: raise ValueError("iterations must be at least 10000")`

---

### SHIELD-A04-006: Python `salt` Parameter No Runtime Type Enforcement
- **Severity**: LOW
- **CWE**: CWE-843 (Access of Resource Using Incompatible Type)
- **Location**: `python/shield/core.py:64,79-80`
- **Evidence**:
```python
salt: Optional[bytes] = None,
...
if salt is None:
    salt = hashlib.sha256(service.encode()).digest()
```
- **Impact**: Type hint says `Optional[bytes]` but no runtime enforcement. Passing `salt="string"` will work with `pbkdf2_hmac` (which accepts `bytes | bytearray | memoryview` — but `str` will raise `TypeError: a bytes-like object is required`). The error message is confusing and doesn't indicate it came from salt validation. However, this is mitigated by Python's type error being raised before any crypto operation.
- **Fix Complexity**: LOW
- **Remediation**: Add explicit type check: `if salt is not None and not isinstance(salt, (bytes, bytearray)): raise TypeError("salt must be bytes")`

---

### SHIELD-A04-007: All 12 Implementations Accept Empty Password Without Warning
- **Severity**: MEDIUM
- **CWE**: CWE-521 (Weak Password Requirements)
- **Location**: All implementations — `shield.rs:75`, `core.py:60`, `shield.js:64`, `shield.go:68`, `shield.c:317`, `Shield.java:42`, `Shield.cs:28`, `Shield.swift:19`, `Shield.kt:33`
- **Evidence** (Rust):
```rust
pub fn new(password: &str, service: &str) -> Self {
    let salt = ring::digest::digest(&ring::digest::SHA256, service.as_bytes());
    let mut key = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
        salt.as_ref(),
        password.as_bytes(),
        &mut key,
    );
```
- **Impact**: Empty string `""` is a valid password across all implementations. PBKDF2 with an empty password produces a deterministic key derived solely from the service salt. While PBKDF2 doesn't technically fail with empty input, an empty password means the encryption key is derived from only the service name — which is public information. Any attacker who knows the service name can derive the same key.
- **Fix Complexity**: LOW
- **Remediation**: Either reject empty passwords or emit a warning. Recommended: `if password.is_empty() { return Err(ShieldError::EmptyPassword); }`

---

### SHIELD-A04-008: C# V1-Only Decrypt Does Not Parse V2 — Silent Data Corruption
- **Severity**: MEDIUM
- **CWE**: CWE-20 (Improper Input Validation)
- **Location**: `csharp/Shield/Shield.cs:122-157`
- **Evidence**:
```csharp
private static byte[] DecryptWithKey(byte[] key, byte[] encrypted)
{
    ...
    // Skip 8-byte counter prefix
    byte[] result = new byte[ciphertextLen - 8];
    Array.Copy(decrypted, 8, result, 0, ciphertextLen - 8);
    return result;
}
```
- **Impact**: C# is V1-only. When it receives V2 ciphertext (produced by Rust, Python, JS, Go, or C), it skips only the 8-byte counter and returns `timestamp(8) || pad_len(1) || padding(32-128) || plaintext` as the "decrypted" result. This is silent data corruption — MAC passes (same key, same algorithm), but the returned data includes V2 metadata prepended to the actual plaintext. Same issue affects Swift (`Shield.swift:122-123`) and Kotlin (`Shield.kt:108`).
- **Cross-Reference**: SHIELD-A02-008, SHIELD-A02-009, SHIELD-A02-010 (V1-only implementations producing incorrect output for V2 input). This finding confirms from the input validation perspective — these implementations do not validate the version/format of the decrypted inner data.
- **Fix Complexity**: MEDIUM
- **Remediation**: Implement V2 detection (timestamp range check) in C#/Swift/Kotlin decrypt paths, or at minimum return an error when V2 format is detected.

---

### SHIELD-A04-009: Minimum Ciphertext Size Allows Zero-Byte Plaintext Without Error
- **Severity**: LOW
- **CWE**: CWE-20 (Improper Input Validation)
- **Location**: All implementations — `shield.rs:25`, `core.py:213`, `shield.js:174`, `shield.go:32`, `shield.c:447`, `Shield.java:25`
- **Evidence** (Rust):
```rust
const MIN_CIPHERTEXT_SIZE: usize = NONCE_SIZE + 8 + MAC_SIZE;  // 40 bytes
```
- **Impact**: `MIN_CIPHERTEXT_SIZE = 40` allows exactly `nonce(16) + encrypted_data(8) + mac(16)`. The inner data is `counter(8)` with 0 bytes of actual content. V1 decrypt returns empty bytes. This is technically valid but allows authenticated empty-payload messages that carry no useful data. For V2 format, the minimum should be much higher: `nonce(16) + counter(8) + timestamp(8) + pad_len(1) + min_padding(32) + mac(16) = 81 bytes`. Accepting 40 bytes for V2 ciphertext guarantees V1 fallback path, which may not be the caller's intent.
- **Fix Complexity**: LOW
- **Remediation**: Consider separate min size constants for V1 and V2 format, or document that 40-byte ciphertext forces V1 interpretation.

---

### SHIELD-A04-010: Java/Kotlin `require()` Throws `IllegalArgumentException` for MAC Failure
- **Severity**: LOW
- **CWE**: CWE-390 (Detection of Error Condition Without Action)
- **Location**: `kotlin/src/main/kotlin/ai/guard8/shield/Shield.kt:98`, `java/.../Shield.java:226-228`
- **Evidence** (Kotlin):
```kotlin
require(constantTimeEquals(receivedMac, expectedMac)) { "Authentication failed" }
```
- **Evidence** (Java):
```java
if (!constantTimeEquals(receivedMac, Arrays.copyOf(expectedMac, MAC_SIZE))) {
    throw new SecurityException("Authentication failed");
}
```
- **Impact**: Kotlin uses `require()` which throws `IllegalArgumentException` — a RuntimeException. This is semantically incorrect for an authentication failure (should be SecurityException or a crypto-specific exception). Java correctly uses `SecurityException`. The Kotlin behavior may lead to callers catching the wrong exception type, potentially missing authentication failures in error handling.
- **Cross-Reference**: SHIELD-A02-016 (already reported Kotlin `require()` pattern).
- **Fix Complexity**: LOW
- **Remediation**: Replace Kotlin `require()` with explicit `if (!constantTimeEquals(...)) throw ShieldException.AuthenticationFailed()`.

---

### SHIELD-A04-011: V2 Timestamp Auto-Detection Is Heuristic-Based — False Positives Possible
- **Severity**: INFO
- **CWE**: N/A (Design observation)
- **Location**: All V2-capable implementations — `shield.rs:298`, `core.py:238`, `shield.js:205`, `shield.go:278`, `shield.c:496`
- **Evidence** (Rust):
```rust
if (MIN_TIMESTAMP_MS..=MAX_TIMESTAMP_MS).contains(&timestamp_ms) {
    // This is v2 format
```
- **Impact**: V2 detection relies on bytes 8-16 of decrypted data falling in the range `[1577836800000, 4102444800000]`. This is a heuristic. A V1 plaintext whose first 8 bytes (after counter) happen to decode as a little-endian u64 in this range will be misinterpreted as V2. The probability is non-trivial for random data: the range spans ~2.5 × 10^12 out of ~1.8 × 10^19 possible u64 values = ~1 in 7.2 million. For structured data starting with small ASCII values, the probability is effectively zero.
- **Cross-Reference**: SHIELD-A02-013 (already documented V2 false positive risk).
- **Fix Complexity**: N/A (accepted design tradeoff)
- **Remediation**: Document the false positive risk. Consider adding an explicit version byte in future protocol versions.

---

### SHIELD-A04-012: All Implementations Accept Arbitrary-Length Password Without Bounds
- **Severity**: INFO
- **CWE**: CWE-400 (Uncontrolled Resource Consumption)
- **Location**: All implementations — constructor/init paths
- **Evidence**: No implementation limits password length. PBKDF2 will process arbitrarily long passwords by first hashing them with SHA256 (per RFC 2898 when password > block size).
- **Impact**: An extremely long password (e.g., 1 GB) causes high memory allocation and CPU usage during PBKDF2 derivation. This is a potential DoS vector in server contexts where password length is not externally limited. The 100k PBKDF2 iterations amplify the cost. However, the password is hashed before iteration, so the per-iteration cost is constant — the issue is only the initial hashing of the long password.
- **Fix Complexity**: LOW
- **Remediation**: Consider adding a reasonable password length limit (e.g., 10,000 bytes) at the API level for server-facing integrations.

---

### SHIELD-A04-013: `shield check <password>` Exposes Password in Process List and Shell History
- **Severity**: HIGH
- **CWE**: CWE-214 (Invocation of Process Using Visible Sensitive Information)
- **Location**: `shield-core/src/bin/shield.rs:13,85,191-197`
- **Evidence**:
```rust
// Usage doc (line 13):
//! shield check "your_password"

// Help text (line 85):
//     shield check "MyP@ssw0rd123"

// Implementation (lines 191-197):
fn cmd_check(args: &[String]) -> ExitCode {
    if args.is_empty() {
        eprintln!("Usage: shield check <password>");
        return ExitCode::FAILURE;
    }
    let password = &args[0];
```
- **Impact**: The `check` command takes the password as a positional CLI argument. This exposes the password in three ways: (1) **Process listing**: `ps aux` or `/proc/<pid>/cmdline` shows `shield check MyP@ssw0rd123` to all users on the system; (2) **Shell history**: The command is recorded in `~/.bash_history` / `~/.zsh_history`; (3) **System audit logs**: Process execution may be logged by auditd or similar. The documentation explicitly encourages this pattern with example `shield check "MyP@ssw0rd123"`. Unlike `encrypt`/`decrypt` which support interactive password prompt via `rpassword`, `check` has no prompt fallback — the password MUST be passed as an argument.
- **Reproduction**: Run `shield check "secret123" &` then `ps aux | grep shield` — password visible. Run `history | tail -1` — password in history.
- **Fix Complexity**: LOW
- **Remediation**: Add password prompt fallback when no argument provided:
```rust
fn cmd_check(args: &[String]) -> ExitCode {
    let password = if args.is_empty() {
        match prompt_password("Password to check: ", false) {
            Some(p) => p,
            None => { eprintln!("Error: Password required"); return ExitCode::FAILURE; }
        }
    } else {
        eprintln!("Warning: Password visible in shell history. Use interactive prompt instead.");
        args[0].clone()
    };
```

---

### SHIELD-A04-014: CLI `-p`/`--password` Flag Exposes Password in Process List
- **Severity**: MEDIUM
- **CWE**: CWE-214 (Invocation of Process Using Visible Sensitive Information)
- **Location**: `shield-core/src/bin/shield.rs:77,84-386`, `python/shield/cli.py:165,171`
- **Evidence** (Rust):
```rust
// Help text (line 77):
//     -p, --password <pass>  Password (prefer prompt for security)

// parse_file_args (lines 384-386):
"-p" | "--password" => {
    i += 1;
    password = args.get(i).cloned();
}
```
- **Evidence** (Python):
```python
# cli.py line 165:
encrypt_parser.add_argument("-p", "--password", help="Password (insecure, prefer prompt)")
# cli.py line 171:
decrypt_parser.add_argument("-p", "--password", help="Password (insecure, prefer prompt)")
```
- **Impact**: Both Rust and Python CLIs accept `-p <password>` as a command-line flag for encrypt/decrypt/text operations. The password is visible in `ps aux` and shell history. The help text includes a warning ("prefer prompt for security" / "insecure, prefer prompt") but no runtime warning is emitted when `-p` is actually used. Automated scripts commonly use `-p` for convenience, permanently exposing passwords in CI logs, cron job listings, and process tables.
- **Fix Complexity**: LOW
- **Remediation**: Emit a stderr warning when `-p` is used: `eprintln!("Warning: Password passed as argument — visible in process list. Use interactive prompt or pipe from stdin.");`. Consider supporting `--password-file` or stdin pipe: `shield encrypt file.txt --password-file /path/to/keyfile`.

---

### SHIELD-A04-015: `shield text` Exposes Plaintext Data as CLI Argument
- **Severity**: MEDIUM
- **CWE**: CWE-214 (Invocation of Process Using Visible Sensitive Information)
- **Location**: `shield-core/src/bin/shield.rs:16,86,234-262`
- **Evidence**:
```rust
// Usage doc (line 16):
//! shield text encrypt "secret message" -p password -s service

// Help text (line 86):
//     shield text encrypt "hello" -p mypass -s myservice

// Implementation (lines 256-258):
_ if data.is_none() => {
    data = Some(args[i].clone());
}
```
- **Impact**: The `text` subcommand takes plaintext data as a positional CLI argument. Combined with the `-p` flag, a command like `shield text encrypt "my SSN is 123-45-6789" -p mypassword -s myservice` exposes BOTH the sensitive data AND the password in process listing and shell history. This is the most severe exposure vector in the CLI — it defeats the entire purpose of encryption if the plaintext is permanently recorded in `.bash_history`.
- **Reproduction**: `shield text encrypt "classified info" -p secret123 -s test &` then `ps aux | grep shield`.
- **Fix Complexity**: MEDIUM
- **Remediation**: Support stdin pipe for data: `echo "secret" | shield text encrypt -s myservice`. Add warning when plaintext is passed as argument.

---

### SHIELD-A04-016: No File Path Validation or Traversal Protection in CLI
- **Severity**: MEDIUM
- **CWE**: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- **Location**: `shield-core/src/bin/shield.rs:421-440`, `python/shield/cli.py:64-65,94-95`
- **Evidence** (Rust):
```rust
fn encrypt_file(shield: &Shield, input: &str, output: &str) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(input)?;           // No path validation
    let encrypted = shield.encrypt(&data)?;
    fs::write(output, encrypted)?;          // No path validation
    Ok(())
}

fn decrypt_file(shield: &Shield, input: &str, output: &str) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(input)?;
    let decrypted = shield.decrypt(&data)?;
    fs::write(output, decrypted)?;          // No path validation
    Ok(())
}
```
- **Evidence** (Python):
```python
cipher.encrypt_file(args.file, output)     # No path validation
cipher.decrypt_file(args.file, output)     # No path validation
```
- **Impact**: No path canonicalization, symlink resolution, or traversal validation on input or output file paths. An attacker who can influence CLI arguments (e.g., via a wrapper script or automated pipeline) could: (1) Read arbitrary files via symlink: `ln -s /etc/shadow evil.enc && shield decrypt evil.enc`; (2) Write to arbitrary locations: `shield encrypt data.txt -o /etc/cron.d/malicious`; (3) Traverse directories: `shield encrypt ../../../sensitive/data.txt`. While the CLI is typically user-invoked (same privilege level), in automated/server contexts or setuid scenarios, this is exploitable.
- **Fix Complexity**: LOW
- **Remediation**: Canonicalize paths and optionally restrict to CWD:
```rust
let input = std::fs::canonicalize(input)?;
// Optionally: check input.starts_with(std::env::current_dir()?)
```

---

### SHIELD-A04-017: Output File Overwrite Without Confirmation
- **Severity**: LOW
- **CWE**: CWE-73 (External Control of File Name or Path)
- **Location**: `shield-core/src/bin/shield.rs:123,428`, `python/shield/cli.py:58,65`
- **Evidence** (Rust):
```rust
// Default output overwrites: encrypt adds ".enc" suffix
let output = output.unwrap_or_else(|| format!("{}.enc", file));
// ...
fs::write(output, encrypted)?;  // Silent overwrite
```
- **Evidence** (Python):
```python
output = args.output or args.file + ".enc"
cipher.encrypt_file(args.file, output)  # Silent overwrite
```
- **Impact**: Both Rust and Python CLIs silently overwrite existing output files without any confirmation or `--force` flag. This can cause data loss if the user accidentally encrypts to a file that already contains important data. The default output paths (appending `.enc` / stripping `.enc`) may collide with existing files. In decrypt scenarios, the original plaintext file could be overwritten if it shares the expected output name.
- **Fix Complexity**: LOW
- **Remediation**: Check if output file exists and prompt for confirmation, or require `--force` flag:
```rust
if std::path::Path::new(&output).exists() {
    eprintln!("Output file '{}' already exists. Use --force to overwrite.", output);
    return ExitCode::FAILURE;
}
```

---

### SHIELD-A04-018: Python CLI `-p` Flag Not Validated for Password Strength
- **Severity**: LOW
- **CWE**: CWE-521 (Weak Password Requirements)
- **Location**: `python/shield/cli.py:57,79`
- **Evidence**:
```python
def cmd_encrypt(args: argparse.Namespace) -> int:
    password = args.password or get_password(confirm=True)
    # No password strength check before encrypting
    output = args.output or args.file + ".enc"
    salt = os.path.basename(args.file).encode()
    cipher = StreamCipher.from_password(password, salt)
```
- **Impact**: Unlike the Rust CLI which calls `check_password()` and warns about weak passwords (lines 111-121), the Python CLI performs no password strength validation. A user can encrypt sensitive files with password `"a"` or `""` without any warning. The Python CLI also uses `StreamCipher.from_password()` instead of `Shield()`, bypassing any validation in the Shield constructor.
- **Fix Complexity**: LOW
- **Remediation**: Import and call password strength check before encryption, matching the Rust CLI pattern.

---

### SHIELD-A04-019: `rpassword` Terminal Echo Suppression — Correct but No Clipboard/Paste Protection
- **Severity**: INFO
- **CWE**: N/A (Defense-in-depth observation)
- **Location**: `shield-core/src/bin/shield.rs:402-418`, `shield-core/Cargo.toml:41`
- **Evidence**:
```rust
fn prompt_password(prompt: &str, confirm: bool) -> Option<String> {
    eprint!("{prompt}");
    io::stderr().flush().ok()?;
    let password = rpassword::read_password().ok()?;
    if confirm {
        eprint!("Confirm password: ");
        io::stderr().flush().ok()?;
        let password2 = rpassword::read_password().ok()?;
        if password != password2 {
            eprintln!("Passwords do not match");
            return None;
        }
    }
    Some(password)
}
```
- **Impact**: The `rpassword` v7.3 integration correctly suppresses terminal echo during password input. Password confirmation is performed on encrypt operations. However: (1) The password string remains in process memory until dropped — no explicit zeroization (inherits SHIELD-A03 finding pattern); (2) No protection against clipboard paste attacks or shoulder surfing beyond echo suppression; (3) Python CLI uses `getpass.getpass()` which provides equivalent echo suppression. These are defense-in-depth observations, not vulnerabilities.
- **Fix Complexity**: N/A
- **Remediation**: Consider using `zeroize` on the password string after Shield construction. Document that interactive prompt is the recommended input method.

---

## Verification Matrix

### TASK-2-002 Findings (CLI & File Path Validation)

| Finding ID | Known? | Verified | Status |
|-----------|--------|----------|--------|
| SHIELD-A04-013 | Yes (recon) | YES | `shield check <password>` process/history exposure — CONFIRMED |
| SHIELD-A04-014 | Partial | EXPANDED | `-p` flag exposure — Rust + Python both affected |
| SHIELD-A04-015 | No | NEW | `shield text` plaintext as CLI arg |
| SHIELD-A04-016 | Yes (recon) | YES | No path traversal protection — CONFIRMED |
| SHIELD-A04-017 | No | NEW | Output file silent overwrite |
| SHIELD-A04-018 | No | NEW | Python CLI no password strength check |
| SHIELD-A04-019 | No | NEW | rpassword integration defense-in-depth |

### TASK-2-001 Findings (Ciphertext & Padding)

## Verification Matrix

| Finding ID | Known? | Verified | Status |
|-----------|--------|----------|--------|
| SHIELD-A04-001 | Yes (recon) | YES | Rust ONLY missing pad_len bounds — CONFIRMED |
| SHIELD-A04-002 | Yes (recon) | YES | JS falsy iterations — CONFIRMED |
| SHIELD-A04-003 | Yes (recon) | YES | JS salt type confusion — CONFIRMED |
| SHIELD-A04-004 | Yes (recon) | YES | JS generateKeystream export — cross-ref A02-015 |
| SHIELD-A04-005 | No | NEW | Python iterations=0 accepted |
| SHIELD-A04-006 | No | NEW | Python salt no type check |
| SHIELD-A04-007 | No | NEW | All impls accept empty password |
| SHIELD-A04-008 | Partial | EXPANDED | C#/Swift/Kotlin V1-only silent corruption — confirms A02-008/009/010 |
| SHIELD-A04-009 | Partial | NEW | Min ciphertext allows zero-byte payload |
| SHIELD-A04-010 | Partial | EXPANDED | Kotlin require() wrong exception — confirms A02-016 |
| SHIELD-A04-011 | Yes | CONFIRMED | V2 heuristic false positive — confirms A02-013 |
| SHIELD-A04-012 | No | NEW | No password length limit |

## Audit Checklist Completion

### TASK-2-001: Ciphertext & Padding Input Validation
1. [x] Padding: pad_len bounds check — Rust MISSING (A04-001), all others PASS
2. [x] Minimum ciphertext length: All implementations check — noted zero-byte edge case (A04-009)
3. [x] Type checking: JS salt/iterations issues found (A04-002, A04-003)
4. [x] Iterations: Python accepts 0 (A04-005), JS falsy handling (A04-002)
5. [x] Salt: JS type confusion (A04-003), Python no runtime check (A04-006)
6. [x] Empty password: All accept (A04-007)
7. [x] Module exports: JS exports generateKeystream (A04-004)
8. [x] Version byte: No explicit version byte — heuristic-based (A04-011)
9. [x] Truncated ciphertext: All implementations properly reject via MIN_CIPHERTEXT_SIZE check

### TASK-2-002: CLI Input & File Path Validation
10. [x] CLI password exposure: `shield check <password>` — HIGH (A04-013)
11. [x] CLI `-p` flag exposure: Rust + Python both affected — MEDIUM (A04-014)
12. [x] CLI plaintext exposure: `shield text` data as arg — MEDIUM (A04-015)
13. [x] File path traversal: No validation on input/output paths — MEDIUM (A04-016)
14. [x] Output file overwrite: Silent overwrite without confirmation — LOW (A04-017)
15. [x] Python CLI password strength: No validation unlike Rust CLI — LOW (A04-018)
16. [x] rpassword integration: Echo suppression correct, defense-in-depth notes — INFO (A04-019)

---

### SHIELD-A04-020: Express `shieldRequired` Leaks Decryption Error Details to Client
- **Severity**: MEDIUM
- **CWE**: CWE-209 (Generation of Error Message Containing Sensitive Information)
- **Location**: `javascript/integrations/express.js:148-152`
- **Evidence**:
```javascript
} catch (err) {
    return res.status(400).json({
        error: `Decryption failed: ${err.message}`
    });
}
```
- **Impact**: The `shieldRequired` middleware returns the raw `err.message` from Shield's `decrypt()` function to the client. This can leak internal error details such as "Authentication failed" vs "Invalid format" vs "Ciphertext too short", enabling an attacker to distinguish between MAC failure and format errors — a prerequisite for padding/format oracle attacks. The `shieldErrorHandler` (line 170-178) has the same issue, echoing `err.message` directly.
- **Reproduction**: Send malformed base64 vs truncated ciphertext vs valid-format-but-wrong-key ciphertext to a `shieldRequired` endpoint. Each returns a different error message.
- **Fix Complexity**: LOW
- **Remediation**: Return a generic error: `res.status(400).json({ error: 'Invalid encrypted payload' })`. Log the actual error server-side.

---

### SHIELD-A04-021: Express `shieldMiddleware` Falls Back to Plaintext on Encryption Error
- **Severity**: MEDIUM
- **CWE**: CWE-636 (Not Failing Securely)
- **Location**: `javascript/integrations/express.js:75-79`
- **Evidence**:
```javascript
} catch (err) {
    // On error, send original data
    console.error('Shield encryption error:', err);
    return originalJson(data);
}
```
- **Impact**: If Shield encryption fails for any reason (memory pressure, invalid state, corrupted key), the middleware silently sends the **unencrypted plaintext response** to the client. The client expects encrypted data, but receives plaintext — this is a confidentiality failure. An attacker who can trigger encryption errors (e.g., by exhausting memory or racing Shield state) can force plaintext disclosure of responses that were intended to be encrypted. Note: `shieldProtected` (line 105-114) does NOT have this fallback — it will throw, which is the safer behavior.
- **Reproduction**: Corrupt the Shield instance key or trigger an OOM condition. Observe that `shieldMiddleware`-protected endpoints return plaintext JSON.
- **Fix Complexity**: LOW
- **Remediation**: Either re-throw the error or return a 500: `return res.status(500).json({ error: 'Encryption failed' })`. Never send plaintext when encryption was expected.

---

### SHIELD-A04-022: Express Route Exclusion Uses `startsWith` — Path Traversal Bypass
- **Severity**: MEDIUM
- **CWE**: CWE-20 (Improper Input Validation)
- **Location**: `javascript/integrations/express.js:53-59`
- **Evidence**:
```javascript
if (paths && !paths.some(p => req.path.startsWith(p))) {
    return next();
}

if (excludePaths && excludePaths.some(p => req.path.startsWith(p))) {
    return next();
}
```
- **Impact**: Route matching uses `String.startsWith()` without normalization. If `paths = ["/api"]`, then `/api-public/data` also matches (unintended encryption of public endpoint). If `excludePaths = ["/health"]`, then `/healthz` and `/health-check` are also excluded. More critically, path normalization is not performed: `//api`, `/./api`, `/%61pi` (URL-encoded) may bypass the checks depending on Express's path parsing. The same pattern appears in the FastAPI middleware (`fastapi.py:644-650`) and Flask extension (`flask.py:1361-1366`).
- **Cross-Reference**: Applies to all three frameworks. FastAPI's `exclude_routes` defaults to `["/docs", "/redoc", "/openapi.json"]` — a path like `/docs-internal` would also be excluded.
- **Fix Complexity**: LOW
- **Remediation**: Use exact path matching or ensure paths end with `/`: `excludePaths.some(p => req.path === p || req.path.startsWith(p + '/'))`. Consider URL-decoding and normalizing paths before comparison.

---

### SHIELD-A04-023: FastAPI `shield_protected` Decorator Leaks Decryption Error Detail via HTTPException
- **Severity**: MEDIUM
- **CWE**: CWE-209 (Generation of Error Message Containing Sensitive Information)
- **Location**: `python/shield/integrations/fastapi.py:718`
- **Evidence**:
```python
except (json.JSONDecodeError, KeyError, ValueError) as e:
    raise HTTPException(status_code=400, detail=f"Decryption failed: {e}")
```
- **Impact**: The `shield_protected` decorator with `encrypt_request=True` leaks exception details to the client. The `{e}` includes the specific Python exception message (e.g., `"MAC verification failed"`, `"Invalid ciphertext length"`, JSON parse errors). This enables an attacker to distinguish error types and build oracle-based attacks. Compare with Flask's `_before_request` which swallows errors silently (different but also problematic — see A04-024).
- **Fix Complexity**: LOW
- **Remediation**: `raise HTTPException(status_code=400, detail="Invalid encrypted request")`

---

### SHIELD-A04-024: Flask `_before_request` Silently Swallows Decryption Errors
- **Severity**: MEDIUM
- **CWE**: CWE-390 (Detection of Error Condition Without Action)
- **Location**: `python/shield/integrations/flask.py:1382-1383`
- **Evidence**:
```python
except Exception:
    pass  # Let the route handle invalid data
```
- **Impact**: When the Flask extension receives an encrypted request body that fails decryption (invalid MAC, corrupted data, wrong key), it silently ignores the error and lets the request proceed with the original (encrypted/garbled) body. The route handler then receives raw encrypted data as if it were a normal JSON request, likely causing an unhandled exception or data corruption. Similarly, `_after_request` (line 1404) silently swallows encryption errors and returns the plaintext response — same fail-open pattern as Express `shieldMiddleware` (A04-021).
- **Fix Complexity**: LOW
- **Remediation**: Return a 400 error on decryption failure: `abort(400, description="Invalid encrypted request")`. For `_after_request`, return 500 on encryption failure instead of plaintext.

---

### SHIELD-A04-025: BrowserBridge `session_id` No Format or Length Validation
- **Severity**: MEDIUM
- **CWE**: CWE-20 (Improper Input Validation)
- **Location**: `python/shield/integrations/browser.py:224-232`
- **Evidence**:
```python
def _derive_session_key(self, session_id: str) -> bytes:
    """Derive a session-specific key."""
    master = self.shield.key
    return hmac.new(
        master,
        session_id.encode("utf-8"),
        hashlib.sha256,
    ).digest()
```
- **Impact**: The `session_id` parameter is used directly as HMAC input with no validation. An attacker can: (1) Pass empty string `""` — derives a session key from just the master key, which is deterministic and predictable; (2) Pass extremely long strings — the `session_id.encode("utf-8")` allocates a large buffer (DoS); (3) Pass any type that has `.encode()` — no type enforcement. The `generate_client_key()` method (line 192) passes this session_id to the client in the response, and `encrypt_for_client()`/`decrypt_from_client()` derive keys from it. An attacker controlling `session_id` controls which derived key is used, potentially causing key confusion between sessions.
- **Fix Complexity**: LOW
- **Remediation**: Validate session_id format and length: `if not session_id or len(session_id) > 256: raise ValueError("Invalid session_id")`. Consider requiring a specific format (UUID, hex, alphanumeric).

---

### SHIELD-A04-026: BrowserBridge Exposes Raw Master Key via `self.shield.key`
- **Severity**: MEDIUM
- **CWE**: CWE-200 (Exposure of Sensitive Information)
- **Location**: `python/shield/integrations/browser.py:227`
- **Evidence**:
```python
master = self.shield.key
```
- **Impact**: The `_derive_session_key` method accesses the raw master encryption key via `self.shield.key`. This is the same key used for all Shield encrypt/decrypt operations. The key is stored as a Python `bytes` object on the heap, and is referenced (not copied) into the `hmac.new()` call. While this access is necessary for the HMAC derivation, it means: (1) The master key is accessible as a Python attribute with no access control; (2) Any code with a reference to the `BrowserBridge` instance can extract the master key via `.shield.key`; (3) The key is never zeroized after use.
- **Cross-Reference**: SHIELD-A03-026 (all 12 impls expose raw key unconditionally). This confirms the pattern in the integration layer.
- **Fix Complexity**: MEDIUM
- **Remediation**: Consider using a dedicated HKDF derivation instead of exposing the master key for session derivation.

---

### SHIELD-A04-027: Express `shieldErrorHandler` Exposes Internal Error Messages
- **Severity**: LOW
- **CWE**: CWE-209 (Generation of Error Message Containing Sensitive Information)
- **Location**: `javascript/integrations/express.js:170-178`
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
- **Impact**: The dedicated error handler echoes `err.message` in the JSON response. While the `error` field is generic, the `message` field contains the specific Shield error which can differentiate MAC failures from format errors, enabling oracle attacks. Less severe than A04-020 because this handler is optional (must be explicitly added by the developer), but still leaks information when used.
- **Fix Complexity**: LOW
- **Remediation**: Remove `message: err.message` from the response. Log it server-side instead.

---

### SHIELD-A04-028: FIDO2 API Issues Unsigned Token After Login — No Shield Encryption
- **Severity**: MEDIUM
- **CWE**: CWE-345 (Insufficient Verification of Data Authenticity)
- **Location**: `python/shield/integrations/fido2_api.py:1172-1176`
- **Evidence**:
```python
token_payload = {
    "sub": username,
    "iat": time.time(),
    "exp": time.time() + 3600,
}
token = base64.urlsafe_b64encode(json.dumps(token_payload).encode()).decode()
```
- **Impact**: After successful FIDO2 authentication, the API returns an access token that is merely base64-encoded JSON — **not signed, not encrypted**. Any client can forge tokens by creating `{"sub": "admin", "iat": ..., "exp": ...}` and base64-encoding it. The comment says "use Shield IdentityProvider in production" but this code ships as a working example in the SDK. Developers copying this pattern will have zero authentication on their tokens.
- **Fix Complexity**: LOW
- **Remediation**: Use `ShieldTokenAuth.create_token()` or at minimum sign the token with HMAC. The infrastructure already exists in the same package.

---

### SHIELD-A04-029: FIDO2 API No Attestation Verification — Comment-Only Security
- **Severity**: LOW
- **CWE**: CWE-345 (Insufficient Verification of Data Authenticity)
- **Location**: `python/shield/integrations/fido2_api.py:1074-1076,1167`
- **Evidence**:
```python
# In production, verify attestation object and signature
...
# In production: verify signature with public key
# For now, just generate a token
```
- **Impact**: The FIDO2 registration endpoint stores credentials without verifying the attestation object or signature. The login endpoint accepts any `credential_id` match without verifying the authenticator signature. This means registration and login are effectively unauthenticated — an attacker can register arbitrary credentials and "authenticate" with any known credential ID. Marked LOW because the file header explicitly states this is a "simplified implementation demonstrating the API structure", but the code is importable and usable as-is.
- **Fix Complexity**: MEDIUM
- **Remediation**: Add a prominent runtime warning on import and consider requiring an explicit `demo_mode=True` flag to allow unverified attestation.

---

### SHIELD-A04-030: pgvector API Stores Plaintext Vectors Alongside Encrypted
- **Severity**: LOW
- **CWE**: CWE-312 (Cleartext Storage of Sensitive Information)
- **Location**: `python/shield/integrations/pgvector_api.py:1881-1882`
- **Evidence**:
```python
"plaintext": request.vector,  # For testing (remove in production)
```
- **Impact**: The vector insert endpoint stores the plaintext vector alongside the encrypted version with a comment "For testing (remove in production)". The search endpoint (line 1931) uses the plaintext directly: `decrypted = vector_data["plaintext"]`. This means the encryption is decorative — all sensitive embedding data is stored in cleartext in memory. Marked LOW because the comment acknowledges this is testing code, but shipped in the SDK.
- **Fix Complexity**: LOW
- **Remediation**: Remove `"plaintext"` storage. Use `self._decrypt_vector(encrypted)` in the search path.

---

### SHIELD-A04-031: pgvector `secret_key` Defaults to Hardcoded Value
- **Severity**: LOW
- **CWE**: CWE-1188 (Insecure Default Initialization of Resource)
- **Location**: `python/shield/integrations/pgvector_api.py:1747`
- **Evidence**:
```python
self.secret_key = secret_key or "default-secret-key"
```
- **Impact**: If no `secret_key` is provided, the pgvector router uses a hardcoded `"default-secret-key"` for token validation. The `_verify_token` method (line 1758) does minimal validation (only checks token length > 10), so the hardcoded key is currently not used for actual crypto, but the pattern is dangerous if the verification is later improved.
- **Fix Complexity**: LOW
- **Remediation**: Raise an error if `require_auth=True` and no `secret_key` is provided: `if require_auth and not secret_key: raise ValueError("secret_key required when require_auth=True")`

---

### SHIELD-A04-032: pgvector Token Verification Only Checks Length — No Crypto Validation
- **Severity**: MEDIUM
- **CWE**: CWE-287 (Improper Authentication)
- **Location**: `python/shield/integrations/pgvector_api.py:1764-1769`
- **Evidence**:
```python
def _verify_token(
    self, credentials: HTTPAuthorizationCredentials
) -> Dict[str, Any]:
    try:
        token = credentials.credentials
        if len(token) < 10:
            raise ValueError("Invalid token")
        return {"user_id": "authenticated_user"}
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
```
- **Impact**: The token verification method accepts ANY string longer than 10 characters as a valid authentication token, always returning `user_id: "authenticated_user"`. This means `require_auth=True` provides no actual authentication — any client can access all vector operations by sending any Bearer token. Combined with the `"default-secret-key"` default (A04-031), this is effectively an open API.
- **Fix Complexity**: MEDIUM
- **Remediation**: Use `ShieldTokenAuth.validate_token()` or implement proper HMAC-based token validation using the `secret_key`.

---

### SHIELD-A04-033: APIProtector Silently Skips Invalid IP Addresses in Blacklist Check
- **Severity**: LOW
- **CWE**: CWE-20 (Improper Input Validation)
- **Location**: `python/shield/integrations/protection.py:2465-2466`
- **Evidence**:
```python
except ValueError:
    pass
```
- **Impact**: In `check_request()`, if `client_ip` is not a valid IP address (e.g., `"not-an-ip"`, `"127.0.0.1:8080"` with port, IPv6 in unexpected format), the blacklist check silently passes. The whitelist check (line 2480) correctly returns `CheckResult(allowed=False, reason="Invalid IP address")` for invalid IPs when `require_whitelist` is True, but the blacklist check has no such guard. An attacker could bypass IP blacklisting by sending a malformed IP in headers (e.g., `X-Forwarded-For: 1.2.3.4, not-valid`).
- **Fix Complexity**: LOW
- **Remediation**: Reject invalid IP addresses in the blacklist check: `except ValueError: return self.CheckResult(allowed=False, reason="Invalid IP address")`.

---

### SHIELD-A04-034: SecureCORS `allow_all` with `allow_credentials` Creates Insecure CORS Configuration
- **Severity**: INFO
- **CWE**: CWE-942 (Overly Permissive Cross-domain Whitelist)
- **Location**: `python/shield/integrations/browser.py:431,459-464`
- **Evidence**:
```python
self.allow_all = "*" in allowed_origins
...
if self.allow_credentials:
    headers["Access-Control-Allow-Origin"] = origin
    headers["Access-Control-Allow-Credentials"] = "true"
else:
    headers["Access-Control-Allow-Origin"] = "*" if self.allow_all else origin
```
- **Impact**: When `allow_all=True` (wildcard origin) and `allow_credentials=True` (the default), the code avoids sending `Access-Control-Allow-Origin: *` (which browsers reject with credentials) and instead reflects the requesting origin. This effectively allows any origin to make credentialed requests — the most permissive CORS configuration possible. While the code correctly avoids the browser-rejected `*` + credentials combination, it does so by reflecting the origin, which achieves the same insecure effect.
- **Fix Complexity**: LOW
- **Remediation**: Warn or reject configuration when `allow_all=True` and `allow_credentials=True`. This combination should require explicit opt-in.

---

## Verification Matrix

### TASK-2-003 Findings (API & Middleware Input Validation)

| Finding ID | Known? | Verified | Status |
|-----------|--------|----------|--------|
| SHIELD-A04-020 | No | NEW | Express shieldRequired leaks decrypt error details |
| SHIELD-A04-021 | No | NEW | Express shieldMiddleware falls back to plaintext |
| SHIELD-A04-022 | Yes (recon) | EXPANDED | Route exclusion startsWith bypass — all 3 frameworks |
| SHIELD-A04-023 | No | NEW | FastAPI shield_protected leaks decrypt error detail |
| SHIELD-A04-024 | No | NEW | Flask _before_request silently swallows decrypt errors |
| SHIELD-A04-025 | No | NEW | BrowserBridge session_id no validation |
| SHIELD-A04-026 | Partial | EXPANDED | BrowserBridge exposes master key — confirms A03-026 |
| SHIELD-A04-027 | No | NEW | Express shieldErrorHandler echoes err.message |
| SHIELD-A04-028 | No | NEW | FIDO2 API issues unsigned/unencrypted token |
| SHIELD-A04-029 | No | NEW | FIDO2 API no attestation verification |
| SHIELD-A04-030 | No | NEW | pgvector stores plaintext alongside encrypted |
| SHIELD-A04-031 | No | NEW | pgvector hardcoded default secret_key |
| SHIELD-A04-032 | No | NEW | pgvector token verification length-only check |
| SHIELD-A04-033 | No | NEW | APIProtector skips invalid IPs in blacklist |
| SHIELD-A04-034 | No | NEW | SecureCORS allow_all + credentials = reflect origin |

### TASK-2-003: API & Middleware Input Validation
17. [x] Express decrypt error disclosure: shieldRequired + shieldErrorHandler leak err.message — MEDIUM (A04-020, A04-027)
18. [x] Express encryption failure fallback: shieldMiddleware sends plaintext on error — MEDIUM (A04-021)
19. [x] Route exclusion bypass: startsWith without normalization — all 3 frameworks — MEDIUM (A04-022)
20. [x] FastAPI decrypt error disclosure: shield_protected leaks exception detail — MEDIUM (A04-023)
21. [x] Flask silent error swallowing: _before_request ignores decrypt failure — MEDIUM (A04-024)
22. [x] BrowserBridge session_id validation: No format/length checks on HMAC key input — MEDIUM (A04-025)
23. [x] BrowserBridge key exposure: Accesses raw master key — confirms A03-026 — MEDIUM (A04-026)
24. [x] FIDO2 unsigned token: base64-only token after authentication — MEDIUM (A04-028)
25. [x] FIDO2 no attestation: Registration/login without crypto verification — LOW (A04-029)
26. [x] pgvector plaintext storage: Encryption is decorative — LOW (A04-030)
27. [x] pgvector hardcoded secret: default-secret-key fallback — LOW (A04-031)
28. [x] pgvector token bypass: Length-only auth check — MEDIUM (A04-032)
29. [x] APIProtector invalid IP bypass: Silently passes blacklist on invalid IP — LOW (A04-033)
30. [x] SecureCORS permissive CORS: Wildcard + credentials = reflect origin — INFO (A04-034)
