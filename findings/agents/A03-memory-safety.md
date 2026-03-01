# A03 — Memory Safety: Key Zeroization Audit

**Agent**: A03 (Memory Safety)
**Task**: TASK-1-010 — Key Zeroization Verification Across All Languages
**Date**: 2026-03-01
**Iteration**: 10

---

## Findings

### SHIELD-A03-001: Rust — 6 Structs with Key Material Missing Zeroize/ZeroizeOnDrop

- **Severity**: HIGH
- **CWE**: CWE-244 (Improper Clearing of Heap Memory Before Release)
- **Location**: Multiple files in `shield-core/src/`
- **Evidence**:

**Structs WITH Zeroize (correct):**
| Struct | File | Line |
|--------|------|------|
| Shield | shield.rs:52 | `#[derive(Zeroize, ZeroizeOnDrop)]` |
| RatchetSession | ratchet.rs:24 | `#[derive(Zeroize, ZeroizeOnDrop)]` |
| SymmetricSignature | signatures.rs:17 | `#[derive(Zeroize, ZeroizeOnDrop)]` |
| LamportSignature | signatures.rs:155 | `#[derive(Zeroize, ZeroizeOnDrop)]` |
| TOTP | totp.rs:22 | `#[derive(Zeroize, ZeroizeOnDrop)]` |

**Structs MISSING Zeroize (key material persists after drop):**
| Struct | File | Line | Key Field(s) |
|--------|------|------|-------------|
| GroupEncryption | group.rs:103 | `group_key: [u8; 32]`, `members: HashMap<String, [u8; 32]>` |
| BroadcastEncryption | group.rs:211 | Contains group key via GroupEncryption |
| StreamCipher | stream.rs:23 | `key: [u8; 32]` |
| KeyRotationManager | rotation.rs:15 | `keys: HashMap<u32, [u8; 32]>` |
| HandshakeState | channel.rs:118 | `local_contribution: [u8; 32]`, `remote_contribution: Option<[u8; 32]>` |
| SecureSession | identity.rs:463 | `master_key: [u8; 32]`, `keys: HashMap<u32, [u8; 32]>` |

```rust
// group.rs:103 — NO Zeroize derive, holds group_key: [u8; 32]
pub struct GroupEncryption {
    group_key: [u8; 32],
    members: HashMap<String, [u8; 32]>,
}

// stream.rs:23 — NO Zeroize derive, holds key: [u8; 32]
pub struct StreamCipher {
    key: [u8; 32],
    chunk_size: usize,
}

// rotation.rs:15 — NO Zeroize derive, holds keys: HashMap<u32, [u8; 32]>
pub struct KeyRotationManager {
    keys: HashMap<u32, [u8; 32]>,
    current_version: u32,
}

// channel.rs:118 — NO Zeroize, holds local_contribution: [u8; 32]
struct HandshakeState {
    salt: [u8; 16],
    local_contribution: [u8; 32],
    remote_contribution: Option<[u8; 32]>,
    is_initiator: bool,
}

// identity.rs:463 — NO Zeroize, holds master_key + versioned keys
pub struct SecureSession {
    master_key: [u8; 32],
    rotation_interval: u64,
    max_old_keys: usize,
    key_version: u32,
    keys: HashMap<u32, [u8; 32]>,
    last_rotation: u64,
}
```

- **Impact**: When these structs are dropped, key material remains in memory (heap). An attacker with memory access (heap inspection, core dump, cold boot) can recover encryption keys. GroupEncryption is especially critical — it holds keys for all group members.
- **Reproduction**: Create a `GroupEncryption` or `StreamCipher`, drop it, read the heap. Key bytes will still be present.
- **Fix Complexity**: LOW — Add `#[derive(Zeroize, ZeroizeOnDrop)]` and `#[zeroize(skip)]` on non-secret fields. `HashMap` values need manual `Drop` impl since `HashMap<K, [u8; 32]>` doesn't auto-derive Zeroize.
- **Remediation**: Add `Zeroize`+`ZeroizeOnDrop` derives to all 6 structs. For `HashMap`-containing structs, implement `Drop` to iterate and zero each value before clearing.

---

### SHIELD-A03-002: Python — No Key Zeroization (GC-Dependent)

- **Severity**: MEDIUM
- **CWE**: CWE-244 (Improper Clearing of Heap Memory Before Release)
- **Location**: `python/shield/core.py:82`, `python/shield/totp.py:50`, `python/shield/stream.py:81`
- **Evidence**:

```python
# core.py:82 — key derived, stored as self._key, never wiped
self._key = hashlib.pbkdf2_hmac(
    'sha256', password.encode(), salt, iterations, dklen=32
)

# totp.py:50 — secret stored, never wiped
self.secret = secret

# stream.py:81 — key stored, never wiped
self.key = key
```

No `del self._key`, no `gc.collect()`, no `ctypes.memset()` anywhere in Python codebase. `self._key` persists in memory until garbage collected (non-deterministic).

- **Impact**: Key material remains in Python process memory indefinitely. Python's GC does not guarantee timely collection. `bytes` objects are immutable — even if deleted, copies may exist in interpreter internals.
- **Reproduction**: `s = Shield("password", "service"); del s` — key bytes persist on heap.
- **Fix Complexity**: MEDIUM — Python `bytes` are immutable. Need `bytearray` + `ctypes.memset()` pattern for reliable zeroization. Requires refactoring key storage from `bytes` to `bytearray`.
- **Remediation**: Store keys as `bytearray`, implement `__del__` or context manager `__exit__` that calls `ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(self._key)), 0, len(self._key))`.

---

### SHIELD-A03-003: JavaScript — No Key Zeroization (GC-Dependent)

- **Severity**: MEDIUM
- **CWE**: CWE-244 (Improper Clearing of Heap Memory Before Release)
- **Location**: `javascript/src/shield.js:70`, `javascript/src/totp.js:23`, `javascript/src/stream.js:97`
- **Evidence**:

```javascript
// shield.js:70 — key derived as Buffer, stored, never wiped
this._key = crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256');

// shield.js:281 — key exposed as return value
return this._key;

// totp.js:23 — secret stored, never wiped
this.secret = secret;

// stream.js:97 — key stored, never wiped
this.key = key;
```

No `buffer.fill(0)` or `.fill(0)` anywhere for key cleanup. `getKey()` returns raw `this._key` reference (already captured as SHIELD-A02-015 for `generateKeystream` export, but `getKey()` itself is the key accessor pattern across all impls).

- **Impact**: Key material persists in Node.js/V8 heap until GC. No mechanism for explicit zeroization.
- **Reproduction**: `const s = new Shield("password", "service"); s = null;` — key bytes persist.
- **Fix Complexity**: LOW — Add `wipe()` method: `this._key.fill(0); this._key = null;`. Buffer.fill(0) is reliable in Node.js.
- **Remediation**: Add `wipe()` method to Shield, TOTP, StreamCipher classes that calls `this._key.fill(0)` then sets to `null`.

---

### SHIELD-A03-004: Go — No Key Zeroization

- **Severity**: MEDIUM
- **CWE**: CWE-244 (Improper Clearing of Heap Memory Before Release)
- **Location**: `go/shield/shield.go:70-73`, `go/shield/stream.go:34`, `go/shield/identity.go:179-185`
- **Evidence**:

```go
// shield.go:70-73 — key derived, copied to fixed array, never zeroed
key := pbkdf2.Key([]byte(password), salt[:], Iterations, KeySize, sha256.New)
copy(s.key[:], key)
// 'key' local variable never zeroed either

// shield.go:106 — key exposed as slice, never zeroed
return s.key[:]

// identity.go:279 — session key derived, never zeroed
copy(session.key[:], h.Sum(nil))
```

No `for i := range key { key[i] = 0 }` pattern anywhere in Go codebase. Local `key` variables from `pbkdf2.Key()` are abandoned to GC without zeroing.

- **Impact**: Key material persists in Go heap. Go GC is non-deterministic. The intermediate `key` local variable from `pbkdf2.Key()` creates a second copy that's never cleaned.
- **Reproduction**: Create Shield, check heap for key bytes after setting to nil.
- **Fix Complexity**: LOW — Add `Wipe()` method: `for i := range s.key { s.key[i] = 0 }`. Also zero the local `key` var in constructors.
- **Remediation**: Add `Wipe()` to Shield, StreamCipher, Identity, Session structs. Zero local `key` variables immediately after `copy()`.

---

### SHIELD-A03-005: RecoveryCodes (Rust) — Secret Codes Stored as String (Immutable, Cannot Zeroize)

- **Severity**: LOW
- **CWE**: CWE-244 (Improper Clearing of Heap Memory Before Release)
- **Location**: `shield-core/src/totp.rs:184`
- **Evidence**:

```rust
// totp.rs:184 — No Zeroize, codes stored as HashSet<String>
pub struct RecoveryCodes {
    codes: HashSet<String>,
    original_count: usize,
}
```

Recovery codes are stored as `String` in a `HashSet`. While `String` technically supports zeroization via the `zeroize` crate, `HashSet` doesn't implement `Zeroize`. The codes are secret authentication material.

- **Impact**: Recovery codes persist in memory after struct is dropped. Recovery codes are high-value targets — they bypass 2FA.
- **Reproduction**: Create `RecoveryCodes`, drop it, inspect heap.
- **Fix Complexity**: MEDIUM — Need custom `Drop` that iterates `HashSet`, zeros each `String`'s backing buffer, then clears.
- **Remediation**: Implement custom `Drop` for `RecoveryCodes` that iterates and zeroizes each code string before clearing the set.

---

### SHIELD-A03-006: C# SecureWipe Uses Array.Clear — May Be Optimized Away

- **Severity**: LOW
- **CWE**: CWE-14 (Compiler Removal of Code to Clear Buffers)
- **Location**: `csharp/Shield/Shield.cs:220-223`
- **Evidence**:

```csharp
// Shield.cs:220-223
public static void SecureWipe(byte[] data)
{
    Array.Clear(data, 0, data.Length);
}
```

Uses `Array.Clear()` instead of `CryptographicOperations.ZeroMemory()` (.NET 6+). The JIT compiler may optimize away `Array.Clear()` if it determines the array isn't read after clearing.

- **Impact**: Key material may not actually be wiped if the JIT optimizes the clear operation away. Risk is theoretical but well-documented in .NET security guidance.
- **Fix Complexity**: LOW — Replace with `CryptographicOperations.ZeroMemory(data)`.
- **Remediation**: Use `System.Security.Cryptography.CryptographicOperations.ZeroMemory()` which is guaranteed not to be optimized away.

---

### SHIELD-A03-007: Swift/Kotlin secureWipe — Simple Loop May Be Optimized Away

- **Severity**: LOW
- **CWE**: CWE-14 (Compiler Removal of Code to Clear Buffers)
- **Location**: `swift/Sources/Shield/Shield.swift:204-208`, `kotlin/src/main/kotlin/ai/guard8/shield/Shield.kt:163-164`
- **Evidence**:

```swift
// Swift — Shield.swift:204-208
public static func secureWipe(_ data: inout [UInt8]) {
    for i in 0..<data.count {
        data[i] = 0
    }
}
```

```kotlin
// Kotlin — Shield.kt:163-164
fun secureWipe(data: ByteArray) {
    data.fill(0)
}
```

Both use simple loops/fill to zero memory. Swift's optimizer and Kotlin's JIT may optimize these away when the data is not read after zeroing. Neither uses a volatile/opaque pattern to prevent optimization.

- **Impact**: Key material may persist despite calling `wipe()`. Compiler optimizations can eliminate "dead stores" (writes to data that's never read again).
- **Fix Complexity**: LOW — Swift: use `withUnsafeMutableBytes { memset_s($0.baseAddress, ...) }`. Kotlin/JVM: use `java.util.Arrays.fill()` which is less likely to be optimized but not guaranteed.
- **Remediation**: Swift: Use `memset_s` or `SecureEnclave`-backed zeroing. Kotlin: Use `java.security.SecureRandom` read-then-zero pattern or JNI call.

---

### SHIELD-A03-008: Java/C/Swift/Kotlin Manual Wipe Not Automatic — Caller Must Invoke

- **Severity**: INFO
- **CWE**: CWE-404 (Improper Resource Shutdown or Release)
- **Location**: Multiple — see table
- **Evidence**:

| Language | Wipe Method | Auto? | Pattern |
|----------|-------------|-------|---------|
| C | `shield_wipe(ctx)` | Manual | Caller must call |
| Java | `shield.wipe()` | Manual | Caller must call |
| C# | `Dispose()` via IDisposable | Semi-auto | `using` block or manual |
| Swift | `wipe()` | Manual | Caller must call |
| Kotlin | `close()` via Closeable | Semi-auto | `use {}` block or manual |

C# and Kotlin implement `IDisposable`/`Closeable` which enables `using`/`use` blocks for semi-automatic cleanup. Java/C/Swift require explicit `wipe()` calls. If a caller forgets to call `wipe()`, keys persist.

Tests consistently call `wipe()` (e.g., `java/src/test/java/.../ShieldTest.java` calls `shield.wipe()` after every test), but application code has no enforcement mechanism.

- **Impact**: Caller responsibility means key leaks on any error path where `wipe()` is not called. No compile-time or runtime enforcement.
- **Fix Complexity**: MEDIUM — Java: implement `AutoCloseable`. C: document prominently. Swift: implement `deinit`.
- **Remediation**: Document wipe requirement prominently. Consider `AutoCloseable`/`Closeable` for Java. Consider finalizer/destructor patterns as safety nets.

---

### SHIELD-A03-009: C shield_secure_wipe Uses Volatile Pointer — Correct Pattern Verified

- **Severity**: INFO
- **CWE**: N/A (Positive finding)
- **Location**: `c/src/shield.c:258-263`
- **Evidence**:

```c
void shield_secure_wipe(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}
```

Uses `volatile uint8_t *` pointer to prevent compiler optimization. This is a correct and well-established pattern for secure memory wiping in C. Preferred over `memset()` which can be optimized away. `explicit_bzero()` or `memset_s()` would also work but have portability concerns.

All C structs (`shield_t`, `shield_stream_t`, `shield_ratchet_t`, `shield_signature_t`, `shield_recovery_t`) have dedicated `_wipe()` functions that call `shield_secure_wipe()`.

- **Impact**: Positive — C implementation correctly prevents compiler optimization of memory wiping.
- **Remediation**: None required.

---

### SHIELD-A03-010: WASM Wrappers Inherit Rust Zeroize via Inner Struct

- **Severity**: INFO
- **CWE**: N/A (Positive finding)
- **Location**: `shield-core/src/wasm.rs:45-47`
- **Evidence**:

```rust
// wasm.rs:45 — WasmShield wraps Shield (which has ZeroizeOnDrop)
pub struct WasmShield {
    inner: Shield,  // Shield has #[derive(Zeroize, ZeroizeOnDrop)]
}
```

`WasmShield`, `WasmTOTP`, `WasmRatchetSession` all wrap inner structs that have `Zeroize`+`ZeroizeOnDrop`. When the WASM wrapper is dropped, the inner struct's `ZeroizeOnDrop` triggers, correctly wiping key material. However, `WasmLamportSignature` wraps `LamportSignature` which also has `ZeroizeOnDrop` — correct.

- **Impact**: Positive — WASM layer correctly inherits zeroization from Rust core.
- **Remediation**: None required.

---

## Zeroization Coverage Summary

| Language | Key Zeroization | Method | Automatic? | Compiler-Safe? |
|----------|----------------|--------|------------|----------------|
| **Rust (core 5 structs)** | YES | `Zeroize`+`ZeroizeOnDrop` | YES (on drop) | YES |
| **Rust (6 structs MISSING)** | NO | — | — | — |
| **Python** | NO | — | — | — |
| **JavaScript** | NO | — | — | — |
| **Go** | NO | — | — | — |
| **Java** | YES (manual) | `Arrays.fill(key, (byte) 0)` | NO | Unlikely optimized |
| **C#** | YES (semi-auto) | `Array.Clear()` + `IDisposable` | Semi (`using`) | May be optimized |
| **Swift** | YES (manual) | `for i in 0..<data.count { data[i] = 0 }` | NO | May be optimized |
| **Kotlin** | YES (semi-auto) | `data.fill(0)` + `Closeable` | Semi (`use`) | May be optimized |
| **C** | YES (manual) | `volatile` pointer wipe | NO | YES (volatile) |
| **Android** | YES (semi-auto) | `data.fill(0)` + `Keystore` | Semi | May be optimized |
| **iOS** | YES (manual) | `secureWipe` + `Keychain` | NO | May be optimized |

**Zeroization Coverage**: 5/11 Rust key-holding structs properly zeroized. 0/3 GC languages (Python, JS, Go) have any zeroization. 5/5 manual-memory languages (C, Java, C#, Swift, Kotlin) have wipe methods but with varying reliability.

---

---

## TASK-1-011: C Buffer Safety & Memory Management

**Task**: TASK-1-011 — A03 C Buffer Safety & Memory Management
**Date**: 2026-03-01
**Iteration**: 11

---

### SHIELD-A03-011: C Fingerprint — strcat() Buffer Overflow in SHIELD_FP_COMBINED Mode

- **Severity**: HIGH
- **CWE**: CWE-120 (Buffer Copy without Checking Size of Input)
- **Location**: `c/src/shield_fingerprint.c:40-57`
- **Evidence**:

```c
// shield_fingerprint.c:40-57
char components[512] = {0};    // 512-byte destination
char mb_serial[256] = {0};      // up to 255 chars + null
char cpu_id[256] = {0};         // up to 255 chars + null

if (get_motherboard_serial(mb_serial, sizeof(mb_serial)) == SHIELD_FP_OK) {
    strcat(components, mb_serial);    // up to 255 bytes
    has_components = 1;
}
if (get_cpu_id(cpu_id, sizeof(cpu_id)) == SHIELD_FP_OK) {
    if (has_components) {
        strcat(components, "-");       // +1 byte = 256
    }
    strcat(components, cpu_id);        // +255 = 511 bytes, fits BARELY
}
```

With maximally-sized inputs: `mb_serial` (255 chars) + `"-"` (1 char) + `cpu_id` (255 chars) = 511 characters + null terminator = 512 bytes. This fits exactly in `components[512]`, but only because `fgets()` in `get_motherboard_serial`/`get_cpu_id` limits to buffer size. However, `strcat()` is inherently unsafe — if either platform function ever returns data without proper truncation, or if buffer sizes are changed, this overflows. The use of `strcat()` with no bounds checking is a CWE-120 violation.

- **Impact**: Stack buffer overflow. If `mb_serial` + `cpu_id` exceed 511 bytes combined, attacker-controlled hardware identifiers could overwrite stack return address. Practical exploitation depends on platform-specific serial/CPU ID lengths. On Windows, `wmic` output could contain unexpectedly long strings.
- **Reproduction**: On a system with long motherboard serial (>256 chars from `wmic baseboard get serialnumber`), the `strcat()` overflows `components` buffer.
- **Fix Complexity**: LOW — Replace `strcat()` with `snprintf(components, sizeof(components), "%s-%s", mb_serial, cpu_id)`.
- **Remediation**: Use `snprintf()` for all string concatenation. Or use `strncat()` with proper remaining-size tracking.

---

### SHIELD-A03-012: C Ratchet/Signature — Missing NULL Checks After malloc() Leads to NULL Dereference

- **Severity**: HIGH
- **CWE**: CWE-476 (NULL Pointer Dereference) / CWE-252 (Unchecked Return Value)
- **Location**: Multiple locations in `c/src/shield.c`
- **Evidence**:

```c
// shield.c:732-733 — shield_ratchet_encrypt: malloc without NULL check
keystream = (uint8_t *)malloc(plaintext_len);
generate_keystream(message_key, nonce, plaintext_len, keystream);  // CRASH if NULL

// shield.c:735-737 — another missing check
ciphertext = (uint8_t *)malloc(plaintext_len);
for (i = 0; i < plaintext_len; i++) {
    ciphertext[i] = plaintext[i] ^ keystream[i];  // CRASH if NULL

// shield.c:747-748 — mac_data malloc without check
uint8_t *mac_data = (uint8_t *)malloc(8 + SHIELD_NONCE_SIZE + plaintext_len);
memcpy(mac_data, counter_bytes, 8);  // CRASH if NULL

// shield.c:760 — result malloc without check
result = (uint8_t *)malloc(result_len);
memcpy(result, counter_bytes, 8);  // CRASH if NULL

// shield.c:827-828 — shield_ratchet_decrypt: same pattern
keystream = (uint8_t *)malloc(ciphertext_len);
generate_keystream(message_key, nonce, ciphertext_len, keystream);  // CRASH if NULL

// shield.c:830-832 — plaintext malloc without check
plaintext = (uint8_t *)malloc(ciphertext_len);
for (i = 0; i < ciphertext_len; i++) {
    plaintext[i] = ciphertext[i] ^ keystream[i];  // CRASH if NULL

// shield.c:813 — ratchet decrypt mac_data
uint8_t *mac_data = (uint8_t *)malloc(8 + SHIELD_NONCE_SIZE + ciphertext_len);
memcpy(mac_data, encrypted, 8);  // CRASH if NULL

// shield.c:1076 — shield_signature_sign_timestamped
sig_data = (uint8_t *)malloc(8 + message_len);
memcpy(sig_data, signature, 8);  // CRASH if NULL

// shield.c:1107 — shield_signature_verify
uint8_t *sig_data = (uint8_t *)malloc(8 + message_len);
memcpy(sig_data, signature, 8);  // CRASH if NULL

// shield.c:862-864 — shield_totp_init
ctx->secret = (uint8_t *)malloc(secret_len);
memcpy(ctx->secret, secret, secret_len);  // CRASH if NULL
```

Contrast with `shield_encrypt()`/`shield_decrypt()` which correctly check every `malloc()` return. The ratchet, signature, and TOTP functions consistently skip these checks.

- **Impact**: Any `malloc()` failure (memory pressure, huge `plaintext_len`) causes NULL pointer dereference → segfault/crash. In crypto library context, a controlled crash could be used as denial-of-service. The attacker can trigger this by sending a message with a large reported `plaintext_len` to the ratchet decrypt path.
- **Reproduction**: Call `shield_ratchet_encrypt()` with very large `plaintext_len` that causes `malloc()` to return NULL. Process crashes.
- **Fix Complexity**: LOW — Add `if (!ptr) { cleanup; return error; }` after each `malloc()`.
- **Remediation**: Add NULL checks after every `malloc()` call. Use a consistent pattern: check, set error code, free prior allocations, return NULL.

---

### SHIELD-A03-013: C Fingerprint — Shell Command Injection Surface via popen()

- **Severity**: MEDIUM
- **CWE**: CWE-78 (OS Command Injection)
- **Location**: `c/src/shield_fingerprint.c:76,107` (Windows), `c/src/shield_fingerprint.c:158,195` (Linux/macOS)
- **Evidence**:

```c
// Windows — shield_fingerprint.c:76
FILE *pipe = _popen("wmic baseboard get serialnumber /value", "r");

// Windows — shield_fingerprint.c:107
FILE *pipe = _popen("wmic cpu get ProcessorId /value", "r");

// Linux — shield_fingerprint.c:158
FILE *pipe = popen("dmidecode -s baseboard-serial-number 2>/dev/null", "r");

// macOS — shield_fingerprint.c:195
FILE *pipe = popen("sysctl -n machdep.cpu.brand_string 2>/dev/null", "r");
```

All four commands are hardcoded string literals — no user input is interpolated, so there is no **direct** command injection. However, `popen()` invokes the system shell, which means:
1. `PATH` manipulation can redirect `wmic`, `dmidecode`, or `sysctl` to attacker-controlled binaries
2. Shell metacharacters in the command string could be exploited if the pattern is ever extended
3. On Windows, `_popen()` uses `cmd.exe` which has different escaping rules

- **Impact**: If an attacker controls `PATH` in the process environment, they can intercept the fingerprint commands. The output is then fed into the MD5 hash that becomes part of the encryption key derivation salt. Attacker controls fingerprint → controls salt → weakens key derivation.
- **Reproduction**: Set `PATH=/tmp/evil:$PATH` where `/tmp/evil/sysctl` is a malicious script. Call `shield_fp_collect(SHIELD_FP_CPU, ...)`.
- **Fix Complexity**: MEDIUM — Use absolute paths (`/usr/sbin/dmidecode`), or use direct syscalls/sysfs reads instead of `popen()`.
- **Remediation**: Replace `popen()` with direct file reads where possible (`/sys/class/dmi/id/board_serial` is already used as primary). For macOS, use `sysctlbyname()` C API directly. For Windows, use WMI COM API instead of `_popen("wmic...")`.

---

### SHIELD-A03-014: C — Decrypted Plaintext and Keystream Not Wiped Before free()

- **Severity**: MEDIUM
- **CWE**: CWE-244 (Improper Clearing of Heap Memory Before Release)
- **Location**: `c/src/shield.c:413-414`, `c/src/shield.c:490,536,552,612,622`
- **Evidence**:

```c
// shield.c:413-414 — shield_encrypt: keystream and plaintext freed without wipe
free(keystream);         // keystream remains in freed heap
free(data_to_encrypt);   // plaintext + padding remains in freed heap

// shield.c:490 — shield_decrypt: keystream freed without wipe
free(keystream);

// shield.c:536 — shield_decrypt: decrypted data freed without wipe
free(decrypted);

// shield.c:739 — shield_ratchet_encrypt: keystream freed without wipe
free(keystream);

// shield.c:766 — shield_ratchet_encrypt: ciphertext freed without wipe
free(ciphertext);

// shield.c:834 — shield_ratchet_decrypt: keystream freed without wipe
free(keystream);
```

Note: `shield_ratchet_encrypt` correctly wipes `message_key` at line 767 with `shield_secure_wipe()`, but does NOT wipe `keystream` or `ciphertext`. Similarly, `shield_decrypt` frees `keystream` and `decrypted` without wiping.

Contrast with `shield_pbkdf2()` which correctly wipes intermediate values:
```c
// shield.c:242-244 — CORRECT: intermediate key material wiped
free(salt_ext);
shield_secure_wipe(U, 32);
shield_secure_wipe(T, 32);
```

- **Impact**: Plaintext, keystream, and intermediate crypto data persist in freed heap memory. Heap inspection, core dumps, or memory forensics can recover plaintext and keystream. The keystream recovery is especially dangerous — knowing keystream + ciphertext = plaintext for any message encrypted with that nonce.
- **Reproduction**: Encrypt data, then inspect process heap for plaintext bytes at the freed allocation address.
- **Fix Complexity**: LOW — Add `shield_secure_wipe(ptr, len)` before each `free()`.
- **Remediation**: Call `shield_secure_wipe()` on all buffers containing sensitive data before `free()`. At minimum: keystream, data_to_encrypt, decrypted, ciphertext, mac_data.

---

### SHIELD-A03-015: C Recovery Code Generation — Buffer Overflow When length > 8

- **Severity**: LOW
- **CWE**: CWE-120 (Buffer Copy without Checking Size of Input)
- **Location**: `c/src/shield.c:1233-1275`, `c/include/shield.h:95`
- **Evidence**:

```c
// shield.h:95 — fixed buffer size
#define SHIELD_RECOVERY_CODE_LEN 10  /* "XXXX-XXXX" + null = 10 bytes */

typedef struct {
    char codes[SHIELD_MAX_RECOVERY_CODES][SHIELD_RECOVERY_CODE_LEN];  // 10 bytes each
    // ...
} shield_recovery_t;

// shield.c:1233 — length parameter controls output size
shield_error_t shield_recovery_init(shield_recovery_t *ctx, int count, int length) {
    // ...
    if (length <= 0) length = 8;
    if (length % 2 != 0) length++;
    // NO CHECK: length > 8 overflows codes[i] buffer

    byte_len = length / 2;
    // ...
    for (j = 0; j < half; j++) {
        ctx->codes[i][pos++] = HEX_CHARS[(bytes[j] >> 4) & 0x0F];  // writes beyond 10 bytes
        ctx->codes[i][pos++] = HEX_CHARS[bytes[j] & 0x0F];
    }
    ctx->codes[i][pos++] = '-';   // dash in middle
    // second half writes continue...
    ctx->codes[i][pos] = '\0';    // null terminator beyond buffer
}
```

If caller passes `length = 16`, then `byte_len = 8`, `half = 4`, total output = 8 hex chars + dash + 8 hex chars + null = 18 bytes. But `codes[i]` is only 10 bytes (`SHIELD_RECOVERY_CODE_LEN`). This overwrites adjacent `codes[i+1]` entries and eventually `used[]` array.

- **Impact**: Buffer overflow within the `shield_recovery_t` struct. Corrupts adjacent recovery codes and the `used[]` array. Could cause incorrect recovery code validation. Exploitation requires caller to pass `length > 8`.
- **Reproduction**: `shield_recovery_init(&ctx, 10, 16)` — overflows each code buffer into the next.
- **Fix Complexity**: LOW — Clamp `length` to `(SHIELD_RECOVERY_CODE_LEN - 2)` (8) or validate and return error.
- **Remediation**: Add `if (length > SHIELD_RECOVERY_CODE_LEN - 2) length = SHIELD_RECOVERY_CODE_LEN - 2;` after the initial checks.

---

### SHIELD-A03-016: C recovery_get_code — strcpy Without Bounds Check on Caller Buffer

- **Severity**: LOW
- **CWE**: CWE-120 (Buffer Copy without Checking Size of Input)
- **Location**: `c/src/shield.c:1357`
- **Evidence**:

```c
// shield.c:1352-1363
bool shield_recovery_get_code(const shield_recovery_t *ctx, int index, char *out) {
    int remaining_index = 0;
    for (int i = 0; i < ctx->count; i++) {
        if (!ctx->used[i]) {
            if (remaining_index == index) {
                strcpy(out, ctx->codes[i]);    // no size parameter
                return true;
            }
            remaining_index++;
        }
    }
    return false;
}
```

Uses `strcpy()` without any way to check the destination buffer size. The caller must provide a buffer of at least `SHIELD_RECOVERY_CODE_LEN` bytes, but this is not enforced.

- **Impact**: If caller provides a buffer smaller than the code length, `strcpy()` overflows it. Since recovery codes are fixed-size (9 chars + null), the risk is limited to callers who misuse the API.
- **Fix Complexity**: LOW — Add a `size_t out_len` parameter and use `strncpy()`.
- **Remediation**: Change signature to `shield_recovery_get_code(ctx, index, out, out_len)` and use `strncpy()`.

---

### SHIELD-A03-017: C HMAC key material (k_ipad, k_opad) Not Wiped After Use

- **Severity**: LOW
- **CWE**: CWE-244 (Improper Clearing of Heap Memory Before Release)
- **Location**: `c/src/shield.c:180-208`, `c/src/shield.c:933-962`
- **Evidence**:

```c
// shield.c:179-208 — shield_hmac_sha256
void shield_hmac_sha256(const uint8_t *key, size_t key_len, ...) {
    uint8_t k_ipad[64], k_opad[64];   // key XOR'd with pad constants
    uint8_t tk[32];                     // temp key if >64 bytes
    // ... computation ...
    // Function returns WITHOUT wiping k_ipad, k_opad, tk
}

// shield.c:932-963 — hmac_sha1 (TOTP)
static void hmac_sha1(const uint8_t *key, size_t key_len, ...) {
    uint8_t k_ipad[64], k_opad[64];
    uint8_t tk[20];
    // ... computation ...
    // Function returns WITHOUT wiping k_ipad, k_opad, tk
}
```

`k_ipad` and `k_opad` contain the key XOR'd with known constants (0x36 and 0x5c). An attacker who reads these from the stack can trivially recover the original key by XOR-ing back. These are stack-allocated so they persist until overwritten by subsequent function calls.

- **Impact**: HMAC key pads remain on stack after function return. Stack memory reuse is non-deterministic. An attacker with stack access (debugger, core dump, speculative execution side-channel) can recover the encryption key from `k_ipad` XOR `0x36`.
- **Fix Complexity**: LOW — Add `shield_secure_wipe(k_ipad, 64); shield_secure_wipe(k_opad, 64);` before return.
- **Remediation**: Add `shield_secure_wipe()` calls for `k_ipad`, `k_opad`, and `tk` at the end of both `shield_hmac_sha256()` and `hmac_sha1()`.

---

### SHIELD-A03-018: C generate_keystream — Stack Buffer Correctly Sized, No Overflow

- **Severity**: INFO
- **CWE**: N/A (Positive finding)
- **Location**: `c/src/shield.c:292-313`
- **Evidence**:

```c
// shield.c:292-313
static void generate_keystream(const uint8_t *key, const uint8_t *nonce, size_t length, uint8_t *keystream) {
    size_t num_blocks = (length + 31) / 32;
    uint8_t block[32 + SHIELD_NONCE_SIZE + 4];  // = 32 + 16 + 4 = 52 bytes (stack)
    uint8_t hash[32];                            // 32 bytes (stack)

    for (i = 0; i < num_blocks; i++) {
        memcpy(block, key, SHIELD_KEY_SIZE);                           // 32 bytes
        memcpy(block + SHIELD_KEY_SIZE, nonce, SHIELD_NONCE_SIZE);     // 16 bytes
        block[SHIELD_KEY_SIZE + SHIELD_NONCE_SIZE] = (uint8_t)(i);     // 4 bytes counter
        // ...
        shield_sha256(block, SHIELD_KEY_SIZE + SHIELD_NONCE_SIZE + 4, hash);  // 52 bytes input

        size_t copy_len = (length - i * 32 < 32) ? (length - i * 32) : 32;
        for (j = 0; j < copy_len; j++) {
            keystream[i * 32 + j] = hash[j];  // bounded by copy_len ≤ 32
        }
    }
}
```

The `block[52]` buffer is correctly sized for `key(32) + nonce(16) + counter(4)`. The `hash[32]` output matches SHA256 output size. The `copy_len` calculation correctly bounds the output copy. **However**, note that `block` and `hash` contain key material and are NOT wiped before the function returns (see SHIELD-A03-017 pattern — key material on stack).

- **Impact**: Positive — no buffer overflow in keystream generation. Stack key material persistence is documented separately in SHIELD-A03-017.
- **Remediation**: None required for buffer overflow. Wiping `block` and `hash` would improve defense-in-depth.

---

## Finding Summary

| ID | Title | Severity | CWE |
|----|-------|----------|-----|
| SHIELD-A03-001 | Rust — 6 Structs Missing Zeroize/ZeroizeOnDrop | HIGH | CWE-244 |
| SHIELD-A03-002 | Python — No Key Zeroization (GC-Dependent) | MEDIUM | CWE-244 |
| SHIELD-A03-003 | JavaScript — No Key Zeroization (GC-Dependent) | MEDIUM | CWE-244 |
| SHIELD-A03-004 | Go — No Key Zeroization | MEDIUM | CWE-244 |
| SHIELD-A03-005 | RecoveryCodes — Secret Strings Cannot Zeroize | LOW | CWE-244 |
| SHIELD-A03-006 | C# SecureWipe Uses Array.Clear — May Be Optimized | LOW | CWE-14 |
| SHIELD-A03-007 | Swift/Kotlin secureWipe — Simple Loop May Be Optimized | LOW | CWE-14 |
| SHIELD-A03-008 | Manual Wipe Not Automatic — Caller Must Invoke | INFO | CWE-404 |
| SHIELD-A03-009 | C Volatile Pointer Wipe — Correct Pattern | INFO | N/A |
| SHIELD-A03-010 | WASM Inherits Rust Zeroize — Correct | INFO | N/A |
| SHIELD-A03-011 | C Fingerprint — strcat() Buffer Overflow in COMBINED Mode | HIGH | CWE-120 |
| SHIELD-A03-012 | C Ratchet/Signature — Missing NULL Checks After malloc() | HIGH | CWE-476 |
| SHIELD-A03-013 | C Fingerprint — Shell Command Injection Surface via popen() | MEDIUM | CWE-78 |
| SHIELD-A03-014 | C — Decrypted Plaintext and Keystream Not Wiped Before free() | MEDIUM | CWE-244 |
| SHIELD-A03-015 | C Recovery Code Generation — Buffer Overflow When length > 8 | LOW | CWE-120 |
| SHIELD-A03-016 | C recovery_get_code — strcpy Without Bounds Check | LOW | CWE-120 |
| SHIELD-A03-017 | C HMAC key material (k_ipad, k_opad) Not Wiped After Use | LOW | CWE-244 |
| SHIELD-A03-018 | C generate_keystream — Stack Buffer Correctly Sized | INFO | N/A |

**Total**: 18 findings (3 HIGH, 4 MEDIUM, 5 LOW, 4 INFO + 2 positive confirmations)

---

---

## TASK-1-012: WASM Memory Isolation & Unwrap Safety

**Task**: TASK-1-012 — A03 WASM Memory Isolation & Unwrap Safety
**Date**: 2026-03-01
**Iteration**: 12

---

### SHIELD-A03-019: WASM key() Method Exports Raw Key Material to JavaScript Heap

- **Severity**: MEDIUM
- **CWE**: CWE-316 (Cleartext Storage of Sensitive Information in Memory)
- **Location**: `shield-core/src/wasm.rs:92-94`
- **Evidence**:

```rust
// wasm.rs:92-94 — Exports derived key as Vec<u8> to JavaScript
#[wasm_bindgen]
#[must_use]
pub fn key(&self) -> Vec<u8> {
    self.inner.key().to_vec()
}
```

The `key()` method on `WasmShield` is exported via `#[wasm_bindgen]` and returns the 32-byte derived encryption key as `Vec<u8>`. When called from JavaScript, `wasm-bindgen` copies this into a new `Uint8Array` on the JS heap. This key is then:
1. Subject to JavaScript garbage collection (non-deterministic lifetime)
2. Visible in browser DevTools Memory tab (heap snapshot)
3. Accessible via any XSS attack that reaches the calling scope
4. Cannot be reliably zeroed from JavaScript (TypedArray views may be copied)

Cross-references: SHIELD-A01-004 (JS `getKey()` returns raw key), SHIELD-A02-015 (JS `generateKeystream` export). This is the WASM-specific variant — the key crosses the WASM-JS boundary.

The `key()` method comment says "for interop testing" but it is exported unconditionally in production WASM builds. There is no `#[cfg(test)]` or feature gate.

- **Impact**: Any JavaScript code in the page context can call `shield.key()` to extract the encryption key. Combined with XSS (even reflected), this enables full plaintext recovery of all encrypted data. The key persists on the JS heap indefinitely.
- **Reproduction**: `const shield = new WasmShield("password", "service"); const key = shield.key(); console.log(key);` — prints full 32-byte key.
- **Fix Complexity**: LOW — Remove `key()` from WASM exports or gate behind `#[cfg(test)]` / `#[cfg(feature = "expose-keys")]`.
- **Remediation**: Remove the `key()` method from `WasmShield`'s `#[wasm_bindgen]` impl block. If needed for testing, gate behind `#[cfg(feature = "expose-keys")]` that is never enabled in production builds.

---

### SHIELD-A03-020: WASM Linear Memory Exposes Key Material to JavaScript Inspection

- **Severity**: MEDIUM
- **CWE**: CWE-316 (Cleartext Storage of Sensitive Information in Memory)
- **Location**: `shield-core/src/wasm.rs:45-47` (WasmShield struct), `wasm/src/lib.rs:46-65` (re-exports)
- **Evidence**:

```rust
// wasm.rs:45-47 — WasmShield stores Shield in WASM linear memory
pub struct WasmShield {
    inner: Shield,  // Shield.key is [u8; 32] — lives in WASM linear memory
}
```

WASM linear memory is a single `ArrayBuffer` accessible from JavaScript via `wasm.memory.buffer`. Any JavaScript code can create a `Uint8Array` view over this buffer and scan for key material:

```javascript
// JavaScript — scan WASM linear memory for key material
const memory = new Uint8Array(wasmInstance.exports.memory.buffer);
// Key bytes are somewhere in this buffer, findable by pattern or known offset
```

This applies to all WASM-wrapped structs: `WasmShield`, `WasmTOTP`, `WasmRatchetSession`, `WasmLamportSignature`. Their inner key fields (`[u8; 32]`, secret bytes) are stored in WASM linear memory which is a single flat `ArrayBuffer`.

While `ZeroizeOnDrop` correctly zeros key material when the Rust struct is dropped, the key is **readable** for the entire lifetime of the struct. There is no memory encryption or obfuscation in WASM linear memory.

- **Impact**: JavaScript with access to the WASM module's memory export can read raw key bytes. This is inherent to the WASM security model — WASM provides isolation from the host, not from the embedding JavaScript. XSS or malicious browser extensions can inspect WASM linear memory.
- **Reproduction**: After creating a `WasmShield`, inspect `wasmInstance.exports.memory.buffer` for the 32-byte key pattern.
- **Fix Complexity**: HIGH — This is an inherent WASM limitation. Mitigations: minimize key lifetime in WASM memory, clear immediately after use, avoid storing keys persistently in WASM structs.
- **Remediation**: Accept as inherent WASM limitation. Document the threat model. Consider a "decrypt-and-clear" pattern where the key is derived per-operation and zeroed immediately, rather than stored persistently in `WasmShield.inner.key`.

---

### SHIELD-A03-021: 4x .unwrap() in WASM Bindings — Panic on Malformed Input Instead of JsError

- **Severity**: LOW
- **CWE**: CWE-248 (Uncaught Exception)
- **Location**: `shield-core/src/wasm.rs:67`, `shield-core/src/wasm.rs:104`, `shield-core/src/wasm.rs:115`, `shield-core/src/wasm.rs:226`
- **Evidence**:

```rust
// wasm.rs:63-67 — with_key: length validated, then unwrap
pub fn with_key(key: &[u8]) -> Result<WasmShield, JsError> {
    if key.len() != 32 {
        return Err(JsError::new("Key must be 32 bytes"));
    }
    let key_array: [u8; 32] = key.try_into().unwrap(); // SAFE but wrong pattern
    // ...
}

// wasm.rs:100-104 — wasm_encrypt: same pattern
pub fn wasm_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, JsError> {
    if key.len() != 32 {
        return Err(JsError::new("key must be 32 bytes"));
    }
    let key_array: [u8; 32] = key.try_into().unwrap(); // SAFE but wrong pattern
    // ...
}

// wasm.rs:111-115 — wasm_decrypt: same pattern
// wasm.rs:222-226 — WasmRatchetSession::new: same pattern
```

All 4 instances follow the pattern: length check → early return on mismatch → `.unwrap()` on `try_into()`. The `.unwrap()` is **logically safe** because the length check guarantees success. However:

1. **WASM panics abort the entire WASM instance** — in the browser, a panic triggers `wasm.__wbindgen_throw` which throws a JavaScript error, but the WASM instance may become unusable
2. **Defensive coding**: if the length check is ever refactored or removed, the unwrap becomes a crash
3. The `Result<_, JsError>` return type is already available — `.map_err(|_| JsError::new("..."))` costs nothing

- **Impact**: LOW — the unwrap is currently safe due to the preceding length check. However, a WASM panic from any `.unwrap()` path aborts the WASM instance, potentially leaving the `ShieldBrowser` singleton in a broken state with no recovery path.
- **Reproduction**: Cannot trigger currently (length check prevents it). Would require removing the length check.
- **Fix Complexity**: LOW — Replace `.unwrap()` with `.map_err(|_| JsError::new("Invalid key length"))?`.
- **Remediation**: Replace all 4 `.unwrap()` calls with `try_into().map_err(|_| JsError::new("Key conversion failed"))?` for defensive consistency.

---

### SHIELD-A03-022: WasmClient Exported Directly — Bypasses SDK Safety Layer

- **Severity**: LOW
- **CWE**: CWE-749 (Exposed Dangerous Method or Function)
- **Location**: `browser/js/index.ts:244`
- **Evidence**:

```typescript
// index.ts:244 — Raw WasmClient exported for "advanced usage"
export { WasmClient as ShieldClient };
```

The raw `WasmClient` (the WASM-generated binding) is re-exported from the Browser SDK. This bypasses:
1. The singleton pattern enforced by `ShieldBrowser.init()`
2. The auto-refresh key lifecycle management
3. The `destroy()` cleanup that calls `client.clear()`
4. Any future security controls added to `ShieldBrowser`

A developer using `ShieldClient` directly creates an unmanaged WASM instance with no key lifecycle, no auto-cleanup, and no fetch hook management.

- **Impact**: Direct `ShieldClient` usage skips key lifecycle management. Keys set via the raw client are never auto-refreshed and never auto-cleared. The exported client provides access to all WASM methods including `key()` (if exposed on `ShieldClient`).
- **Reproduction**: `import { ShieldClient } from '@guard8/shield-browser'; const c = new ShieldClient(); c.setKey(...);` — no lifecycle management.
- **Fix Complexity**: LOW — Remove the export or document risks prominently.
- **Remediation**: Remove `export { WasmClient as ShieldClient }` from the public API. If needed for advanced use cases, gate behind a separate entry point (e.g., `@guard8/shield-browser/advanced`) with explicit documentation of risks.

---

### SHIELD-A03-023: Decrypted Plaintext Passes Through JavaScript String — Unzeroed in GC Heap

- **Severity**: INFO
- **CWE**: CWE-316 (Cleartext Storage of Sensitive Information in Memory)
- **Location**: `browser/js/fetch-hook.ts:77`, `browser/js/index.ts:186,196`
- **Evidence**:

```typescript
// fetch-hook.ts:77 — Decrypted plaintext as JS string
const decryptedText = client.decryptEnvelope(text);
return new Response(decryptedText, { ... });

// index.ts:186 — decrypt returns Uint8Array (WASM → JS copy)
decrypt(encryptedBase64: string): Uint8Array {
    return this.client.decrypt(encryptedBase64);
}

// index.ts:196 — decryptEnvelope returns string (WASM → JS copy)
decryptEnvelope(envelopeJson: string): string {
    return this.client.decryptEnvelope(envelopeJson);
}
```

After WASM decryption, the plaintext crosses back to JavaScript as either a `Uint8Array` or `string`. JavaScript strings are immutable and cannot be zeroed. The `Uint8Array` from `decrypt()` could theoretically be zeroed with `.fill(0)`, but the `decryptEnvelope()` string cannot.

The fetch hook creates a new `Response` object with `decryptedText`, which is then consumed by the application. The original `decryptedText` string remains in the V8 heap until garbage collected.

- **Impact**: Decrypted plaintext persists in the JavaScript heap. This is inherent to the browser decryption model — the whole point is to make decrypted data available to the application. The risk is that plaintext remains in memory longer than necessary due to GC non-determinism.
- **Remediation**: Document as accepted risk. The browser SDK's purpose is to make plaintext available to the application. Consider returning `Uint8Array` instead of `string` from `decryptEnvelope()` to give callers the option to zero the buffer after use.

---

### SHIELD-A03-024: forbid(unsafe_code) Confirmed — No Unsafe Rust in WASM Path

- **Severity**: INFO
- **CWE**: N/A (Positive finding)
- **Location**: `shield-core/src/lib.rs:37`
- **Evidence**:

```rust
// lib.rs:37 — Compile-time enforcement
#![forbid(unsafe_code)]
```

The `shield-core` crate uses `#![forbid(unsafe_code)]` which is stronger than `#![deny(unsafe_code)]` — it cannot be overridden by `#[allow(unsafe_code)]` attributes. This means:

1. No `unsafe` blocks anywhere in `shield-core` source, including `wasm.rs`
2. No raw pointer manipulation, no `transmute`, no `UnsafeCell`
3. All memory safety is enforced by the Rust compiler
4. WASM bindings rely entirely on `wasm-bindgen`'s safe abstractions

Note: This does NOT prevent unsafe code in dependencies (`ring`, `subtle`, `wasm-bindgen` itself). But the Shield application code is free of `unsafe`.

- **Impact**: Positive — eliminates entire classes of memory safety bugs (use-after-free, double-free, buffer overflow) in the Shield WASM code path.
- **Remediation**: None required. Maintain `#![forbid(unsafe_code)]`.

---

### SHIELD-A03-025: No Key Storage in Browser Persistent Storage — Correct

- **Severity**: INFO
- **CWE**: N/A (Positive finding)
- **Location**: `browser/js/index.ts`, `browser/js/fetch-hook.ts` (full codebase search)
- **Evidence**:

No references to `localStorage`, `sessionStorage`, `IndexedDB`, or `Cache API` found in the browser SDK source. Keys are stored only in WASM linear memory (via `WasmClient`) and as transient JavaScript variables.

The Browser SDK correctly uses in-memory-only key storage with `credentials: 'same-origin'` for key fetch requests. Keys are refreshed via HTTP on each session rather than persisted client-side.

- **Impact**: Positive — keys cannot be recovered from browser persistent storage after the tab is closed. No cache, no IndexedDB, no localStorage.
- **Remediation**: None required. Document this as a security property.

---

## WASM Memory Isolation Audit Summary

| # | File:Line | Check | Status | Risk |
|---|-----------|-------|--------|------|
| 1 | wasm.rs:92-94 | Key export to JS via key() | FAIL | Medium |
| 2 | wasm.rs:45-47 | Key in WASM linear memory | EXPECTED | Medium |
| 3 | wasm.rs:67,104,115,226 | .unwrap() panic risk | WARN | Low |
| 4 | index.ts:244 | Raw WasmClient exported | WARN | Low |
| 5 | fetch-hook.ts:77 | Plaintext in JS string | EXPECTED | Info |
| 6 | lib.rs:37 | forbid(unsafe_code) | PASS | N/A |
| 7 | index.ts,fetch-hook.ts | No persistent key storage | PASS | N/A |
| 8 | index.ts:121-124 | Key fetch credentials:same-origin | PASS | N/A |
| 9 | wasm.rs (all JsError) | No key material in error messages | PASS | N/A |
| 10 | browser/ (full search) | No console.log of key data | PASS | N/A |

**Isolation Score**: 7/10 checks passed (2 expected limitations, 1 fail)

---

## Finding Summary (TASK-1-012)

| ID | Title | Severity | CWE |
|----|-------|----------|-----|
| SHIELD-A03-019 | WASM key() Exports Raw Key to JS Heap | MEDIUM | CWE-316 |
| SHIELD-A03-020 | WASM Linear Memory Exposes Key Material | MEDIUM | CWE-316 |
| SHIELD-A03-021 | 4x .unwrap() — Panic Instead of JsError | LOW | CWE-248 |
| SHIELD-A03-022 | WasmClient Exported — Bypasses SDK Safety | LOW | CWE-749 |
| SHIELD-A03-023 | Decrypted Plaintext in JS String — Unzeroed | INFO | CWE-316 |
| SHIELD-A03-024 | forbid(unsafe_code) Confirmed | INFO | N/A |
| SHIELD-A03-025 | No Persistent Key Storage — Correct | INFO | N/A |

---

---

## TASK-1-013: Key Accessor Surface Mapping

**Task**: TASK-1-013 — A03 Key Accessor Surface Mapping
**Date**: 2026-03-01
**Iteration**: 13

---

### SHIELD-A03-026: All 12 Implementations Expose Raw Key via Public Accessor — No Feature Gate

- **Severity**: HIGH
- **CWE**: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
- **Location**: 12 files across all language implementations
- **Evidence**:

Every Shield implementation provides an unconditional public method that returns the raw 32-byte derived encryption key. None are gated behind compile-time flags, debug modes, or access controls.

| # | Language | File:Line | Method | Returns | Copy? |
|---|----------|-----------|--------|---------|-------|
| 1 | Rust | `shield-core/src/shield.rs:381` | `pub fn key(&self) -> &[u8; 32]` | Reference to internal key | No (borrow) |
| 2 | Python | `python/shield/core.py:298-301` | `@property def key -> bytes` | `self._key` | No (same ref) |
| 3 | JavaScript | `javascript/src/shield.js:280-282` | `get key()` | `this._key` | No (same ref) |
| 4 | Go | `go/shield/shield.go:105-107` | `func (s *Shield) Key() []byte` | `s.key[:]` slice | No (slice of array) |
| 5 | C | `c/src/shield.c:656-658` | `shield_get_key(ctx)` | `ctx->key` pointer | No (raw ptr) |
| 6 | Java | `java/.../Shield.java:123-125` | `public byte[] getKey()` | `Arrays.copyOf(key)` | Yes |
| 7 | C# | `csharp/Shield/Shield.cs:65-70` | `public byte[] GetKey()` | `Array.Copy` | Yes |
| 8 | Swift | `swift/.../Shield.swift:43-44` | `public func getKey() -> [UInt8]` | `key` | Yes (value type) |
| 9 | Kotlin | `kotlin/.../Shield.kt:181` | `fun getKey(): ByteArray` | `key.copyOf()` | Yes |
| 10 | WASM | `shield-core/src/wasm.rs:92-93` | `pub fn key() -> Vec<u8>` | `.to_vec()` copy | Yes (cross-boundary) |
| 11 | Android | N/A — wraps SecureKeyStore | `getKey(alias)` | From EncryptedSharedPrefs | Yes |
| 12 | iOS | N/A — wraps SecureKeychain | `retrieve(for:)` | From Keychain | Yes |

```rust
// shield.rs:379-383 — Source of truth for all implementations
/// Get the derived key (for testing/debugging).
#[must_use]
pub fn key(&self) -> &[u8; 32] {
    &self.key
}
```

```javascript
// shield.js:280-282 — Returns direct reference, NOT a copy
get key() {
    return this._key;
}
```

```go
// shield.go:104-107 — Returns slice header pointing to internal array
func (s *Shield) Key() []byte {
    return s.key[:]
}
```

```c
// shield.c:656-658 — Returns raw pointer to internal key buffer
const uint8_t *shield_get_key(const shield_t *ctx) {
    return ctx->key;
}
```

All 12 implementations label this "for testing/debugging" but ship it unconditionally in production. This creates a universal key extraction surface — any code with a reference to a Shield instance can extract the raw key material.

Cross-references: SHIELD-A01-004 (previously reported key accessor existence). This finding deepens A01-004 with the full 12-implementation mapping, copy semantics analysis, and risk classification.

- **Impact**: Any consumer code (application, middleware, plugin, XSS payload) that holds a Shield instance reference can call `.key()` / `.getKey()` / `shield_get_key()` to extract the raw encryption key. The key can then be used independently to decrypt any ciphertext encrypted with that instance, bypassing all SDK security controls. In 5 of 12 implementations (Rust, Python, JS, Go, C), the returned value is NOT a copy — modifications to the returned value directly corrupt the internal key state.
- **Reproduction**: In any language: instantiate Shield, call the key accessor, print the result — full 32-byte key is exposed.
- **Fix Complexity**: LOW — Gate behind `#[cfg(feature = "expose-keys")]` (Rust), `SHIELD_DEBUG` env var, or remove entirely.
- **Remediation**: Remove key accessors from all 12 production builds. If needed for testing, gate behind compile-time feature flags / build configurations that are never enabled in release builds. At minimum, mark as `@deprecated` / `#[deprecated]` with prominent warnings.

---

### SHIELD-A03-027: Go — 4 Additional Key Accessor Methods Beyond Shield.Key()

- **Severity**: MEDIUM
- **CWE**: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
- **Location**: Multiple Go files
- **Evidence**:

Go's Shield implementation has **5 separate public methods** returning raw key material, the most of any implementation:

| # | File:Line | Method | Returns |
|---|-----------|--------|---------|
| 1 | `go/shield/shield.go:105` | `Shield.Key()` | Shield encryption key |
| 2 | `go/shield/identity.go:239` | `Identity.Key()` | Identity key (user-derived) |
| 3 | `go/shield/identity.go:311` | `Session.Key()` | Session encryption key |
| 4 | `go/shield/group.go:112` | `GroupEncryption.GroupKey()` | Group encryption key |
| 5 | `go/shield/exchange.go:176` | `QRExchange.Key()` | Exchanged shared key |

```go
// identity.go:238-241 — Returns raw identity key (user-derived secret)
func (i *Identity) Key() []byte {
    return i.key[:]
}

// identity.go:310-313 — Returns raw session key
func (s *Session) Key() []byte {
    return s.key[:]
}

// group.go:111-114 — Returns raw group key
func (ge *GroupEncryption) GroupKey() []byte {
    return ge.groupKey[:]
}

// exchange.go:175-178 — Returns raw exchanged key
func (qe *QRExchange) Key() []byte {
    return qe.key[:]
}
```

All 5 methods return `[]byte` slices pointing directly to internal arrays — no copies are made. Any caller that retains the slice has ongoing read/write access to the internal key material.

- **Impact**: Go's exported Key() surface is 5x wider than other implementations. Each accessor exposes a different category of key material (encryption, identity, session, group, exchange). An attacker who compromises any Go code path that handles these objects can extract multiple independent keys. The slice semantics mean the key can be modified through the returned value, potentially corrupting internal state.
- **Reproduction**: `s := shield.New("pw", "svc", nil); fmt.Println(hex.EncodeToString(s.Key()))` — same for Identity, Session, GroupEncryption, QRExchange.
- **Fix Complexity**: LOW — Remove or gate all 5 methods.
- **Remediation**: Remove `Key()` from Identity, Session, GroupEncryption, and QRExchange. If retained for Shield, return `[]byte` copy (`append([]byte(nil), s.key[:]...)`).

---

### SHIELD-A03-028: JavaScript/Python — Key Accessors Return Mutable References, Not Copies

- **Severity**: MEDIUM
- **CWE**: CWE-496 (Public Data Assigned to Private Array-Typed Field)
- **Location**: `javascript/src/shield.js:280-282`, `python/shield/core.py:298-301`
- **Evidence**:

```javascript
// shield.js:280-282 — Returns direct reference to internal Buffer
get key() {
    return this._key;
}
// Caller can mutate: shield.key[0] = 0; — corrupts internal state
```

```python
# core.py:298-301 — Returns direct reference to internal bytes
@property
def key(self) -> bytes:
    """Get the derived key (for testing/debugging)."""
    return self._key
```

JavaScript's `Buffer` is mutable — `shield.key.fill(0)` or `shield.key[0] = 0xFF` directly corrupts the internal encryption key without any error. All subsequent encrypt/decrypt operations use the corrupted key.

Python's `bytes` is immutable, so direct mutation isn't possible. However, the reference identity is leaked — `shield.key is shield.key` returns `True`, allowing identity-based tracking and the reference is GC-pinned as long as any external code holds it.

Contrast with Java (`Arrays.copyOf`), C# (`Array.Copy`), Kotlin (`key.copyOf()`), which correctly return defensive copies.

- **Impact**: In JavaScript, an accidental or malicious `shield.key.fill(0)` silently corrupts the encryption key. All subsequent operations silently produce garbage ciphertext that cannot be decrypted. In Go, same via slice: `key := s.Key(); key[0] = 0` corrupts internal state. C has the same raw pointer issue.
- **Reproduction**: `const s = new Shield("pw","svc"); const k = s.key; k[0] = 0xFF; // s._key is now corrupted`
- **Fix Complexity**: LOW — Return `Buffer.from(this._key)` in JS, `bytes(self._key)` in Python.
- **Remediation**: If key accessors are retained, return defensive copies. JS: `return Buffer.from(this._key)`. Python: `return bytes(self._key)`. Go: `return append([]byte(nil), s.key[:]...)`. C: document that returned pointer is read-only.

---

### SHIELD-A03-029: JavaScript Exports generateKeystream as Public API — Enables Key Material Misuse

- **Severity**: MEDIUM
- **CWE**: CWE-749 (Exposed Dangerous Method or Function)
- **Location**: `javascript/src/shield.js:343-348`
- **Evidence**:

```javascript
// shield.js:343-348 — Module exports
module.exports = {
    Shield,
    quickEncrypt,
    quickDecrypt,
    generateKeystream  // Internal function exported publicly
};
```

```javascript
// shield.js:29 — The exported function
function generateKeystream(key, nonce, length) {
    // SHA256-CTR keystream generation
```

The `generateKeystream` function is an internal cryptographic primitive that should never be part of the public API. It accepts a raw key and nonce, producing the raw keystream. With a known nonce (extracted from ciphertext prefix), this enables:
1. Key verification attacks (encrypt known plaintext, compare keystream)
2. Keystream reuse if caller controls nonce
3. Misuse by developers who don't understand CTR mode

Cross-references: SHIELD-A02-015 (previously identified). This finding is a cross-reference — the exposure is confirmed and mapped as part of the key accessor surface.

No other implementation exports `generateKeystream` — it's private/internal in Rust, Python, Go, Java, C#, Swift, Kotlin, and C.

- **Impact**: Developers can call `generateKeystream(key, nonce, length)` to produce raw keystream bytes. Combined with the `key` getter, this allows constructing ciphertext without MAC authentication, or performing keystream operations that bypass Shield's encrypt-then-MAC protection.
- **Reproduction**: `const { generateKeystream, Shield } = require('./shield'); const s = new Shield("pw","svc"); const ks = generateKeystream(s.key, nonce, 32);`
- **Fix Complexity**: LOW — Remove from `module.exports`.
- **Remediation**: Remove `generateKeystream` from exports. Keep it as a module-internal function.

---

### SHIELD-A03-030: C shield_get_key() Returns Raw Pointer to Internal Key Buffer — No Lifetime/Ownership

- **Severity**: MEDIUM
- **CWE**: CWE-562 (Return of Stack Variable Address) / CWE-200
- **Location**: `c/src/shield.c:656-658`, `c/include/shield.h:182`
- **Evidence**:

```c
// shield.c:656-658 — Returns raw pointer to internal ctx->key
const uint8_t *shield_get_key(const shield_t *ctx) {
    return ctx->key;
}

// shield.h:182 — Public declaration
const uint8_t *shield_get_key(const shield_t *ctx);
```

The C implementation returns a `const uint8_t *` to the internal key buffer inside the `shield_t` struct. The `const` qualifier prevents accidental writes through the pointer, but:

1. **Use-after-wipe**: If `shield_wipe(&ctx)` is called, the pointer dangles to zeroed memory
2. **Use-after-free**: If `ctx` is stack-allocated and function returns, pointer is invalid
3. **Cast-away const**: C allows `(uint8_t *)shield_get_key(ctx)` to mutate internal key
4. **Pointer aliasing**: Caller can retain pointer indefinitely, bypassing expected key lifecycle

```c
// Dangerous usage pattern:
const uint8_t *key = shield_get_key(&ctx);
shield_wipe(&ctx);  // key now points to zeroed memory
// key still readable but contents are zero — silent failure
```

- **Impact**: The returned pointer has no ownership semantics. After `shield_wipe()`, any code holding the pointer reads zeroed or garbage data. If the caller copies the pointer value before wipe, key material has leaked to an uncontrolled location. There is no way for the Shield library to revoke access once the pointer is returned.
- **Reproduction**: `shield_t ctx; shield_init(&ctx, "pw", "svc", 60000); const uint8_t *k = shield_get_key(&ctx); printf("%02x", k[0]); shield_wipe(&ctx); printf("%02x", k[0]); // prints 00`
- **Fix Complexity**: MEDIUM — Requires API change to copy-based getter.
- **Remediation**: Replace `shield_get_key()` with `shield_copy_key(ctx, out_buf, buf_len)` that copies key material into a caller-owned buffer. This makes the copy explicit and gives callers responsibility for wiping their buffer.

---

### SHIELD-A03-031: Python self._key — Underscore Convention Only, No Enforcement

- **Severity**: LOW
- **CWE**: CWE-200 (Exposure of Sensitive Information)
- **Location**: `python/shield/core.py:82,106`
- **Evidence**:

```python
# core.py:82 — Key stored as instance attribute
self._key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)

# core.py:106 — with_key sets _key directly
instance._key = key
```

Python's `self._key` uses the single underscore naming convention, which is advisory only — there is no access control enforcement. Any code can access `shield_instance._key` directly. Additionally:

1. `vars(shield_instance)` returns `{'_key': b'...', '_counter': 0, '_max_age_ms': 60000}` — key visible in dict
2. `shield_instance.__dict__` exposes key
3. `pickle.dumps(shield_instance)` serializes the key
4. `repr()` of `__dict__` includes key bytes

The `@property def key` accessor makes this worse by providing a "clean" public API that encourages key access.

- **Impact**: Python's attribute model means the key is always accessible. The `_key` naming convention signals "private" but any debugging, serialization, or introspection code can extract the key. Flask/Django debug toolbars, Sentry error reporting, and similar tools may capture `__dict__` contents in error reports.
- **Reproduction**: `s = Shield("pw", "svc"); print(vars(s))` — prints full key.
- **Fix Complexity**: MEDIUM — `__slots__` + name mangling would improve but not fully prevent.
- **Remediation**: Use `__key` (double underscore) for name mangling. Add `__slots__` to prevent `__dict__` attribute access. Override `__repr__` to exclude key material. Add `__reduce__` to prevent pickling of key data.

---

### SHIELD-A03-032: Rust Shield Struct — Zeroize Correct, No Debug/Clone on Key Types

- **Severity**: INFO
- **CWE**: N/A (Positive finding)
- **Location**: `shield-core/src/shield.rs:51-52`
- **Evidence**:

```rust
// shield.rs:51-52 — Correct: Zeroize + ZeroizeOnDrop, NO Debug or Clone
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Shield {
    key: [u8; 32],
    // ...
}
```

The Rust `Shield` struct correctly:
1. Derives `Zeroize` and `ZeroizeOnDrop` for automatic key cleanup
2. Does NOT derive `Debug` — `println!("{:?}", shield)` will not compile
3. Does NOT derive `Clone` — key cannot be accidentally duplicated
4. Does NOT derive `Serialize` — key cannot be serialized

The `key()` method still exposes a reference, but the type-level protections prevent accidental exposure via Debug output, cloning, or serialization.

- **Impact**: Positive — Rust's type system prevents the most common accidental key exposure vectors. The remaining risk is the explicit `key()` method call.
- **Remediation**: None required. Gate `key()` behind `#[cfg(feature = "expose-keys")]` to complete the protection.

---

## Key Accessor Surface Map (All Implementations)

| # | Language | File:Line | Symbol | Access | Key Type | Risk |
|---|----------|-----------|--------|--------|----------|------|
| 1 | Rust | `shield.rs:381` | `pub fn key()` | Public method | Master/derived | HIGH |
| 2 | Python | `core.py:298-301` | `@property key` | Public property | Master/derived | HIGH |
| 3 | JavaScript | `shield.js:280-282` | `get key()` | Public getter | Master/derived | HIGH |
| 4 | Go | `shield.go:105` | `Shield.Key()` | Exported method | Master/derived | HIGH |
| 5 | Go | `identity.go:239` | `Identity.Key()` | Exported method | Identity key | HIGH |
| 6 | Go | `identity.go:311` | `Session.Key()` | Exported method | Session key | HIGH |
| 7 | Go | `group.go:112` | `GroupEncryption.GroupKey()` | Exported method | Group key | HIGH |
| 8 | Go | `exchange.go:176` | `QRExchange.Key()` | Exported method | Exchange key | HIGH |
| 9 | C | `shield.c:656` | `shield_get_key()` | Public function | Master/derived | HIGH |
| 10 | Java | `Shield.java:123` | `public getKey()` | Public method | Master/derived | HIGH |
| 11 | C# | `Shield.cs:65` | `public GetKey()` | Public method | Master/derived | HIGH |
| 12 | Swift | `Shield.swift:43` | `public getKey()` | Public method | Master/derived | HIGH |
| 13 | Kotlin | `Shield.kt:181` | `fun getKey()` | Public method | Master/derived | HIGH |
| 14 | WASM | `wasm.rs:92` | `pub fn key()` | WASM export | Master/derived | HIGH |
| 15 | Android | `SecureKeyStore.kt:77` | `getKey(alias)` | Public method | Stored key | MEDIUM |
| 16 | iOS | `SecureKeychain.swift` | `retrieve(for:)` | Public method | Stored key | MEDIUM |
| 17 | JS | `shield.js:347` | `generateKeystream` | Module export | Keystream fn | MEDIUM |
| 18 | Python | `core.py:82` | `self._key` | Attribute access | Master/derived | LOW |

**Exposure Summary**:
- Public key accessors: 16 (all critical key types)
- No-copy returns (mutable reference risk): 5 (Rust borrow, Python ref, JS Buffer, Go slice, C pointer)
- Defensive copy returns: 5 (Java, C#, Swift, Kotlin, WASM)
- Platform-mediated (Keystore/Keychain): 2 (Android, iOS)
- Internal function exported: 1 (JS `generateKeystream`)
- Convention-only privacy: 1 (Python `self._key`)

---

## Finding Summary (TASK-1-013)

| ID | Title | Severity | CWE |
|----|-------|----------|-----|
| SHIELD-A03-026 | All 12 Impls Expose Raw Key — No Feature Gate | HIGH | CWE-200 |
| SHIELD-A03-027 | Go — 4 Additional Key Accessors Beyond Shield.Key() | MEDIUM | CWE-200 |
| SHIELD-A03-028 | JS/Python Key Accessors Return Mutable References | MEDIUM | CWE-496 |
| SHIELD-A03-029 | JS Exports generateKeystream as Public API | MEDIUM | CWE-749 |
| SHIELD-A03-030 | C shield_get_key() Returns Raw Pointer — No Lifetime | MEDIUM | CWE-200 |
| SHIELD-A03-031 | Python self._key — Convention-Only Privacy | LOW | CWE-200 |
| SHIELD-A03-032 | Rust Shield — Zeroize Correct, No Debug/Clone | INFO | N/A |

**Total**: 7 findings (1 HIGH, 4 MEDIUM, 1 LOW, 1 INFO)

**Total (TASK-1-012)**: 7 findings (0 HIGH, 2 MEDIUM, 2 LOW, 3 INFO)

---

## Cumulative A03 Finding Summary

| ID | Title | Severity | CWE | Task |
|----|-------|----------|-----|------|
| SHIELD-A03-001 | Rust — 6 Structs Missing Zeroize/ZeroizeOnDrop | HIGH | CWE-244 | 1-010 |
| SHIELD-A03-002 | Python — No Key Zeroization (GC-Dependent) | MEDIUM | CWE-244 | 1-010 |
| SHIELD-A03-003 | JavaScript — No Key Zeroization (GC-Dependent) | MEDIUM | CWE-244 | 1-010 |
| SHIELD-A03-004 | Go — No Key Zeroization | MEDIUM | CWE-244 | 1-010 |
| SHIELD-A03-005 | RecoveryCodes — Secret Strings Cannot Zeroize | LOW | CWE-244 | 1-010 |
| SHIELD-A03-006 | C# SecureWipe Uses Array.Clear — May Be Optimized | LOW | CWE-14 | 1-010 |
| SHIELD-A03-007 | Swift/Kotlin secureWipe — Simple Loop May Be Optimized | LOW | CWE-14 | 1-010 |
| SHIELD-A03-008 | Manual Wipe Not Automatic — Caller Must Invoke | INFO | CWE-404 | 1-010 |
| SHIELD-A03-009 | C Volatile Pointer Wipe — Correct Pattern | INFO | N/A | 1-010 |
| SHIELD-A03-010 | WASM Inherits Rust Zeroize — Correct | INFO | N/A | 1-010 |
| SHIELD-A03-011 | C Fingerprint — strcat() Buffer Overflow | HIGH | CWE-120 | 1-011 |
| SHIELD-A03-012 | C Ratchet/Signature — Missing NULL Checks | HIGH | CWE-476 | 1-011 |
| SHIELD-A03-013 | C Fingerprint — popen() Command Injection Surface | MEDIUM | CWE-78 | 1-011 |
| SHIELD-A03-014 | C — Plaintext/Keystream Not Wiped Before free() | MEDIUM | CWE-244 | 1-011 |
| SHIELD-A03-015 | C Recovery Code — Buffer Overflow When length > 8 | LOW | CWE-120 | 1-011 |
| SHIELD-A03-016 | C recovery_get_code — strcpy Without Bounds Check | LOW | CWE-120 | 1-011 |
| SHIELD-A03-017 | C HMAC k_ipad/k_opad Not Wiped After Use | LOW | CWE-244 | 1-011 |
| SHIELD-A03-018 | C generate_keystream — Stack Buffer Correct | INFO | N/A | 1-011 |
| SHIELD-A03-019 | WASM key() Exports Raw Key to JS Heap | MEDIUM | CWE-316 | 1-012 |
| SHIELD-A03-020 | WASM Linear Memory Exposes Key Material | MEDIUM | CWE-316 | 1-012 |
| SHIELD-A03-021 | 4x .unwrap() — Panic Instead of JsError | LOW | CWE-248 | 1-012 |
| SHIELD-A03-022 | WasmClient Exported — Bypasses SDK Safety | LOW | CWE-749 | 1-012 |
| SHIELD-A03-023 | Decrypted Plaintext in JS String — Unzeroed | INFO | CWE-316 | 1-012 |
| SHIELD-A03-024 | forbid(unsafe_code) Confirmed | INFO | N/A | 1-012 |
| SHIELD-A03-025 | No Persistent Key Storage — Correct | INFO | N/A | 1-012 |

**Cumulative A03 Total**: 25 findings (3 HIGH, 7 MEDIUM, 7 LOW, 8 INFO)
