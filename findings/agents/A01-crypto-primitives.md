# A01 — Crypto Primitives Findings

**Agent**: Agent 1 — Crypto Primitives
**Phase**: 1 (Crypto Core)
**Status**: IN-PROGRESS (TASK-1-001 through TASK-1-005)
**Last Updated**: 2026-03-01T09:00:00+03:00

---

## TASK-1-001: PBKDF2 Parameter Audit

### SHIELD-A01-001: Key Separation Violation — Same Key for Encryption and HMAC
- **Tag**: VULN
- **Severity**: HIGH
- **CWE**: CWE-330 (Use of Insufficiently Random Values / Improper Key Derivation)
- **Location**: ALL 12 implementations:
  - `shield-core/src/shield.rs:224` — `hmac::Key::new(hmac::HMAC_SHA256, key)` uses encryption key directly
  - `python/shield/core.py:197` — `hmac.new(self._key, ...)` uses PBKDF2 output directly
  - `javascript/src/shield.js:159` — same pattern
  - `go/shield/shield.go:131` — `hmac.New(sha256.New, key)` uses encryption key
  - `c/src/shield.c:424` — `shield_hmac_sha256(ctx->key, ...)` uses encryption key
  - `java/src/main/java/ai/guard8/shield/Shield.java` — same pattern
  - `csharp/Shield/Shield.cs` — same pattern
  - `swift/Sources/Shield/Shield.swift` — same pattern
  - `kotlin/src/main/kotlin/ai/guard8/shield/Shield.kt` — same pattern
  - `android/.../Shield.kt` — same pattern
  - `ios/Sources/Shield/Shield.swift` — same pattern
  - `shield-core/src/wasm.rs` — delegates to Rust core, same key
- **Evidence**: PROTOCOL.md specifies `mac_key = SHA256(master_key || "mac")` but NO implementation follows this. All use the raw 32-byte PBKDF2 output for BOTH XOR keystream generation AND HMAC authentication.
  ```rust
  // shield.rs:224 — same key used for HMAC as for encryption
  let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
  ```
  ```python
  # core.py:197 — self._key is the PBKDF2 output, used for both
  mac = hmac.new(self._key, nonce + ciphertext, hashlib.sha256).digest()[:MAC_SIZE]
  ```
- **Impact**: Using the same key for both encryption and authentication violates the key separation principle. In constructions like Encrypt-then-MAC, using independent keys prevents multi-key attacks and simplifies security proofs. While no practical attack against HMAC-SHA256 exploiting key reuse with SHA256-CTR is publicly known, this weakens the theoretical security model and contradicts the project's own protocol specification.
- **Reproduction**:
  1. Read PROTOCOL.md — it specifies `mac_key = SHA256(master_key || "mac")`
  2. Read any implementation's encrypt function — the HMAC key IS the encryption key
  3. No key separation exists in any of the 12 implementations
- **Fix Complexity**: MEDIUM (requires wire format change or versioned key derivation)
- **Remediation**: Derive separate keys: `enc_key = HKDF(master_key, "encrypt")`, `mac_key = HKDF(master_key, "mac")`. Must be done in ALL 12 implementations simultaneously to maintain interop. Consider making this a v3 format change.
- **Verification Notes**: VULN — confirmed by reading all 12 implementations. Every single one passes the raw PBKDF2 output as the HMAC key. The protocol spec explicitly says to derive a separate MAC key, making this a spec-to-implementation discrepancy.

---

### SHIELD-A01-002: JavaScript Allows Configurable PBKDF2 Iterations (Downgrade Attack)
- **Tag**: VULN
- **Severity**: HIGH
- **CWE**: CWE-916 (Use of Password Hash With Insufficient Computational Effort)
- **Location**: `javascript/src/shield.js:67`
- **Evidence**:
  ```javascript
  // shield.js:67 — caller can set iterations to 1
  const iterations = options.iterations || PBKDF2_ITERATIONS;
  ```
  Constructor accepts `options.iterations` without minimum validation. An integrator can (accidentally or maliciously) set `iterations: 1`, reducing PBKDF2 to effectively no key stretching.
- **Impact**: If an application using the JS SDK passes a low iteration count (e.g., `iterations: 1`), the derived key becomes trivially brutable. A single SHA256 operation would derive the key from any password, reducing security from password-strength to zero.
- **Reproduction**:
  ```javascript
  const shield = new Shield('password', 'service', { iterations: 1 });
  // Key derived with only 1 PBKDF2 iteration — trivially brutable
  ```
- **Fix Complexity**: LOW
- **Remediation**: Add minimum iteration validation: `if (options.iterations && options.iterations < 100000) throw new Error('Minimum 100000 iterations required');` Or remove the option entirely.
- **Verification Notes**: VULN — confirmed. Only the JavaScript implementation exposes this option. Rust, Python, Go, C, Java, C#, Swift, Kotlin, Android, iOS all hardcode 100,000 iterations. JS is the only one that accepts caller-controlled iterations.

---

### SHIELD-A01-003: JavaScript Salt Type Confusion Bypasses Derivation
- **Tag**: VULN
- **Severity**: HIGH
- **CWE**: CWE-843 (Access of Resource Using Incompatible Type / Type Confusion)
- **Location**: `javascript/src/shield.js:65-66`
- **Evidence**:
  ```javascript
  // shield.js:65-66
  const salt = options.salt ||
      crypto.createHash('sha256').update(service).digest();
  ```
  If caller passes `options.salt` as a truthy non-Buffer value (e.g., a string or number), it bypasses the SHA256(service) salt derivation. The raw value gets passed to `crypto.pbkdf2Sync()` which may coerce it silently, producing a different (weaker or predictable) key.
- **Impact**: An integrator who passes a string salt (e.g., `{salt: "mysalt"}`) gets a different key derivation than expected. A short string salt reduces key uniqueness. An attacker who knows the integrator's salt pattern could pre-compute keys.
- **Reproduction**:
  ```javascript
  // These produce different keys:
  const s1 = new Shield('pass', 'svc');  // salt = SHA256("svc")
  const s2 = new Shield('pass', 'svc', { salt: 'svc' });  // salt = "svc" raw string
  // s2 uses raw string "svc" as salt — only 3 bytes, no SHA256 derivation
  ```
- **Fix Complexity**: LOW
- **Remediation**: Validate salt type: `if (options.salt && !Buffer.isBuffer(options.salt)) throw new TypeError('salt must be a Buffer');`
- **Verification Notes**: VULN — confirmed by reading shield.js:65-66. The `||` operator allows any truthy value through. `crypto.pbkdf2Sync` accepts strings for salt parameter, so no runtime error occurs — just silently different keys.

---

### SHIELD-A01-004: Public Key Accessor Exposes Derived Key Material in ALL Implementations
- **Tag**: VERIFIED
- **Severity**: HIGH
- **CWE**: CWE-200 (Exposure of Sensitive Information)
- **Location**:
  - `shield-core/src/shield.rs:381-383` — `pub fn key() -> &[u8; 32]`
  - `python/shield/core.py` — `def key(self)` property
  - `javascript/src/shield.js` — `key()` method
  - `go/shield/shield.go:106` — `func (s *Shield) Key() []byte`
  - `c/src/shield.c:656` — `shield_get_key(const shield_t *ctx)`
  - `java/.../Shield.java:123` — `public byte[] getKey()`
  - `swift/.../Shield.swift:43` — `public func getKey() -> [UInt8]`
  - `kotlin/.../Shield.kt:181` — `fun getKey(): ByteArray`
  - `android/.../Shield.kt` — similar
  - `ios/.../Shield.swift` — similar
  - `shield-core/src/wasm.rs:92` — `pub fn key(&self) -> Vec<u8>` (WASM-exported!)
- **Evidence**:
  ```rust
  // shield.rs:381 — public method, no feature gate
  pub fn key(&self) -> &[u8; 32] {
      &self.key
  }
  ```
  ```javascript
  // WASM — key is exported to JavaScript!
  pub fn key(&self) -> Vec<u8> {
      self.inner.key().to_vec()
  }
  ```
- **Impact**: Any code with a reference to a Shield instance can extract the raw derived key. The WASM export is especially dangerous — JavaScript code in the browser can call `.key()` and extract the key from WASM memory. This is labeled "testing/debugging" but ships in production builds.
- **Reproduction**: In any language: `shield.key()` or `shield.getKey()` returns the raw 32-byte derived key.
- **Fix Complexity**: LOW (remove or feature-gate the accessor)
- **Remediation**: Remove `key()` from public API, or gate behind a `#[cfg(test)]` / debug-only feature flag. The WASM export is highest priority to remove.
- **Verification Notes**: VERIFIED — confirmed in all 12 implementations. The method is public and unrestricted.

---

### SHIELD-A01-005: PBKDF2 Constants Verified Consistent Across All 12 Implementations
- **Tag**: NON-VULN
- **Severity**: INFO
- **CWE**: N/A
- **Location**: All 12 implementations
- **Evidence**:
  | Language | Iterations | Key Size | Nonce Size | MAC Size |
  |----------|-----------|----------|------------|----------|
  | Rust | 100,000 | 32 | 16 | 16 |
  | Python | 100,000 | 32 | 16 | 16 |
  | JavaScript | 100,000 | 32 | 16 | 16 |
  | Go | 100,000 | 32 | 16 | 16 |
  | C | 100,000 | 32 | 16 | 16 |
  | Java | 100,000 | 32 | 16 | 16 |
  | C# | 100,000 | 32 | 16 | 16 |
  | Swift | 100,000 | 32 | 16 | 16 |
  | Kotlin | 100,000 | 32 | 16 | 16 |
  | Android | 100,000 | 32 | 16 | 16 |
  | iOS | 100,000 | 32 | 16 | 16 |
  | WASM | (delegates to Rust) | 32 | 16 | 16 |
- **Impact**: N/A — constants are correct and consistent.
- **Verification Notes**: NON-VULN — all implementations use identical constants. PBKDF2-SHA256 with 100k iterations meets OWASP 2023 minimum. 256-bit key, 128-bit nonce, 128-bit MAC are adequate. PAKE Exchange uses 200k iterations (higher, correct).

---

### SHIELD-A01-006: Modulo Bias in Padding Length Calculation
- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-330 (Use of Insufficiently Random Values)
- **Location**:
  - `shield-core/src/shield.rs:204` — `(random_byte % 97) + 32`
  - `python/shield/core.py:183` — same formula
  - All other implementations — same formula
- **Evidence**:
  ```rust
  // shield.rs:204
  let pad_len = (random_bytes[0] % 97) + 32;
  ```
  `256 % 97 = 62`, so values 32–93 have probability 3/256, while values 94–128 have probability 2/256. This creates a ~50% bias for lower padding values.
- **Impact**: Padding length is slightly non-uniform. This is a minor information leak — an attacker analyzing many ciphertexts could determine that shorter padding is more likely. Not security-critical since padding is after encryption and the padding length is already encrypted.
- **Reproduction**: Statistical test: encrypt 100,000 messages, record pad_len. Values 32-93 will appear ~1.5x more often than 94-128.
- **Fix Complexity**: LOW
- **Remediation**: Use rejection sampling: generate random bytes until value < 97*2 (or 97), then `pad_len = (value % 97) + 32`. Or use `random_byte % 97` only when `random_byte < 97 * floor(256/97)`.
- **Verification Notes**: VERIFIED — mathematical analysis confirms bias. Not exploitable for key recovery but degrades security margin.

---

## TASK-1-002: SHA256-CTR Mode Verification Across All Languages

### CTR Mode Verification Matrix

| Aspect | Rust | Python | JS | Go | C | Java | C# | Swift | Kotlin | Android | iOS | WASM |
|--------|------|--------|----|----|---|------|----|-------|--------|---------|-----|------|
| Counter init (keystream) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | Rust |
| Counter type (keystream) | u32 LE | u32 LE | u32 LE | u32 LE | u32 LE | u32 LE | int LE* | u32 LE | int LE | int LE | int LE | Rust |
| SHA input order | k\|\|n\|\|c | k\|\|n\|\|c | k\|\|n\|\|c | k\|\|n\|\|c | k\|\|n\|\|c | k\|\|n\|\|c | k\|\|n\|\|c | k\|\|n\|\|c | k\|\|n\|\|c | k\|\|n\|\|c | k\|\|n\|\|c | Rust |
| XOR correct | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Rust |
| Overflow check | None | None | None | None | None | None | None | None | None | None | None | Rust |
| Wire format | V2 | V2 | V2 | V2 | V2 | V2 | **V1** | **V1** | **V1** | V1 | V1 | V2 |
| V2 header counter | 0 | incr++ | incr++ | 0 | 0 | 0 | N/A | N/A | N/A | incr++ | incr++ | 0 |
| Replay protection | Y | Y | Y | Y | Y | Y | **N** | **N** | **N** | N | N | Y |
| Pad validation | **N** | Y | Y | Y | Y | Y | N/A | N/A | N/A | N/A | N/A | **N** |

**Legend**: `*` = C# uses `BitConverter.GetBytes(i)` which is system-endian (LE on x86/x64/ARM, but BE on other archs)

### SHIELD-A01-007: V1-Only Wire Format in C#, Kotlin, Swift — Missing V2 Replay Protection and Padding
- **Tag**: VULN
- **Severity**: HIGH
- **CWE**: CWE-294 (Authentication Bypass by Capture-replay)
- **Location**:
  - `csharp/Shield/Shield.cs:92-117` — `EncryptWithKey()` uses V1 format (counter prefix only, no timestamp/padding)
  - `kotlin/src/main/kotlin/ai/guard8/shield/Shield.kt:63-83` — same V1-only pattern
  - `swift/Sources/Shield/Shield.swift:72-94` — same V1-only pattern
- **Evidence**:
  ```csharp
  // csharp/Shield/Shield.cs:97-99 — V1 only: counter prefix (8 bytes of zeros), no timestamp, no padding
  // Counter prefix (8 bytes of zeros)
  byte[] dataToEncrypt = new byte[8 + plaintext.Length];
  Array.Copy(plaintext, 0, dataToEncrypt, 8, plaintext.Length);
  ```
  ```kotlin
  // kotlin/Shield.kt:67-69 — V1 only: counter prefix (8 bytes of zeros)
  val dataToEncrypt = ByteArray(8 + plaintext.size)
  System.arraycopy(plaintext, 0, dataToEncrypt, 8, plaintext.size)
  ```
  ```swift
  // swift/Shield.swift:79-80 — V1 only: counter prefix (8 bytes of zeros)
  var dataToEncrypt = [UInt8](repeating: 0, count: 8) + plaintext
  ```
  Meanwhile, Rust, Python, JS, Go, C, Java all implement V2 with `counter(8) || timestamp(8) || pad_len(1) || padding(32-128) || plaintext`.
- **Impact**: Messages encrypted by C#, Kotlin (JVM), or Swift have:
  1. **No replay protection** — captured ciphertext can be replayed indefinitely since there's no timestamp
  2. **No length obfuscation** — ciphertext length reveals exact plaintext length (no random padding)
  3. **Cross-language interop break** — V2-aware decryptors (Rust, Python, JS, Go, C, Java) auto-detect V1 by timestamp heuristic and will handle V1 messages correctly, but C#/Kotlin/Swift can't decrypt V2 messages with timestamp/padding
- **Reproduction**:
  1. Encrypt with C# Shield: `Shield.QuickEncrypt(key, plaintext)` — output is V1
  2. Encrypt with Java Shield: `Shield.quickEncrypt(key, plaintext)` — output is V2
  3. C# ciphertext is 8 bytes shorter (no timestamp) + 32-128 bytes shorter (no padding)
  4. C# cannot decrypt Java's V2 output (no V2 detection logic)
- **Fix Complexity**: MEDIUM
- **Remediation**: Upgrade C#, Kotlin (JVM), and Swift implementations to V2 wire format matching Rust/Python/JS/Go/C/Java. Must add timestamp generation, padding, and V2 auto-detection in decrypt.
- **Verification Notes**: VULN — confirmed by reading all 12 encrypt functions. C#, Kotlin, Swift literally only prepend 8 zero bytes as counter, with no timestamp or padding. Their decrypt functions only handle V1 (skip 8-byte counter prefix).

---

### SHIELD-A01-008: Android and iOS Implementations Use V1 Wire Format with Incrementing Counter (Divergent from All Other Implementations)
- **Tag**: VULN
- **Severity**: MEDIUM
- **CWE**: CWE-838 (Inappropriate Encoding for Output)
- **Location**:
  - `android/shield/src/main/java/ai/guard8/shield/Shield.kt:95-118` — V1 with incrementing counter
  - `ios/Sources/Shield/Shield.swift:81-106` — V1 with incrementing counter
- **Evidence**:
  ```kotlin
  // android/Shield.kt:97-99 — counter increments per encrypt call (V1 with counter)
  val counterBytes = ByteArray(8)
  for (i in 0..7) counterBytes[i] = (counter shr (i * 8)).toByte()
  counter++
  ```
  ```swift
  // ios/Shield.swift:86-90 — counter increments per encrypt call
  var counterBytes = [UInt8](repeating: 0, count: 8)
  for i in 0..<8 {
      counterBytes[i] = UInt8(truncatingIfNeeded: counter >> (i * 8))
  }
  counter += 1
  ```
  Format: `counter(8) || plaintext` — no timestamp, no padding. Counter increments per encrypt.
- **Impact**:
  1. **No replay protection** via timestamps (same as SHIELD-A01-007)
  2. **No length obfuscation** (same as SHIELD-A01-007)
  3. **Counter state is instance-local** — new Shield instance resets counter to 0, so counter provides no replay protection across instances
  4. **Diverges from Python/JS** which also increment but use V2 format with timestamp+padding
- **Reproduction**: Create new Android/iOS Shield instance, encrypt twice — counter goes 0,1. Create new instance — counter restarts at 0.
- **Fix Complexity**: MEDIUM
- **Remediation**: Upgrade to V2 wire format with timestamp and padding.
- **Verification Notes**: VULN — confirmed by reading source. Android and iOS are in a "middle ground" — they have an incrementing counter (like Python/JS) but no V2 timestamp/padding (like C#/Kotlin/Swift). This creates a third wire format variant.

---

### SHIELD-A01-009: C# BitConverter.GetBytes() Endianness is Platform-Dependent
- **Tag**: VULN
- **Severity**: MEDIUM
- **CWE**: CWE-198 (Use of Incorrect Byte Ordering)
- **Location**: `csharp/Shield/Shield.cs:169`
- **Evidence**:
  ```csharp
  // Shield.cs:169 — BitConverter.GetBytes returns SYSTEM-endian bytes
  BitConverter.GetBytes(i).CopyTo(block, KeySize + NonceSize);
  ```
  `BitConverter.GetBytes(int)` uses the native endianness of the platform. On x86/x64/ARM (little-endian), this produces LE bytes matching all other implementations. On big-endian platforms (some embedded systems, older POWER/SPARC), this would produce BE bytes, causing **different keystream** and **interop failure**.
- **Impact**: C# Shield running on a big-endian .NET runtime (rare but possible: Mono on MIPS, old PowerPC) would produce ciphertext incompatible with all other implementations. Decryption would silently fail with wrong plaintext (MAC check would catch it).
- **Reproduction**:
  1. Check `BitConverter.IsLittleEndian` — if false, keystream diverges
  2. On BE platform: `BitConverter.GetBytes(1)` → `[0, 0, 0, 1]` (BE) instead of `[1, 0, 0, 0]` (LE)
- **Fix Complexity**: LOW
- **Remediation**: Replace with explicit LE encoding:
  ```csharp
  block[KeySize + NonceSize] = (byte)i;
  block[KeySize + NonceSize + 1] = (byte)(i >> 8);
  block[KeySize + NonceSize + 2] = (byte)(i >> 16);
  block[KeySize + NonceSize + 3] = (byte)(i >> 24);
  ```
  Or use `BinaryPrimitives.WriteInt32LittleEndian()`.
- **Verification Notes**: VULN — confirmed by reading Shield.cs:169. All other implementations explicitly use LE encoding. Java uses `ByteBuffer.order(ByteOrder.LITTLE_ENDIAN)`, Go uses `binary.LittleEndian`, etc.

---

### SHIELD-A01-010: V2 Header Counter Field Divergence Between Implementations
- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-838 (Inappropriate Encoding for Output)
- **Location**:
  - `shield-core/src/shield.rs:199` — counter always `0u64`
  - `python/shield/core.py:181-182` — counter increments per encrypt
  - `javascript/src/shield.js:137-138` — counter increments per encrypt
  - `go/shield/shield.go:197` — counter always `0`
  - `c/src/shield.c:335` — counter always `{0}`
  - `java/src/main/java/ai/guard8/shield/Shield.java:162` — counter always `0`
- **Evidence**:
  ```rust
  // Rust shield.rs:199 — always 0
  let counter_bytes = 0u64.to_le_bytes();
  ```
  ```python
  # Python core.py:181-182 — increments
  counter_bytes = struct.pack("<Q", self._counter)
  self._counter += 1
  ```
  ```javascript
  // JS shield.js:137-138 — increments
  counterBytes.writeBigUInt64LE(BigInt(this._counter));
  this._counter++;
  ```
- **Impact**: The V2 counter field is encrypted, so it doesn't affect interoperability — decryptors don't use it. However, it means the counter field's original purpose (replay detection via counter monotonicity) is only partially implemented. Python/JS increment it (useful if receiver tracks seen counters), while Rust/Go/C/Java always write 0 (counter field is wasted bytes).
- **Reproduction**: Encrypt 3 messages with Python Shield, decrypt — counter bytes are 0, 1, 2. Encrypt 3 with Rust — counter bytes are always 0.
- **Fix Complexity**: LOW
- **Remediation**: Decide on one behavior: either all implementations increment (for potential counter-based replay detection) or all use 0 (and rely solely on timestamp for replay protection). Document the decision.
- **Verification Notes**: VERIFIED — confirmed by reading all V2 encrypt functions. Counter is encrypted so no interop issue, but behavioral divergence should be unified.

---

### SHIELD-A01-011: JavaScript O(n²) Buffer.concat in Keystream Generation (Algorithmic DoS)
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-405 (Asymmetric Resource Consumption / Amplification)
- **Location**: `javascript/src/shield.js:36-48`
- **Evidence**:
  ```javascript
  // shield.js:36-48 — O(n²) allocation pattern
  function generateKeystream(key, nonce, length) {
      let keystream = Buffer.alloc(0);
      const numBlocks = Math.ceil(length / 32);
      for (let i = 0; i < numBlocks; i++) {
          // ... hash ...
          keystream = Buffer.concat([keystream, block]); // Copies entire keystream each iteration!
      }
      return keystream.slice(0, length);
  }
  ```
  `Buffer.concat` creates a new buffer and copies all existing data on every iteration. For a 1 MB plaintext (32,768 blocks), this performs ~32,768 copies of growing buffers, totaling ~16 GB of memory traffic.
- **Impact**: Encrypting large messages with the JavaScript implementation is O(n²) in time and memory allocation. A 10 MB message would cause ~5 TB of memory allocation churn. This is a denial-of-service vector if an attacker can influence message size (e.g., in a server processing user-uploaded encrypted data).
  - All other implementations pre-allocate: Rust uses `Vec::with_capacity()`, Go uses `make([]byte, 0, n*32)`, Java/Kotlin/C# pre-allocate `new byte[n*32]`, C writes directly to pre-allocated output buffer.
- **Reproduction**:
  ```javascript
  const shield = new Shield('pass', 'svc');
  const start = Date.now();
  shield.encrypt(Buffer.alloc(1_000_000)); // 1 MB — measure time
  console.log(`Took ${Date.now() - start}ms`);
  // Compare with Python: same plaintext size will be orders of magnitude faster
  ```
- **Fix Complexity**: LOW
- **Remediation**: Pre-allocate the output buffer:
  ```javascript
  const keystream = Buffer.alloc(numBlocks * 32);
  for (let i = 0; i < numBlocks; i++) {
      // ...hash...
      block.copy(keystream, i * 32);
  }
  ```
- **Verification Notes**: VERIFIED — confirmed by reading shield.js:36-48 and comparing with all other implementations which pre-allocate.

---

### SHIELD-A01-012: No Counter Overflow Check in Keystream Generation (128 GiB Theoretical Limit)
- **Tag**: VERIFIED
- **Severity**: INFO
- **CWE**: CWE-190 (Integer Overflow)
- **Location**: All 12 implementations — keystream counter is u32 (4 bytes)
- **Evidence**: The block counter in `generateKeystream` is a 32-bit unsigned integer. Maximum blocks = 2^32 = 4,294,967,296. At 32 bytes per block, maximum keystream = 128 GiB. No implementation checks for this overflow.
  ```rust
  // Rust — i is usize, cast to u32: wraps at 2^32
  let counter = (i as u32).to_le_bytes();
  ```
  ```python
  # Python — struct.pack("<I", i) raises OverflowError at 2^32 (safe!)
  counter = struct.pack("<I", i)
  ```
  ```javascript
  // JS — writeUInt32LE wraps silently at 2^32
  counter.writeUInt32LE(i);
  ```
- **Impact**: If a message exceeds 128 GiB, the counter wraps to 0, reusing keystream blocks. This would allow XOR of two ciphertext blocks encrypted with the same keystream, revealing plaintext XOR. However, 128 GiB is impractically large for Shield's use cases (API secrets, tokens, configs). Python is actually safe here — `struct.pack("<I", i)` raises `OverflowError` at 2^32.
- **Reproduction**: Theoretical only — requires encrypting a 128+ GiB message.
- **Fix Complexity**: LOW
- **Remediation**: Add a length check: `if (length > 128 * 1024 * 1024 * 1024) error("message too large")`. This is defense-in-depth only.
- **Verification Notes**: INFO — not practically exploitable given Shield's intended use cases (short secrets, tokens, configs). Python's struct.pack naturally prevents overflow. Documenting for completeness.

---

## TASK-1-003: HMAC-SHA256 MAC Verification Audit

### MAC Verification Matrix

| Aspect | Rust | Python | JS | Go | C | Java | C# | Swift | Kotlin | Android | iOS | WASM |
|--------|------|--------|----|----|---|------|----|-------|--------|---------|-----|------|
| MAC order | EtM | EtM | EtM | EtM | EtM | EtM | EtM | EtM | EtM | EtM | EtM | Rust |
| MAC input | n‖ct | n‖ct | n‖ct | n‖ct | n‖ct | n‖ct | n‖ct | n‖ct | n‖ct | n‖ct | n‖ct | Rust |
| Truncation | 16B | 16B | 16B | 16B | 16B | 16B | 16B | 16B | 16B | 16B | 16B | Rust |
| Verify-first | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Rust |
| Const-time fn | subtle | hmac.cd | tSE | subtle | custom* | custom* | custom* | custom* | custom* | custom* | custom* | subtle |
| Key separation | N | N | N | N | N | N | N | N | N | N | N | N |
| Early len return | N/A | N/A | N/A | N/A | N | Y | Y† | Y | Y | Y | Y | N/A |

**Legend**: EtM = Encrypt-then-MAC; n‖ct = nonce‖ciphertext; hmac.cd = `hmac.compare_digest()`; tSE = `crypto.timingSafeEqual()`; subtle = cryptographic library constant-time; custom* = hand-rolled XOR-accumulation; `†` = C# takes explicit length parameter but still has early return if array shorter than length.

### SHIELD-A01-013: Custom Constant-Time Comparison Instead of Platform Primitives in 8/12 Implementations
- **Tag**: VERIFIED
- **Severity**: INFO
- **CWE**: CWE-208 (Observable Timing Discrepancy)
- **Location**:
  - `java/src/main/java/ai/guard8/shield/Shield.java:357-365` — custom `constantTimeEquals()` with early return on `a.length != b.length`
  - `csharp/Shield/Shield.cs` — custom `ConstantTimeEquals(byte[] a, byte[] b, int length)` with early return on `a.Length < length`
  - `kotlin/src/main/kotlin/ai/guard8/shield/Shield.kt:148-154` — custom with early return on `a.size != b.size`
  - `swift/Sources/Shield/Shield.swift:187-192` — custom with `guard a.count == b.count`
  - `android/shield/src/main/java/ai/guard8/shield/Shield.kt:213-219` — custom with early return on `a.size != b.size`
  - `ios/Sources/Shield/Shield.swift:185-190` — custom with `guard a.count == b.count`
  - `c/src/shield.c:249-256` — custom with `volatile uint8_t result` (see SHIELD-A01-014)
  - `android/shield/src/main/java/ai/guard8/shield/StreamCipher.kt:129-135` — duplicate custom impl in StreamCipher
- **Evidence**:
  ```java
  // Java Shield.java:357-365 — custom instead of MessageDigest.isEqual()
  public static boolean constantTimeEquals(byte[] a, byte[] b) {
      if (a.length != b.length) {  // ← Early return leaks length inequality
          return false;
      }
      int result = 0;
      for (int i = 0; i < a.length; i++) {
          result |= a[i] ^ b[i];
      }
      return result == 0;
  }
  ```
  ```kotlin
  // Kotlin Shield.kt:148-154 — same pattern
  fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
      if (a.size != b.size) return false  // ← Early return
      var result = 0
      for (i in a.indices) {
          result = result or (a[i].toInt() xor b[i].toInt())
      }
      return result == 0
  }
  ```
  ```swift
  // Swift Shield.swift:187-192 — same pattern
  public static func constantTimeEquals(_ a: [UInt8], _ b: [UInt8]) -> Bool {
      guard a.count == b.count else { return false }  // ← Early return
      var result: UInt8 = 0
      for i in 0..<a.count { result |= a[i] ^ b[i] }
      return result == 0
  }
  ```
  Platform-provided alternatives exist: Java has `MessageDigest.isEqual()`, Go uses `subtle.ConstantTimeCompare()`, Python uses `hmac.compare_digest()`, Node.js uses `crypto.timingSafeEqual()`.
- **Impact**: The early return on length mismatch leaks whether the arrays are the same length. In Shield's MAC verification, both arrays are always MAC_SIZE (16 bytes), so this is NOT exploitable in practice. However:
  1. The custom implementations are publicly exported (Java `public static`, Kotlin `companion object`, Swift `public static`) and could be used by integrators for other purposes where length may vary
  2. Platform functions have been audited and hardened against compiler optimizations; custom implementations have not
  3. The `public` visibility means integrators may call `Shield.constantTimeEquals()` for their own secret comparison, where the length-leak could matter
- **Reproduction**: `Shield.constantTimeEquals(new byte[16], new byte[32])` — returns immediately (non-constant-time) because lengths differ. This is detectable via timing measurement.
- **Fix Complexity**: LOW
- **Remediation**: Replace custom implementations with platform primitives:
  - Java: `java.security.MessageDigest.isEqual(a, b)`
  - Kotlin/Android: `java.security.MessageDigest.isEqual(a, b)`
  - C#: `System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(a, b)` (.NET Core 2.1+)
  - Swift/iOS: Consider using `timingsafe_bcmp()` from Darwin libc, or keep custom but add `@usableFromInline` internal visibility
- **Verification Notes**: VERIFIED — all 8 custom implementations confirmed to have structurally correct XOR-accumulation loop but with early return on length mismatch. Not exploitable in MAC verification (fixed-length comparison) but exported publicly.

---

### SHIELD-A01-014: C `volatile`-Based Constant-Time Compare May Be Optimized by Compiler
- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-208 (Observable Timing Discrepancy)
- **Location**: `c/src/shield.c:249-256`
- **Evidence**:
  ```c
  // shield.c:249-256
  int shield_secure_compare(const uint8_t *a, const uint8_t *b, size_t len) {
      volatile uint8_t result = 0;
      size_t i;
      for (i = 0; i < len; i++) {
          result |= a[i] ^ b[i];
      }
      return result == 0;
  }
  ```
  The `volatile` qualifier on `result` prevents the compiler from eliding the variable, but it does NOT prevent:
  1. **Loop unrolling with branch elimination** — the compiler may determine that if early XOR results are non-zero, subsequent iterations don't affect the `result == 0` check, and short-circuit
  2. **The final `return result == 0`** — this comparison is NOT volatile-qualified, so the compiler could theoretically evaluate it before the loop completes
  3. **Memory access patterns** — `a[i]` and `b[i]` are non-volatile reads; the compiler can reorder or prefetch them

  Modern compilers (GCC 12+, Clang 15+) have been observed optimizing `volatile` accumulators in specific scenarios. The standard only guarantees that `volatile` accesses themselves are not reordered relative to other `volatile` accesses — it says nothing about non-volatile accesses around them.
- **Impact**: On certain compiler versions and optimization levels, the comparison MAY not be constant-time. This could enable a timing side-channel in MAC verification, allowing an attacker to determine the MAC byte-by-byte. In practice, most current compilers on x86-64 with `-O2` do NOT optimize this pattern, but it's not guaranteed by the C standard.
- **Reproduction**: Compile with `gcc -O3 -S shield.c` and inspect the assembly for `shield_secure_compare`. On most toolchains, the loop is preserved, but this should be verified on the target deployment toolchain.
- **Fix Complexity**: LOW
- **Remediation**: Use a barrier-based approach:
  ```c
  // Option 1: Use OpenSSL's CRYPTO_memcmp if linked
  #include <openssl/crypto.h>
  // CRYPTO_memcmp(a, b, len)

  // Option 2: Use compiler barrier
  int shield_secure_compare(const uint8_t *a, const uint8_t *b, size_t len) {
      volatile uint8_t result = 0;
      for (size_t i = 0; i < len; i++) {
          result |= a[i] ^ b[i];
      }
      // Compiler barrier to prevent reordering
      __asm__ volatile("" ::: "memory");
      return result == 0;
  }
  ```
- **Verification Notes**: VERIFIED — code confirmed at shield.c:249-256. The `volatile` approach is a well-known footgun in C crypto code. While current common toolchains preserve the loop, the C standard does not guarantee this.

---

### SHIELD-A01-015: MAC Verification Audit — Encrypt-then-MAC Correctly Implemented Across All Languages
- **Tag**: NON-VULN
- **Severity**: INFO
- **CWE**: N/A
- **Location**: All 12 implementations
- **Evidence**: Full audit confirms:
  1. **Encrypt-then-MAC order** — All 12 implementations compute MAC over `nonce || ciphertext` (the encrypted output), NOT over plaintext. This is the correct authenticated encryption paradigm.
  2. **MAC coverage includes nonce** — All implementations include the nonce in the MAC input, preventing nonce-substitution attacks.
  3. **Truncation is consistent** — All implementations truncate HMAC-SHA256 output to the first 16 bytes (128 bits) using `.prefix(16)`, `[:MAC_SIZE]`, `copyOf(MAC_SIZE)`, etc.
  4. **Verify-before-decrypt** — All implementations check MAC before performing any decryption. On MAC failure, no decrypted output is produced.

  Key evidence per language:
  - Rust: `tag.as_ref()[..MAC_SIZE]` + `ct_eq` before decrypt (shield.rs)
  - Python: `hmac.compare_digest()` before decrypt (core.py)
  - JS: `crypto.timingSafeEqual()` before decrypt (shield.js)
  - Go: `subtle.ConstantTimeCompare()` before decrypt (shield.go)
  - C: `shield_secure_compare()` before decrypt (shield.c)
  - Java: `constantTimeEquals()` before decrypt (Shield.java)
  - C#: `ConstantTimeEquals()` before decrypt (Shield.cs)
  - Kotlin: `constantTimeEquals()` before decrypt (Shield.kt)
  - Swift: `constantTimeEquals()` before decrypt (Shield.swift)
  - Android: `constantTimeEquals()` before decrypt (Shield.kt)
  - iOS: `constantTimeEquals()` before decrypt (Shield.swift)
  - WASM: delegates to Rust implementation
- **Impact**: N/A — MAC implementation is architecturally correct.
- **Verification Notes**: NON-VULN — comprehensive audit of all encrypt/decrypt paths in all 12 implementations confirms correct encrypt-then-MAC with verify-before-decrypt. Key separation issue already documented in SHIELD-A01-001.

---

## TASK-1-004: Nonce Generation Audit Across All Languages

### Nonce Generation CSPRNG Matrix

| Language | Source | Secure? | Length | Fresh per encrypt? | User-controllable? | Return checked? |
|----------|--------|---------|--------|-------------------|-------------------|-----------------|
| Rust | `ring::rand::SystemRandom` | Y | 16B | Y | No | Y (Result) |
| Python | `os.urandom(NONCE_SIZE)` | Y | 16B | Y | No | Y (raises) |
| JavaScript | `crypto.randomBytes(NONCE_SIZE)` | Y | 16B | Y | No | Y (throws) |
| Go | `crypto/rand.Read(nonce)` | Y | 16B | Y | No | Y (err check) |
| C | `/dev/urandom` (Unix) / `CryptGenRandom` (Win) | Y* | 16B | Y | No | Partial** |
| Java | `SecureRandom().nextBytes(nonce)` | Y | 16B | Y | No | N/A (void) |
| C# | `RandomNumberGenerator.Create()` | Y | 16B | Y | No | N/A (void) |
| Swift | `SecRandomCopyBytes(kSecRandomDefault, ...)` | Y | 16B | Y | No | Y (guard) |
| Kotlin | `SecureRandom().nextBytes(nonce)` | Y | 16B | Y | No | N/A (void) |
| Android | `SecureRandom().nextBytes(nonce)` | Y | 16B | Y | No | N/A (void) |
| iOS | `SecRandomCopyBytes(kSecRandomDefault, ...)` | **FAIL** | 16B | Y | No | **NO** |
| WASM | `getrandom` crate (delegates to host) | Y | 16B | Y | No | Y (Result) |

`*` C uses acceptable CSPRNG sources but has robustness concerns (see SHIELD-A01-018)
`**` C checks `n != len` but does not retry on EINTR
`FAIL` iOS discards return value — nonce is all-zeros on failure

### SHIELD-A01-016: iOS Discards SecRandomCopyBytes Return Value — Zero Nonce on Failure
- **Tag**: VULN
- **Severity**: HIGH
- **CWE**: CWE-252 (Unchecked Return Value)
- **Location**: `ios/Sources/Shield/Shield.swift:83`
- **Evidence**:
  ```swift
  // ios/Sources/Shield/Shield.swift:81-83 — return value DISCARDED
  public func encrypt(_ plaintext: [UInt8]) -> [UInt8] {
      var nonce = [UInt8](repeating: 0, count: Self.nonceSize)
      _ = SecRandomCopyBytes(kSecRandomDefault, Self.nonceSize, &nonce)
  ```
  The `_ =` syntax explicitly discards the return value of `SecRandomCopyBytes`. If the function fails (returns anything other than `errSecSuccess`), the nonce remains as the initialized `[UInt8](repeating: 0, count: 16)` — **16 zero bytes**.

  Compare with the **Swift** (non-iOS) implementation which correctly checks:
  ```swift
  // swift/Sources/Shield/Shield.swift:75 — CORRECT: checks return value
  guard SecRandomCopyBytes(kSecRandomDefault, nonceSize, &nonce) == errSecSuccess else {
      throw ShieldError.randomGenerationFailed
  }
  ```
- **Impact**: If `SecRandomCopyBytes` fails on an iOS device (e.g., during early boot, in a sandboxed extension with restricted entropy, or under resource pressure), the nonce becomes 16 zero bytes. This means:
  1. **Nonce reuse** — every failed-nonce encryption uses the same zero nonce, breaking CTR-mode security entirely
  2. **Keystream reuse** — two messages encrypted with the same key and zero nonce produce the same keystream; XOR of ciphertexts reveals XOR of plaintexts
  3. **Silent failure** — no error is raised; the caller believes encryption succeeded normally
- **Reproduction**:
  1. On iOS: `SecRandomCopyBytes` can fail when called from a background extension with limited entropy
  2. When it fails, nonce is `[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]`
  3. Two messages encrypted during this state share identical nonce → keystream reuse
- **Fix Complexity**: LOW
- **Remediation**: Check the return value and abort encryption on failure:
  ```swift
  let status = SecRandomCopyBytes(kSecRandomDefault, Self.nonceSize, &nonce)
  guard status == errSecSuccess else {
      // Return empty or throw error — do NOT proceed with zero nonce
      return []
  }
  ```
  Or change `encrypt()` to throw, matching the Swift package's pattern.
- **Verification Notes**: VULN — confirmed by reading ios/Sources/Shield/Shield.swift:83. The `_ =` is explicit. The Swift (non-iOS) package correctly guards this at swift/Sources/Shield/Shield.swift:75. The RatchetSession in iOS (`ios/Sources/Shield/RatchetSession.swift:140`) also discards with `_ =`, same vulnerability.

---

### SHIELD-A01-017: Swift GroupEncryption Falls Back to All-Zero Key on Random Failure
- **Tag**: VULN
- **Severity**: HIGH
- **CWE**: CWE-329 (Generation of Predictable IV/Key)
- **Location**:
  - `swift/Sources/Shield/GroupEncryption.swift:18`
  - `swift/Sources/Shield/GroupEncryption.swift:91`
- **Evidence**:
  ```swift
  // GroupEncryption.swift:17-18 — init() uses zero-key fallback
  public init() {
      self.groupKey = Shield.randomBytes(32) ?? [UInt8](repeating: 0, count: 32)
  }
  ```
  ```swift
  // GroupEncryption.swift:89-91 — rotateKey() uses same zero-key fallback
  public func rotateKey() -> [UInt8] {
      let oldKey = groupKey
      groupKey = Shield.randomBytes(32) ?? [UInt8](repeating: 0, count: 32)
      return oldKey
  }
  ```
  `Shield.randomBytes(32)` returns `nil` when `SecRandomCopyBytes` fails (see `swift/Sources/Shield/Shield.swift:196-201`). The `??` nil-coalescing operator then sets `groupKey` to **32 zero bytes**.
- **Impact**: If `SecRandomCopyBytes` fails during group creation or key rotation:
  1. **Predictable group key** — all-zero key is trivially guessable
  2. **All group messages compromised** — every message encrypted with the zero group key can be decrypted by anyone
  3. **Key rotation becomes key downgrade** — rotating the key may produce a weaker key than the original
  4. **Silent failure** — no error or indication that the key is zeros
- **Reproduction**:
  1. Simulate `SecRandomCopyBytes` failure (e.g., mock or restrict entropy)
  2. Create `GroupEncryption()` — groupKey will be 32 zero bytes
  3. Encrypt message → encrypted with predictable key → trivially decryptable
- **Fix Complexity**: LOW
- **Remediation**: Throw an error instead of falling back:
  ```swift
  public init() throws {
      guard let key = Shield.randomBytes(32) else {
          throw ShieldError.randomGenerationFailed
      }
      self.groupKey = key
  }
  ```
- **Verification Notes**: VULN — confirmed by reading GroupEncryption.swift:18,91 and Shield.swift:196-201. The `randomBytes()` function correctly returns nil on failure, but GroupEncryption silently falls back to zeros.

---

### SHIELD-A01-018: C Random Bytes Implementation Has Robustness Issues
- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-252 (Unchecked Return Value) + CWE-477 (Use of Obsolete Function)
- **Location**: `c/src/shield.c:265-288`
- **Evidence**:
  ```c
  // shield.c:265-288
  shield_error_t shield_random_bytes(uint8_t *buf, size_t len) {
  #ifdef _WIN32
      HCRYPTPROV hProv;
      if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
          return SHIELD_ERR_RANDOM_FAILED;
      }
      if (!CryptGenRandom(hProv, (DWORD)len, buf)) {
          CryptReleaseContext(hProv, 0);
          return SHIELD_ERR_RANDOM_FAILED;
      }
      CryptReleaseContext(hProv, 0);
  #else
      int fd = open("/dev/urandom", O_RDONLY);
      if (fd < 0) { return SHIELD_ERR_RANDOM_FAILED; }
      ssize_t n = read(fd, buf, len);
      close(fd);
      if (n != (ssize_t)len) { return SHIELD_ERR_RANDOM_FAILED; }
  #endif
      return SHIELD_OK;
  }
  ```
  Two issues:
  1. **Unix**: Single `read()` call without EINTR retry. If the read is interrupted by a signal, it returns a short count or -1 with `errno == EINTR`. The function correctly returns an error on partial read (`n != len`), but does not retry — causing unnecessary random generation failures under signal-heavy workloads.
  2. **Windows**: Uses `CryptGenRandom` from the CryptoAPI, which Microsoft deprecated in favor of `BCryptGenRandom` (CNG). While `CryptGenRandom` is still functional, Microsoft recommends migration to CNG for new code.
- **Impact**:
  1. **Unix signal handling**: Under heavy signal load (e.g., SIGCHLD in a process-spawning server), `read()` from `/dev/urandom` may be interrupted. The function returns `SHIELD_ERR_RANDOM_FAILED`, causing encryption to fail. This is a reliability issue, not a security issue — no weak random is ever used.
  2. **Windows deprecation**: `CryptGenRandom` continues to work on all current Windows versions but may be removed in future Windows releases.
- **Reproduction**: On Linux: send signals to a process calling `shield_random_bytes` in a tight loop; some calls will fail with `SHIELD_ERR_RANDOM_FAILED`.
- **Fix Complexity**: LOW
- **Remediation**:
  ```c
  // Unix: retry on EINTR
  ssize_t total = 0;
  while (total < (ssize_t)len) {
      ssize_t n = read(fd, buf + total, len - total);
      if (n < 0) {
          if (errno == EINTR) continue;
          close(fd);
          return SHIELD_ERR_RANDOM_FAILED;
      }
      total += n;
  }
  // Windows: use BCryptGenRandom
  #include <bcrypt.h>
  NTSTATUS status = BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  ```
  Alternatively on Linux, use `getrandom(2)` syscall which avoids file descriptor management entirely.
- **Verification Notes**: VERIFIED — confirmed by reading shield.c:265-288. The security posture is correct (errors are returned, never zero-fills), but reliability can be improved.

---

### SHIELD-A01-019: Nonce Generation Audit — All 12 Implementations Use CSPRNG Sources
- **Tag**: NON-VULN
- **Severity**: INFO
- **CWE**: N/A
- **Location**: All 12 implementations
- **Evidence**: Full audit confirms all implementations use platform-appropriate CSPRNG:
  | Language | CSPRNG Source | Standard |
  |----------|-------------|----------|
  | Rust | `ring::rand::SystemRandom` | Backed by OS entropy |
  | Python | `os.urandom(16)` | `/dev/urandom` / `CryptGenRandom` |
  | JavaScript | `crypto.randomBytes(16)` | Node.js crypto (OpenSSL) |
  | Go | `crypto/rand.Read()` | `/dev/urandom` / `CryptGenRandom` |
  | C | `/dev/urandom` / `CryptGenRandom` | Direct OS API |
  | Java | `java.security.SecureRandom` | JCA provider |
  | C# | `RandomNumberGenerator.Create()` | .NET cryptographic RNG |
  | Swift | `SecRandomCopyBytes` | Apple Security framework |
  | Kotlin | `java.security.SecureRandom` | JCA provider |
  | Android | `java.security.SecureRandom` | Android JCA (hardware-backed on modern devices) |
  | iOS | `SecRandomCopyBytes` | Apple Security framework |
  | WASM | `getrandom` crate → `crypto.getRandomValues()` | Web Crypto API |

  All nonces are:
  - 16 bytes (128 bits) — consistent across all implementations
  - Generated fresh for every encryption call — no reuse
  - Not user-controllable — no API parameter allows callers to inject a nonce
  - No test/debug mode that fixes or disables random generation
- **Impact**: N/A — CSPRNG usage is correct. Specific implementation concerns documented in SHIELD-A01-016 (iOS return check), SHIELD-A01-017 (Swift zero fallback), SHIELD-A01-018 (C robustness).
- **Verification Notes**: NON-VULN — comprehensive audit of nonce generation in all 12 implementations confirms CSPRNG usage. No weak PRNG (`Math.random`, `rand()`, `Random()`) found in any encryption path.

---

## TASK-1-005: Key Separation & Constant-Time Operations Audit

### SHIELD-A01-020: TOTP Verify Uses Non-Constant-Time String Comparison in 5 Implementations
- **Tag**: VULN
- **Severity**: MEDIUM
- **CWE**: CWE-208 (Observable Timing Discrepancy)
- **Location**: 5 of 12 implementations:
  - `go/shield/totp.go:76,82` — `t.Generate(checkTime) == code` (Go `==` operator)
  - `java/src/main/java/ai/guard8/shield/TOTP.java:61,65` — `generate(...).equals(code)` (Java `String.equals`)
  - `kotlin/src/main/kotlin/ai/guard8/shield/TOTP.kt:33,34` — `generate(...) == code` (Kotlin `==`)
  - `swift/Sources/Shield/TOTP.swift:35,38` — `generate(...) == code` (Swift `==`)
  - `csharp/Shield/Totp.cs:52,54` — `Generate(...) == code` (C# `==`)
- **Evidence**:
  ```go
  // go/shield/totp.go:76
  if t.Generate(checkTime) == code {
      return true
  }
  ```
  ```java
  // java TOTP.java:61
  if (generate(timestamp - i * interval).equals(code)) {
      return true;
  }
  ```
  Correct implementations for comparison:
  ```python
  # python/shield/totp.py:139 — CORRECT
  if hmac.compare_digest(code, expected):
  ```
  ```javascript
  // javascript/src/totp.js:109 — CORRECT
  if (crypto.timingSafeEqual(Buffer.from(code), Buffer.from(expected))) {
  ```
  ```kotlin
  // android TOTP.kt:164 — CORRECT
  if (constantTimeEquals(code, expected)) {
  ```
  ```swift
  // ios TOTP.swift:125 — CORRECT
  if constantTimeEquals(code, expected) {
  ```
- **Impact**: Timing side-channel allows attackers to determine TOTP codes character-by-character. An attacker who can observe response timing (e.g., network-level) can reduce brute-force from 10^6 to ~60 guesses (6 digits × ~10 per digit). Practical exploitability depends on network jitter; local/co-located attackers have higher success rate.
- **Fix Complexity**: LOW
- **Remediation**:
  - Go: Replace `==` with `subtle.ConstantTimeCompare([]byte(generated), []byte(code)) == 1`
  - Java: Replace `.equals()` with `MessageDigest.isEqual(generated.getBytes(), code.getBytes())`
  - Kotlin (JVM): Replace `==` with `MessageDigest.isEqual(generated.toByteArray(), code.toByteArray())`
  - Swift: Replace `==` with `Shield.constantTimeEquals(Array(generated.utf8), Array(code.utf8))`
  - C#: Replace `==` with `CryptographicOperations.FixedTimeEquals(...)` or custom constant-time comparison

### SHIELD-A01-021: Key Separation & Constant-Time MAC Audit — Complete Verification
- **Tag**: NON-VULN
- **Severity**: INFO
- **CWE**: N/A
- **Location**: All 12 implementations
- **Evidence**:

  **Key Separation Status** (confirms SHIELD-A01-001):
  All 12 implementations use the same PBKDF2-derived key for both SHA256-CTR keystream generation AND HMAC-SHA256 authentication. No implementation derives separate sub-keys as specified in PROTOCOL.md (`mac_key = SHA256(master_key || "mac")`). This violation is uniformly present — no implementation is more or less affected.

  **Constant-Time MAC Comparison — All 12 Correct**:
  | Language | Function | Location | Constant-Time? |
  |----------|----------|----------|----------------|
  | Rust | `subtle::ConstantTimeEq::ct_eq()` | shield.rs:287 | Yes (hardware-backed) |
  | Python | `hmac.compare_digest()` | core.py:233 | Yes (CPython built-in) |
  | JavaScript | `crypto.timingSafeEqual()` | shield.js:189 | Yes (Node.js built-in) |
  | Go | `subtle.ConstantTimeCompare()` | shield.go:166 | Yes (`crypto/subtle`) |
  | C | `shield_secure_compare()` — XOR/OR accumulate, `volatile` | shield.c:249 | Yes (custom, volatile risk per A01-014) |
  | Java | `constantTimeEquals()` — XOR/OR accumulate | Shield.java:357 | Yes (custom) |
  | C# | `ConstantTimeEquals()` — XOR/OR accumulate | Shield.cs:200 | Yes (custom, not using .NET `FixedTimeEquals`) |
  | Swift | `constantTimeEquals()` — XOR/OR accumulate | Shield.swift:187 | Yes (custom) |
  | Kotlin | `constantTimeEquals()` — XOR/OR accumulate | Shield.kt:148 | Yes (custom) |
  | Android | `constantTimeEquals()` — XOR/OR accumulate | Shield.kt:177 | Yes (custom) |
  | iOS | `constantTimeEquals()` — XOR/OR accumulate | Shield.swift:185 | Yes (custom) |
  | WASM | Delegates to Rust `ct_eq()` | N/A | Yes |

  **Constant-Time in Extended Modules** (signatures, identity, exchange, ratchet):
  | Module | Go | Java | C | Swift | Kotlin | JS |
  |--------|-----|------|---|-------|--------|-----|
  | Signatures | `subtle.ConstantTimeCompare` | `Shield.constantTimeEquals` | `shield_secure_compare` | `Shield.constantTimeEquals` | `Shield.constantTimeEquals` | `crypto.timingSafeEqual` |
  | Identity | `subtle.ConstantTimeCompare` | `constantTimeEquals` | N/A | `Shield.constantTimeEquals` | `constantTimeEquals` | `crypto.timingSafeEqual` |
  | Exchange | `subtle.ConstantTimeCompare` | N/A | N/A | N/A | N/A | `crypto.timingSafeEqual` |
  | Ratchet | `subtle.ConstantTimeCompare` | `Shield.constantTimeEquals` | `shield_secure_compare` | `Shield.constantTimeEquals` | `constantTimeEquals` | `crypto.timingSafeEqual` |

  All MAC verification and signature verification paths use constant-time comparison. The ONLY timing leak found is in TOTP string comparison (SHIELD-A01-020 above).

- **Impact**: N/A — MAC comparison is correctly constant-time across all 12 implementations and all extended modules (signatures, identity, exchange, ratchet, group encryption, key rotation, streaming).
- **Verification Notes**: NON-VULN — comprehensive constant-time audit confirms all cryptographic comparison operations use appropriate constant-time functions. Key separation violation remains as documented in SHIELD-A01-001.
