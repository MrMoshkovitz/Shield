# Agent 12: Mobile Platform Security — Findings

**Agent**: A12 — Mobile Platform
**Phase**: 3 (Platform & HW)
**Priority**: MEDIUM
**Auditor**: Ralph Loop (Iteration 40)
**Date**: 2026-03-03
**Files Audited**:
- `android/shield/src/main/java/ai/guard8/shield/SecureKeyStore.kt`
- `android/shield/src/main/java/ai/guard8/shield/Shield.kt`
- `android/shield/src/main/java/ai/guard8/shield/DeviceFingerprint.kt`
- `android/shield/src/main/java/ai/guard8/shield/Exchange.kt`
- `android/shield/src/main/java/ai/guard8/shield/RatchetSession.kt`
- `android/shield/src/main/java/ai/guard8/shield/ShieldChannel.kt`
- `android/shield/src/main/java/ai/guard8/shield/StreamCipher.kt`
- `android/shield/src/main/java/ai/guard8/shield/TOTP.kt`
- `android/shield/build.gradle.kts`
- `android/shield/src/main/AndroidManifest.xml`
- `android/shield/proguard-rules.pro`
- `android/shield/consumer-rules.pro`
- `ios/Sources/Shield/SecureKeychain.swift`
- `ios/Sources/Shield/Shield.swift`
- `ios/Sources/Shield/DeviceFingerprint.swift`
- `ios/Sources/Shield/RatchetSession.swift`
- `ios/Sources/Shield/TOTP.swift`
- `ios/Package.swift`

**Total Findings**: 18 (1 HIGH, 10 MEDIUM, 5 LOW, 2 INFO)

---

## Findings

### SHIELD-A12-001: Android Hardware Key Not Authentication-Gated
- **Tag**: VERIFIED
- **Severity**: HIGH
- **CWE**: CWE-287 (Improper Authentication)
- **Platform**: Android
- **Location**: `android/shield/src/main/java/ai/guard8/shield/SecureKeyStore.kt:132`
- **Evidence**:
```kotlin
val spec = KeyGenParameterSpec.Builder(
    alias,
    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setKeySize(256)
    .setUserAuthenticationRequired(false)  // <-- NO AUTH REQUIRED
    .build()
```
- **Impact**: Any app on the device (or malware with root access) can use hardware-backed keys without biometric or PIN verification. Keys intended for "hardware-backed security" are accessible without user authentication. Combined with missing StrongBox requirement, an attacker who gains app-level access can use all stored keys.
- **Reproduction**: Call `generateHardwareKey("test")` — key is immediately usable without any user interaction or biometric prompt.
- **Fix Complexity**: LOW
- **Remediation**: Set `setUserAuthenticationRequired(true)` and `setUserAuthenticationValidityDurationSeconds(30)`. Add `setIsStrongBoxBacked(true)` with fallback to TEE.
- **Verification Notes**: Directly confirmed in source code. The `false` parameter is explicit, not a default.

---

### SHIELD-A12-002: Android No StrongBox/TEE Requirement for Hardware Keys
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-320 (Key Management Errors)
- **Platform**: Android
- **Location**: `android/shield/src/main/java/ai/guard8/shield/SecureKeyStore.kt:125-133`
- **Evidence**:
```kotlin
val spec = KeyGenParameterSpec.Builder(
    alias,
    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setKeySize(256)
    .setUserAuthenticationRequired(false)
    .build()
// Missing: .setIsStrongBoxBacked(true)
```
- **Impact**: Keys may be stored in software-only KeyStore implementation rather than TEE/StrongBox hardware. Documentation claims "hardware-backed" but code does not enforce it. On devices without TEE, keys are extractable.
- **Reproduction**: Check `isHardwareBackedAvailable()` — always returns true even on software-only KeyStore because `generateHardwareKey` doesn't require hardware backing.
- **Fix Complexity**: LOW
- **Remediation**: Add `.setIsStrongBoxBacked(true)` with try-catch fallback to standard Keystore + document that hardware backing is best-effort.
- **Verification Notes**: No `setIsStrongBoxBacked` call anywhere in codebase. Confirmed via search.

---

### SHIELD-A12-003: Android R8/ProGuard Disabled in Release Builds
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-200 (Exposure of Sensitive Information)
- **Platform**: Android
- **Location**: `android/shield/build.gradle.kts:21`
- **Evidence**:
```kotlin
release {
    isMinifyEnabled = false  // <-- MINIFICATION DISABLED
    proguardFiles(
        getDefaultProguardFile("proguard-android-optimize.txt"),
        "proguard-rules.pro"
    )
}
```
And `proguard-rules.pro:4-5`:
```
-keep class ai.guard8.shield.** { *; }
-keepclassmembers class ai.guard8.shield.** { *; }
```
- **Impact**: All Shield class names, method names, and field names are preserved in release builds. An attacker can trivially reverse-engineer the encryption implementation, identify key storage locations, and understand internal state management. Even if minification were enabled, the keep rules prevent any obfuscation.
- **Reproduction**: Build release APK, decompile with jadx — all class/method names visible.
- **Fix Complexity**: LOW
- **Remediation**: Set `isMinifyEnabled = true`. Narrow ProGuard keep rules to only public API surface. Use `-allowobfuscation` for internal classes.
- **Verification Notes**: Both the gradle config AND the proguard rules confirm zero obfuscation.

---

### SHIELD-A12-004: Alpha Dependency in Production (androidx.security:security-crypto:1.1.0-alpha06)
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-1104 (Use of Unmaintained Third-Party Components)
- **Platform**: Android
- **Location**: `android/shield/build.gradle.kts:47`
- **Evidence**:
```kotlin
implementation("androidx.security:security-crypto:1.1.0-alpha06")
```
- **Impact**: Alpha-version library used for EncryptedSharedPreferences. Alpha APIs may change without notice, have known bugs, or lack security fixes. The `-alpha06` suffix indicates pre-release software not recommended for production. If this library has vulnerabilities, it would directly impact key storage.
- **Reproduction**: Check Maven Central — 1.1.0-alpha06 is a pre-release version. The stable release is 1.0.0.
- **Fix Complexity**: MEDIUM
- **Remediation**: Downgrade to stable `1.0.0` or upgrade to latest stable release when available. Evaluate if EncryptedSharedPreferences functionality from alpha is actually needed.
- **Verification Notes**: Version string directly confirms alpha status.

---

### SHIELD-A12-005: Derived Key Stored as Hex in EncryptedSharedPreferences Not Hardware Keystore
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-312 (Cleartext Storage of Sensitive Information)
- **Platform**: Android
- **Location**: `android/shield/src/main/java/ai/guard8/shield/SecureKeyStore.kt:65-69`
- **Evidence**:
```kotlin
fun storeKey(alias: String, key: ByteArray) {
    encryptedPrefs.edit()
        .putString(KEY_PREFIX + alias, key.toHexString())
        .apply()
}
```
And in `getOrCreateShield()` at line 171-183:
```kotlin
val key = deriveKey(password, service)
storeKey(alias, key)  // Stores raw derived key bytes as hex in SharedPrefs
```
- **Impact**: The raw PBKDF2-derived encryption key is stored as a hex string in EncryptedSharedPreferences. While EncryptedSharedPreferences is encrypted, the master key for it uses default MasterKey (line 40-43) without authentication requirement. On a rooted device or with backup extraction, the derived key can be recovered. The key should be stored in hardware Keystore, not SharedPreferences.
- **Reproduction**: Call `getOrCreateShield()`, then extract `shield_secure_prefs` XML from device backup — contains hex-encoded encryption key.
- **Fix Complexity**: MEDIUM
- **Remediation**: Store keys in Android Keystore (hardware-backed) rather than EncryptedSharedPreferences. Use `generateHardwareKey()` pattern for all key storage.
- **Verification Notes**: `storeKey()` writes to EncryptedSharedPreferences, not to Keystore. Confirmed by tracing `getOrCreateShield()` flow.

---

### SHIELD-A12-006: Android Derived Key Not Zeroized After Use
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-244 (Improper Clearing of Heap Memory Before Release)
- **Platform**: Android
- **Location**: `android/shield/src/main/java/ai/guard8/shield/SecureKeyStore.kt:185-191`
- **Evidence**:
```kotlin
private fun deriveKey(password: String, service: String): ByteArray {
    val salt = java.security.MessageDigest.getInstance("SHA-256")
        .digest(service.toByteArray(Charsets.UTF_8))
    val factory = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    val spec = javax.crypto.spec.PBEKeySpec(password.toCharArray(), salt, 100_000, 256)
    return factory.generateSecret(spec).encoded
    // No Arrays.fill(0) on salt, spec, or returned key after use
}
```
- **Impact**: PBKDF2-derived key bytes, salt, and PBEKeySpec remain in JVM heap memory after use. On Android, memory can be dumped by a debugger on rooted devices, or by companion malware exploiting memory disclosure. The key persists until garbage collection, which is non-deterministic.
- **Reproduction**: Attach debugger to process after `getOrCreateShield()` call, dump heap — search for 32-byte key patterns.
- **Fix Complexity**: LOW
- **Remediation**: Call `spec.clearPassword()` on PBEKeySpec, `Arrays.fill(salt, 0.toByte())` on salt, and `Arrays.fill(key, 0.toByte())` on returned key after storing. Add `secureWipe()` calls matching `ShieldUtils.secureWipe()` pattern.
- **Verification Notes**: No `fill(0)` or wipe calls found anywhere in `SecureKeyStore.kt`. `ShieldUtils.secureWipe()` exists but is never called from SecureKeyStore.

---

### SHIELD-A12-007: Android No allowBackup Restriction in Manifest
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-312 (Cleartext Storage of Sensitive Information)
- **Platform**: Android
- **Location**: `android/shield/src/main/AndroidManifest.xml`
- **Evidence**:
```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <!-- No permissions required for core encryption -->
    <!-- Hardware keystore access is automatic on supported devices -->
</manifest>
<!-- Missing: android:allowBackup="false" -->
```
- **Impact**: Since AndroidManifest.xml doesn't set `android:allowBackup="false"`, the consuming app inherits default `allowBackup="true"`. This means `adb backup` or Google Auto Backup can extract EncryptedSharedPreferences files containing hex-encoded encryption keys (from SHIELD-A12-005). Combined with key storage in SharedPrefs rather than Keystore, this creates a key extraction path via device backup.
- **Reproduction**: `adb backup -f backup.ab ai.guard8.shield` extracts SharedPrefs files including encrypted key material.
- **Fix Complexity**: LOW
- **Remediation**: Add `android:allowBackup="false"` to manifest `<application>` tag, or at minimum add `android:fullBackupContent="@xml/backup_rules"` excluding `shield_secure_prefs`.
- **Verification Notes**: Manifest is minimal (5 lines) with no application tag or backup restrictions.

---

### SHIELD-A12-008: Android Salt Derivation Differs from Protocol Spec
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-329 (Generation of Predictable IV/Nonce/Salt)
- **Platform**: Android
- **Location**: `android/shield/src/main/java/ai/guard8/shield/Shield.kt:47-48`
- **Evidence**:
```kotlin
val salt = MessageDigest.getInstance("SHA-256")
    .digest(service.toByteArray(Charsets.UTF_8))  // SHA256(service)
```
Rust core (from SHIELD_SECURITY_CONTEXT.md line 81):
```
salt = SHA256("shield:" + service)
```
- **Impact**: Android implementation uses `SHA256(service)` while Rust core uses `SHA256("shield:" + service)`. This means Android encryption is NOT interoperable with Rust/other implementations. Ciphertext encrypted on Android cannot be decrypted by Rust core or vice versa when using password+service derivation. **Cross-platform interoperability broken.**
- **Reproduction**: Encrypt "test" with password "pass", service "github.com" on Android and Rust — outputs differ because salts differ.
- **Fix Complexity**: LOW
- **Remediation**: Change salt derivation to `MessageDigest.getInstance("SHA-256").digest(("shield:" + service).toByteArray(Charsets.UTF_8))` matching Rust core PROTOCOL.md specification.
- **Verification Notes**: Direct string comparison of salt derivation code. Android: `SHA256(service)`, Rust: `SHA256("shield:" + service)`. Cross-reference with SHIELD_SECURITY_CONTEXT.md line 81.

---

### SHIELD-A12-009: iOS Salt Derivation Differs from Protocol Spec
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-329 (Generation of Predictable IV/Nonce/Salt)
- **Platform**: iOS
- **Location**: `ios/Sources/Shield/Shield.swift:42`
- **Evidence**:
```swift
let salt = service.data(using: .utf8)!.sha256()  // SHA256(service)
```
Rust core (from SHIELD_SECURITY_CONTEXT.md line 81):
```
salt = SHA256("shield:" + service)
```
- **Impact**: Same as SHIELD-A12-008 — iOS implementation uses `SHA256(service)` while Rust core uses `SHA256("shield:" + service)`. iOS encryption is NOT interoperable with Rust core. **Both mobile platforms break cross-platform interoperability.**
- **Reproduction**: Encrypt "test" with password "pass", service "github.com" on iOS and Rust — outputs differ.
- **Fix Complexity**: LOW
- **Remediation**: Prepend `"shield:"` to service before hashing: `"shield:\(service)".data(using: .utf8)!.sha256()`.
- **Verification Notes**: Direct comparison with Rust core protocol. iOS salt = `SHA256(service)`, Rust = `SHA256("shield:" + service)`.

---

### SHIELD-A12-010: iOS Derived Key Not Zeroized After Use
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-244 (Improper Clearing of Heap Memory Before Release)
- **Platform**: iOS
- **Location**: `ios/Sources/Shield/SecureKeychain.swift:196-218`
- **Evidence**:
```swift
private func deriveKey(password: String, service: String) -> [UInt8] {
    let salt = service.data(using: .utf8)!.sha256()
    var derivedKey = [UInt8](repeating: 0, count: 32)
    let passwordData = password.data(using: .utf8)!
    // ... CCKeyDerivationPBKDF call ...
    return derivedKey
    // derivedKey array never zeroed after return
}
```
- **Impact**: The derived key array remains in Swift heap memory after the function returns. Swift uses ARC, not manual memory management, so there's no deterministic cleanup. On a jailbroken device, memory scanning can find the key bytes.
- **Reproduction**: Call `getOrCreateShield()`, then dump app memory — search for 32-byte patterns matching PBKDF2 output.
- **Fix Complexity**: LOW
- **Remediation**: Zero the `derivedKey` array after use: `derivedKey.withUnsafeMutableBufferPointer { ptr in memset_s(ptr.baseAddress, ptr.count, 0, ptr.count) }`. Apply similar pattern in `Shield.deriveKey()`.
- **Verification Notes**: No wipe/zero calls found in SecureKeychain.swift or Shield.swift for derived keys.

---

### SHIELD-A12-011: Android ShieldChannel Confirmation Uses Non-Constant-Time Comparison
- **Tag**: VERIFIED
- **Severity**: MEDIUM
- **CWE**: CWE-208 (Observable Timing Discrepancy)
- **Platform**: Android
- **Location**: `android/shield/src/main/java/ai/guard8/shield/ShieldChannel.kt:214`
- **Evidence**:
```kotlin
require(received.contentEquals(expected)) { "Authentication failed" }
```
- **Impact**: `ByteArray.contentEquals()` in Kotlin uses element-by-element comparison that short-circuits on first mismatch. During the ShieldChannel handshake confirmation step, an attacker performing a MITM could use timing differences to learn the correct confirmation byte-by-byte, forging a valid handshake confirmation. This is a timing oracle on the PAKE handshake.
- **Reproduction**: Measure timing of handshake confirmation responses with varying prefix lengths of the correct confirmation — timing should correlate with correct prefix length.
- **Fix Complexity**: LOW
- **Remediation**: Replace with the existing `constantTimeEquals()` helper from `RatchetSession` companion object, or extract it to `ShieldUtils.constantTimeEquals()`.
- **Verification Notes**: `contentEquals()` is Kotlin stdlib, not constant-time. The same codebase has `constantTimeEquals()` in RatchetSession.kt:262-268 and Shield.kt:177-183, but ShieldChannel doesn't use them.

---

### SHIELD-A12-012: Android QR Exchange Manual JSON Has No String Escaping
- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-74 (Improper Neutralization of Special Elements)
- **Platform**: Android
- **Location**: `android/shield/src/main/java/ai/guard8/shield/Exchange.kt:157`
- **Evidence**:
```kotlin
private fun toJson(map: Map<String, Any>): String {
    val sb = StringBuilder("{")
    var first = true
    for ((key, value) in map) {
        if (!first) sb.append(",")
        first = false
        sb.append("\"$key\":")  // No escaping of key
        when (value) {
            is String -> sb.append("\"$value\"")  // No escaping of value
            else -> sb.append(value)
        }
    }
    sb.append("}")
    return sb.toString()
}
```
- **Impact**: If metadata contains strings with quotes, backslashes, or newlines, the generated JSON is malformed. An attacker providing crafted metadata could break the JSON parser on the receiving end or inject additional fields. In practice, metadata is optional and caller-controlled, limiting real-world exploitability.
- **Reproduction**: Call `generateExchangeData(key, mapOf("name" to "test\"injected\":true"))` — produces malformed JSON with injected field.
- **Fix Complexity**: LOW
- **Remediation**: Use `org.json.JSONObject` for JSON serialization, or add string escaping for quotes, backslashes, and control characters.
- **Verification Notes**: Manual string concatenation with no escaping. No calls to this function found in test files, so limited attack surface.

---

### SHIELD-A12-013: Android MD5 Used for Device Fingerprinting
- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-328 (Use of Weak Hash)
- **Platform**: Android
- **Location**: `android/shield/src/main/java/ai/guard8/shield/DeviceFingerprint.kt:147-149`
- **Evidence**:
```kotlin
private fun String.md5(): String {
    val md = MessageDigest.getInstance("MD5")
    val digest = md.digest(this.toByteArray())
    return digest.toHexString()
}
```
- **Impact**: MD5 is cryptographically broken (collision attacks practical since 2004). Used for device fingerprinting hash. An attacker could craft two different device fingerprint inputs that produce the same MD5 hash, potentially spoofing device identity. However, fingerprinting is used for key derivation augmentation (not as primary security), so impact is moderate.
- **Reproduction**: Known MD5 collision pairs can be applied to construct fingerprint strings with identical hash.
- **Fix Complexity**: LOW
- **Remediation**: Replace with SHA-256: `MessageDigest.getInstance("SHA-256")`.
- **Verification Notes**: MD5 identified by string literal "MD5". Same issue in iOS (SHIELD-A12-014).

---

### SHIELD-A12-014: iOS MD5 Used for Device Fingerprinting
- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-328 (Use of Weak Hash)
- **Platform**: iOS
- **Location**: `ios/Sources/Shield/DeviceFingerprint.swift:186-188`
- **Evidence**:
```swift
private static func md5(string: String) -> String {
    let data = Data(string.utf8)
    let digest = Insecure.MD5.hash(data: data)  // Apple's own framework marks it "Insecure"
    return digest.map { String(format: "%02x", $0) }.joined()
}
```
- **Impact**: Same as SHIELD-A12-013. Apple's CryptoKit explicitly marks MD5 under `Insecure` namespace, confirming its unsuitability for security purposes. Used for fingerprint hashing.
- **Reproduction**: Same as Android equivalent.
- **Fix Complexity**: LOW
- **Remediation**: Replace with `SHA256.hash(data: data)` from CryptoKit (already imported).
- **Verification Notes**: Apple's own naming convention (`Insecure.MD5`) flags this as inappropriate.

---

### SHIELD-A12-015: iOS Biometric Protection Disabled by Default
- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-287 (Improper Authentication)
- **Platform**: iOS
- **Location**: `ios/Sources/Shield/SecureKeychain.swift:53`
- **Evidence**:
```swift
public func store(key: [UInt8], for alias: String, biometricProtection: Bool = false) throws {
```
And `getOrCreateShield()` at line 173:
```swift
try store(key: key, for: alias)  // biometricProtection defaults to false
```
- **Impact**: Keys stored via `getOrCreateShield()` are not biometric-protected by default. Any code running in the app's sandbox can access all stored keys without biometric verification. The biometric protection feature exists but is opt-in, and the convenience method `getOrCreateShield()` never enables it.
- **Reproduction**: Call `getOrCreateShield()` then `retrieve(for: alias)` — no biometric prompt appears.
- **Fix Complexity**: LOW
- **Remediation**: Consider making `biometricProtection: true` the default, or at minimum document that `getOrCreateShield()` stores keys without biometric protection. Add a `getOrCreateShieldWithBiometrics()` convenience method.
- **Verification Notes**: Default parameter `biometricProtection: Bool = false` is explicit. Keychain accessibility is correctly `WhenUnlockedThisDeviceOnly` (good), but no access control requiring biometric.

---

### SHIELD-A12-016: iOS Force-Unwrap on String Encoding Could Crash
- **Tag**: VERIFIED
- **Severity**: LOW
- **CWE**: CWE-754 (Improper Check for Unusual Conditions)
- **Platform**: iOS
- **Location**: `ios/Sources/Shield/Shield.swift:42,139,199` and `ios/Sources/Shield/SecureKeychain.swift:197,199`
- **Evidence**:
```swift
// Shield.swift:42
let salt = service.data(using: .utf8)!.sha256()

// Shield.swift:139
let passwordData = password.data(using: .utf8)!

// SecureKeychain.swift:197
let salt = service.data(using: .utf8)!.sha256()
```
- **Impact**: Force-unwrapping `.data(using: .utf8)!` will crash the app if the string contains invalid UTF-8 sequences. While Swift strings are valid Unicode, the `data(using:)` method can theoretically return nil for certain encoding edge cases. In practice, this is extremely unlikely for UTF-8 encoding of Swift strings, but the force-unwrap violates defensive coding practices in a security library.
- **Reproduction**: Extremely unlikely in practice since Swift Strings are always valid Unicode and UTF-8 encoding should always succeed. Theoretical risk only.
- **Fix Complexity**: LOW
- **Remediation**: Use `Data(string.utf8)` instead of `string.data(using: .utf8)!` — this never fails.
- **Verification Notes**: Multiple force-unwrap sites identified. While practically safe, it's a code quality concern in a security library.

---

### SHIELD-A12-017: Both Mobile Platforms Missing V2 Wire Format
- **Tag**: VERIFIED
- **Severity**: INFO
- **CWE**: CWE-757 (Selection of Less-Secure Algorithm During Negotiation)
- **Platform**: Both
- **Location**: `android/shield/src/main/java/ai/guard8/shield/Shield.kt:95-118` and `ios/Sources/Shield/Shield.swift:81-106`
- **Evidence**:
Android encrypt produces: `nonce(16) || enc(counter(8) || plaintext) || mac(16)` — V1 format.
Rust V2 format adds: timestamp, random padding, pad_len byte.
Neither Android nor iOS implement V2 wire format with timestamp/padding.
- **Impact**: Mobile SDKs only support V1 wire format. This means: (1) no timestamp-based replay protection, (2) no random padding for traffic analysis resistance, (3) ciphertext length directly reveals plaintext length. Messages encrypted on mobile cannot leverage V2 security features. This is an interoperability note — V1 is auto-detected by other implementations.
- **Reproduction**: Compare wire format bytes: mobile output has no timestamp or padding fields.
- **Fix Complexity**: MEDIUM
- **Remediation**: Implement V2 wire format matching Rust core: `nonce(16) || enc(counter(8) || timestamp(8) || pad_len(1) || random_padding || plaintext) || mac(16)`.
- **Verification Notes**: Both Android and iOS encrypt functions produce counter+plaintext only, no timestamp or padding.

---

### SHIELD-A12-018: Android RatchetSession secureWipe Uses Arrays.fill — JIT May Optimize Away
- **Tag**: UN-VERIFIED
- **Severity**: INFO
- **CWE**: CWE-14 (Compiler Removal of Code to Clear Buffers)
- **Platform**: Android
- **Location**: `android/shield/src/main/java/ai/guard8/shield/RatchetSession.kt:271-273`
- **Evidence**:
```kotlin
private fun secureWipe(data: ByteArray) {
    data.fill(0)
}
```
And `ShieldUtils.secureWipe()` at `Shield.kt:226-228`:
```kotlin
fun secureWipe(data: ByteArray) {
    data.fill(0)
}
```
- **Impact**: `ByteArray.fill(0)` may be optimized away by the JIT compiler if the array is not subsequently read. This is a known issue with non-volatile memory wiping in JVM languages. The `RatchetSession.close()` method calls `secureWipe()` on send/recv chains, but the JIT may determine the zeroed array is never read and eliminate the fill operation.
- **Reproduction**: Requires JIT analysis or memory dump after `close()` — if bytes are not zeroed, JIT optimized away the fill.
- **Fix Complexity**: MEDIUM
- **Remediation**: Use `java.security.SecureRandom().nextBytes(data)` followed by `data.fill(0)` (harder to optimize away), or use JNI to call `explicit_bzero()`.
- **Verification Notes**: Cannot confirm JIT behavior from static analysis alone. Tagged UN-VERIFIED. The pattern is a known JVM anti-pattern for secure wiping.

---

## Audit Checklist Status

### Android
1. [x] KeyStore: No StrongBox requirement → **SHIELD-A12-002**
2. [x] KeyStore: Key purposes correctly limited to encrypt/decrypt → **PASS** (line 127)
3. [x] Biometric: UserAuthenticationRequired = false → **SHIELD-A12-001**
4. [x] ProGuard: Disabled + over-broad keep rules → **SHIELD-A12-003**
5. [x] Min SDK: API 23 → **PASS** (reasonable, fingerprint API 23+)
6. [x] Backup: No allowBackup restriction → **SHIELD-A12-007**

### iOS
1. [x] Keychain: Correctly uses `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` → **PASS** (line 62)
2. [x] Keychain: Biometric default false → **SHIELD-A12-015**
3. [x] Secure Enclave: Used in DeviceFingerprint, not in SecureKeychain for key storage → **Info** (Keychain is adequate)
4. [x] App Transport Security: No ATS config but no network calls in SDK → **PASS**
5. [x] Data Protection: Not explicitly set but Keychain items inherit device protection → **PASS**

### Cross-Platform
1. [x] Salt derivation mismatch vs Rust core → **SHIELD-A12-008, SHIELD-A12-009**
2. [x] V2 wire format not implemented → **SHIELD-A12-017**
3. [x] MD5 in fingerprinting → **SHIELD-A12-013, SHIELD-A12-014**
4. [x] Key zeroization gaps → **SHIELD-A12-006, SHIELD-A12-010, SHIELD-A12-018**
